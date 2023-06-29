package aws

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/data_usage"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"

	ap "github.com/raito-io/cli/base/access_provider/sync_from_target"
)

//go:generate go run github.com/vektra/mockery/v2 --name=dataUsageRepository --with-expecter --inpackage
type dataUsageRepository interface {
	ListFiles(ctx context.Context, bucket string, prefix *string) ([]AwsS3Entity, error)
	GetFile(ctx context.Context, bucket string, key string) (io.ReadCloser, error)
}

type DataUsageSyncer struct {
	configMap *config.ConfigMap
}

func NewDataUsageSyncer() *DataUsageSyncer {
	return &DataUsageSyncer{}
}

func (s *DataUsageSyncer) provideRepo() dataUsageRepository {
	return &AwsS3Repository{
		configMap: s.configMap,
	}
}

func (s *DataUsageSyncer) SyncDataUsage(ctx context.Context, dataUsageFileHandler wrappers.DataUsageStatementHandler, configParams *config.ConfigMap) error {
	s.configMap = configParams

	repo := s.provideRepo()

	bucket := configParams.GetString(AwsS3CloudTrailBucket)

	allUsageFiles, err := repo.ListFiles(ctx, bucket, nil)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("A total of %d usage files found in bucket %s", len(allUsageFiles), bucket))

	numberOfDays := 90
	startDate := time.Now().Truncate(24*time.Hour).AddDate(0, 0, -numberOfDays)

	if configParams.Parameters["lastUsed"] != "" {
		startDateRaw, errLocal := time.Parse(time.RFC3339, configParams.Parameters["lastUsed"])
		if errLocal == nil && startDateRaw.After(startDate) {
			startDate = startDateRaw
		}
	}

	logger.Info(fmt.Sprintf("using start date %s", startDate.Format(time.RFC3339)))

	usageFiles := []string{}

	r := regexp.MustCompile(`.*/(\d{4}/\d{2}/\d{2})/.*`)
	dateFormat := "2006/01/02"

	for _, file := range allUsageFiles {
		matches := r.FindStringSubmatch(file.Key)
		if len(matches) != 2 {
			continue
		}

		dt, err := time.Parse(dateFormat, matches[1])
		if err != nil {
			continue
		}

		if strings.Contains(file.Key, "/CloudTrail/eu-central-1/") && time.Since(dt).Hours() < float64(numberOfDays+1)*24 {
			usageFiles = append(usageFiles, file.Key)
		}
	}

	logger.Info(fmt.Sprintf("%d files to process", len(usageFiles)))

	fileChan := make(chan string)
	wg := new(sync.WaitGroup)
	fileLock := new(sync.Mutex)
	numWorkers := 16

	for t := 0; t < numWorkers; t++ {
		wg.Add(1)

		go readAndParseUsageLog(ctx, bucket, fileChan, repo, dataUsageFileHandler, wg, fileLock)
	}

	for _, usageFile := range usageFiles {
		fileChan <- usageFile
	}

	close(fileChan)
	wg.Wait()

	return nil
}

func readAndParseUsageLog(ctx context.Context, bucketName string, fileChan chan string, repo dataUsageRepository,
	dataUsageFileHandler wrappers.DataUsageStatementHandler, wg *sync.WaitGroup, fileLock *sync.Mutex) {
	defer wg.Done()
	logger.Info("Starting worker")

	for fileKey := range fileChan {
		parts := strings.Split(fileKey, "/")
		fileKeyShort := parts[len(parts)-1]

		start := time.Now()

		contents, err := getFileContents(ctx, repo, bucketName, fileKey)
		if err != nil {
			logger.Error(err.Error())
			return
		}

		var result CloudTrailLog

		err = json.Unmarshal([]byte(contents), &result)
		if err != nil {
			logger.Error(err.Error())
			return
		}

		statements := []data_usage.Statement{}

		for ind := range result.Records {
			record := result.Records[ind]
			isCloudTrailBucket := false
			accessedObjects := []ap.WhatItem{}

			for _, resource := range record.Resources {
				if resource.Type != nil && resource.Arn != nil && strings.Contains(*resource.Arn, bucketName) {
					isCloudTrailBucket = true
					break
				}

				permission := *record.EventName

				if resource.Type != nil && resource.Arn != nil && strings.EqualFold(*resource.Type, "AWS::S3::Object") {
					object := convertArnToFullname(*resource.Arn)
					accessedObjects = append(accessedObjects, ap.WhatItem{
						DataObject: &data_source.DataObjectReference{
							FullName: object,
							Type:     data_source.File,
						},
						Permissions: []string{permission},
					})
				}
			}

			userName := ""
			// TODO: investigate what the different possibilities are, this has been figured out by just looking
			// at the logs so far
			if record.UserIdentity == nil || record.UserIdentity.Type == nil {
				logger.Warn("user identity is nil")
				continue
			} else if *record.UserIdentity.Type == "IAMUser" {
				userName = *record.UserIdentity.UserName
			} else if *record.UserIdentity.Type == "AssumedRole" {
				principalId := record.UserIdentity.PrincipalId
				parts := strings.Split(*principalId, ":")
				userName = parts[1]
			} else if record.UserIdentity.InvokedBy != nil {
				userName = *record.UserIdentity.InvokedBy
			} else if record.UserIdentity.Arn != nil {
				userName = *record.UserIdentity.Arn
			}

			if !isCloudTrailBucket && len(accessedObjects) > 0 && userName != "" {
				statements = append(statements, data_usage.Statement{
					ExternalId:          *record.EventID,
					StartTime:           record.EventTime.Unix(),
					Bytes:               int(record.Bytes.BytesIn) + int(record.Bytes.BytesOut),
					AccessedDataObjects: accessedObjects,
					User:                userName,
					Success:             true,
				})
			}
		}

		if len(statements) > 0 {
			err = addStatementsToDataUsageHandler(dataUsageFileHandler, statements, fileLock)
			if err != nil {
				logger.Error(err.Error())
				return
			}
		}

		logger.Info(fmt.Sprintf("%d records fetched and processed in %d ms from %s", len(result.Records), time.Since(start).Milliseconds(), fileKeyShort))
	}
}

func getFileContents(ctx context.Context, repo dataUsageRepository, bucketName string, fileKey string) (string, error) {
	reader, err := repo.GetFile(ctx, bucketName, fileKey)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return "", err
	}
	defer gzipReader.Close()

	buf := new(strings.Builder)

	_, err = io.Copy(buf, gzipReader) //nolint: gosec
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func addStatementsToDataUsageHandler(dataUsageFileHandler wrappers.DataUsageStatementHandler, statements []data_usage.Statement, lock *sync.Mutex) error {
	lock.Lock()
	defer lock.Unlock()

	return dataUsageFileHandler.AddStatements(statements)
}
