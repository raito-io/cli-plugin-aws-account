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

	"github.com/gammazero/workerpool"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	data_source2 "github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/data_usage"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"

	ap "github.com/raito-io/cli/base/access_provider/sync_from_target"
)

type dataUsageRepository interface {
	ListFiles(ctx context.Context, bucket string, prefix *string) ([]model.AwsS3Entity, error)
	GetFile(ctx context.Context, bucket string, key string, region string) (io.ReadCloser, error)
}

type DataUsageSyncer struct {
	configMap *config.ConfigMap
}

func NewDataUsageSyncer() *DataUsageSyncer {
	return &DataUsageSyncer{}
}

func (s *DataUsageSyncer) provideRepo() dataUsageRepository {
	return data_source2.NewAwsS3Repository(s.configMap)
}

func (s *DataUsageSyncer) SyncDataUsage(ctx context.Context, dataUsageFileHandler wrappers.DataUsageStatementHandler, configMap *config.ConfigMap) error {
	s.configMap = configMap
	repo := s.provideRepo()

	return s.syncDataUsageForRegion(ctx, dataUsageFileHandler, repo)
}

func (s *DataUsageSyncer) syncDataUsageForRegion(ctx context.Context, dataUsageFileHandler wrappers.DataUsageStatementHandler, repo dataUsageRepository) error {
	bucket := s.configMap.GetString(constants.AwsS3CloudTrailBucket)

	if bucket == "" {
		utils.Logger.Warn("No usage cloud trail bucket specified.")

		return nil
	}

	allUsageFiles, err := repo.ListFiles(ctx, bucket, nil)
	if err != nil {
		return fmt.Errorf("error while reading usage files from S3 bucket: %w", err)
	}

	utils.Logger.Info(fmt.Sprintf("A total of %d usage files found in bucket %s", len(allUsageFiles), bucket))

	numberOfDays := 90
	startDate := time.Now().Truncate(24*time.Hour).AddDate(0, 0, -numberOfDays)

	if s.configMap.Parameters["lastUsed"] != "" {
		startDateRaw, errLocal := time.Parse(time.RFC3339, s.configMap.Parameters["lastUsed"])
		if errLocal == nil && startDateRaw.After(startDate) {
			startDate = startDateRaw
		}
	}

	utils.Logger.Info(fmt.Sprintf("using start date %s", startDate.Format(time.RFC3339)))

	usageFiles := []string{}

	r := regexp.MustCompile(`.*/(\d{4}/\d{2}/\d{2})/.*`)
	dateFormat := "2006/01/02"

	for _, file := range allUsageFiles {
		matches := r.FindStringSubmatch(file.Key)
		if len(matches) != 2 {
			continue
		}

		dt, err2 := time.Parse(dateFormat, matches[1])
		if err2 != nil {
			continue
		}

		if strings.Contains(file.Key, "/CloudTrail/eu-central-1/") && time.Since(dt).Hours() < float64(numberOfDays+1)*24 {
			usageFiles = append(usageFiles, file.Key)
		}
	}

	utils.Logger.Info(fmt.Sprintf("%d files to process", len(usageFiles)))

	fileChan := make(chan string)
	workerPool := workerpool.New(utils.GetConcurrency(s.configMap))
	fileLock := new(sync.Mutex)
	numWorkers := 16

	doSyncer := data_source2.NewDataSourceSyncer()
	availableObjects, err := doSyncer.GetAvailableObjects(ctx, s.configMap)

	if err != nil {
		return fmt.Errorf("error while fetching available objects for data usage: %w", err)
	}

	for t := 0; t < numWorkers; t++ {
		workerPool.Submit(func() {
			readAndParseUsageLog(ctx, bucket, fileChan, repo, dataUsageFileHandler, fileLock, availableObjects)
		})
	}

	for _, usageFile := range usageFiles {
		fileChan <- usageFile
	}

	close(fileChan)
	workerPool.StopWait()

	return nil
}

func readAndParseUsageLog(ctx context.Context, bucketName string, fileChan chan string, repo dataUsageRepository,
	dataUsageFileHandler wrappers.DataUsageStatementHandler, fileLock *sync.Mutex, availableObjects map[string]interface{}) {
	utils.Logger.Info("Starting data usage worker")

	for fileKey := range fileChan {
		parts := strings.Split(fileKey, "/")
		fileKeyShort := parts[len(parts)-1]

		start := time.Now()

		contents, err := getFileContents(ctx, repo, bucketName, fileKey)
		if err != nil {
			utils.Logger.Error(err.Error())
			return
		}

		var result model.CloudTrailLog

		err = json.Unmarshal([]byte(contents), &result)
		if err != nil {
			utils.Logger.Error(err.Error())
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

				permission := fmt.Sprintf("%s:%s", constants.S3PermissionPrefix, *record.EventName)

				if resource.Type != nil && resource.Arn != nil && strings.EqualFold(*resource.Type, "AWS::S3::Object") {
					object := utils.ConvertArnToFullname(*resource.Arn)

					mappedObject := mapToClosedObject(object, availableObjects)
					if !strings.Contains(mappedObject, "/") {
						utils.Logger.Info(fmt.Sprintf("Could not map object %q to anything known. Skipping", object))
						continue
					}

					accessedObjects = append(accessedObjects, ap.WhatItem{
						DataObject: &data_source.DataObjectReference{
							FullName: mappedObject,
							Type:     data_source.File,
						},
						Permissions: []string{permission},
					})
				}
			}

			if isCloudTrailBucket || len(accessedObjects) == 0 {
				continue
			}

			userName := ""
			// TODO: investigate what the different possibilities are, this has been figured out by just looking
			// at the logs so far
			if record.UserIdentity == nil || record.UserIdentity.Type == nil {
				utils.Logger.Warn("user identity is nil")
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

			if userName != "" {
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
				utils.Logger.Error(err.Error())
				return
			}
		}

		utils.Logger.Info(fmt.Sprintf("%d records fetched and processed in %d ms from %s", len(result.Records), time.Since(start).Milliseconds(), fileKeyShort))
	}
}

// mapToClosedObject maps the object path to the closest available path.
func mapToClosedObject(object string, availableObjects map[string]interface{}) string {
	parts := strings.Split(object, "/")
	path := ""
	currentMap := availableObjects

	for _, part := range parts {
		nextElement, found := currentMap[part]

		if !found {
			break
		}

		path += part + "/"

		newMap, isMap := nextElement.(map[string]interface{})
		if isMap {
			currentMap = newMap
		}
	}

	path = strings.TrimSuffix(path, "/")

	return path
}

func getFileContents(ctx context.Context, repo dataUsageRepository, bucketName string, fileKey string) (string, error) {
	reader, err := repo.GetFile(ctx, bucketName, fileKey, "")
	if err != nil {
		return "", fmt.Errorf("get file: %w", err)
	}
	defer reader.Close()

	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return "", fmt.Errorf("new reader: %w", err)
	}
	defer gzipReader.Close()

	buf := new(strings.Builder)

	_, err = io.Copy(buf, gzipReader) //nolint:gosec // no risk of injection
	if err != nil {
		return "", fmt.Errorf("copy: %w", err)
	}

	return buf.String(), nil
}

func addStatementsToDataUsageHandler(dataUsageFileHandler wrappers.DataUsageStatementHandler, statements []data_usage.Statement, lock *sync.Mutex) error {
	lock.Lock()
	defer lock.Unlock()

	err := dataUsageFileHandler.AddStatements(statements)
	if err != nil {
		return fmt.Errorf("add statement to handler: %w", err)
	}

	return nil
}
