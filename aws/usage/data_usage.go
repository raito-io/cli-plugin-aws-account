package usage

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
	"github.com/hashicorp/go-multierror"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	data_source2 "github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source/permissions"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	baserepo "github.com/raito-io/cli-plugin-aws-account/aws/repo"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils/trie"

	"github.com/raito-io/cli/base/data_usage"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"
)

type dataUsageRepository interface {
	ListFiles(ctx context.Context, bucket string, prefix *string) ([]model.AwsS3Entity, string, error)
	GetFile(ctx context.Context, bucket string, key string, region *string) (io.ReadCloser, error)
}

type dataObjectRepository interface {
	GetAvailableObjectTypes(ctx context.Context, cfg *config.ConfigMap) (*trie.Trie[string], error)
}

type DataUsageSyncer struct {
	account        string
	repo           dataUsageRepository
	dataObjectRepo dataObjectRepository
	configMap      *config.ConfigMap
}

func NewDataUsageSyncer() *DataUsageSyncer {
	return &DataUsageSyncer{}
}

func (s *DataUsageSyncer) provideRepo() dataUsageRepository {
	return data_source2.NewAwsS3Repository(s.configMap)
}

func (s *DataUsageSyncer) SyncDataUsage(ctx context.Context, dataUsageFileHandler wrappers.DataUsageStatementHandler, configMap *config.ConfigMap) error {
	s.configMap = configMap
	s.repo = s.provideRepo()
	s.dataObjectRepo = data_source2.NewDataSourceSyncer()

	var err error

	s.account, err = baserepo.GetAccountId(ctx, configMap)
	if err != nil {
		return fmt.Errorf("getting account id: %w", err)
	}

	return s.syncDataUsage(ctx, dataUsageFileHandler, configMap)
}

func (s *DataUsageSyncer) syncDataUsage(ctx context.Context, dataUsageFileHandler wrappers.DataUsageStatementHandler, configMap *config.ConfigMap) error {
	dataObjectMapper, err := ObjectMapperFactory(ctx, s.dataObjectRepo, configMap)
	if err != nil {
		return fmt.Errorf("get data object mapper: %w", err)
	}

	regions, err := s.getAllRegions(ctx)
	if err != nil {
		return fmt.Errorf("get all regions: %w", err)
	}

	err = s.syncDataUsageForAllRegions(ctx, regions, dataUsageFileHandler, dataObjectMapper)
	if err != nil {
		return fmt.Errorf("sync data usage: %w", err)
	}

	return nil
}

func (s *DataUsageSyncer) syncDataUsageForAllRegions(ctx context.Context, regions set.Set[string], dataUsageFileHandler wrappers.DataUsageStatementHandler, dataObjectMapper ObjectMapper) error {
	for region := range regions {
		err := s.syncDataUsageForRegion(ctx, region, dataUsageFileHandler, dataObjectMapper)
		if err != nil {
			return fmt.Errorf("sync data usage for region %q: %w", region, err)
		}
	}

	return nil
}

func (s *DataUsageSyncer) getAllRegions(ctx context.Context) (set.Set[string], error) {
	regionsStr := s.configMap.GetString(constants.AwsRegions)
	if regionsStr == "" {
		cfg, err := baserepo.GetAWSConfig(ctx, s.configMap, nil)
		if err != nil {
			return nil, fmt.Errorf("get aws config: %w", err)
		}

		return set.NewSet(cfg.Region), nil
	}

	regions := strings.Split(regionsStr, ",")

	return set.NewSet(regions...), nil
}

func (s *DataUsageSyncer) addStatementsToDataUsageHandler(dataUsageFileHandler wrappers.DataUsageStatementHandler, statementChannel <-chan []data_usage.Statement, errorChannel chan<- error) {
	for statements := range statementChannel {
		utils.Logger.Info(fmt.Sprintf("Will add %d statements to data usage handler", len(statements)))

		err := addStatementsToDataUsageHandler(dataUsageFileHandler, statements, new(sync.Mutex))
		if err != nil {
			errorChannel <- fmt.Errorf("add statement to data usage handler: %w", err)
		}
	}
}

func (s *DataUsageSyncer) syncDataUsageForRegion(ctx context.Context, region string, dataUsageFileHandler wrappers.DataUsageStatementHandler, dataObjectMapper ObjectMapper) error {
	bucket := s.configMap.GetString(constants.AwsS3CloudTrailBucket)

	// Preparation
	if bucket == "" {
		utils.Logger.Warn("No usage cloud trail bucket specified.")

		return nil
	}

	usageFiles, bucketRegion, err := s.loadUsageFilesInRegion(ctx, bucket, region)
	if err != nil {
		return fmt.Errorf("load usage files: %w", err)
	}

	workerPool := workerpool.New(utils.GetConcurrency(s.configMap))
	statementChannel := make(chan []data_usage.Statement)
	errorChannel := make(chan error)

	// error parsing
	var errorParsingWg sync.WaitGroup
	var parsingErrors error

	errorParsingWg.Add(1)

	go func() {
		defer errorParsingWg.Done()

		for parsingErr := range errorChannel {
			parsingErrors = multierror.Append(parsingErrors, parsingErr)
		}
	}()

	// statement parsing
	var statementParsingWg sync.WaitGroup
	statementParsingWg.Add(1)

	go func() {
		defer statementParsingWg.Done()

		s.addStatementsToDataUsageHandler(dataUsageFileHandler, statementChannel, errorChannel)
	}()

	// Syncing
	for _, usageFile := range usageFiles {
		workerPool.Submit(func() {
			s.readAndParseUsageLog(ctx, bucket, bucketRegion, region, usageFile, dataObjectMapper, statementChannel, errorChannel)
		})
	}

	workerPool.StopWait()
	close(statementChannel)
	statementParsingWg.Wait()
	close(errorChannel)
	errorParsingWg.Wait()

	return parsingErrors
}

func (s *DataUsageSyncer) loadUsageFilesInRegion(ctx context.Context, bucket string, region string) ([]string, string, error) {
	allUsageFiles, bucketRegion, err := s.repo.ListFiles(ctx, bucket, nil)
	if err != nil {
		return nil, "", fmt.Errorf("error while reading usage files from S3 bucket: %w", err)
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

		if strings.Contains(file.Key, fmt.Sprintf("/CloudTrail/%s/", region)) && time.Since(dt).Hours() < float64(numberOfDays+1)*24 {
			usageFiles = append(usageFiles, file.Key)
		}
	}

	utils.Logger.Info(fmt.Sprintf("%d files to process", len(usageFiles)))

	return usageFiles, bucketRegion, nil
}

func (s *DataUsageSyncer) readAndParseUsageLog(ctx context.Context, bucketName string, bucketRegion string, region string, fileKey string, dataObjectMapper ObjectMapper, statementChannel chan<- []data_usage.Statement, errorChannel chan<- error) {
	parts := strings.Split(fileKey, "/")
	fileKeyShort := parts[len(parts)-1]

	start := time.Now()

	contents, err := getFileContents(ctx, s.repo, bucketName, bucketRegion, fileKey)
	if err != nil {
		errorChannel <- fmt.Errorf("get content of file \"%s/%s\": %w", bucketName, fileKey, err)

		return
	}

	var result model.CloudTrailLog

	err = json.Unmarshal([]byte(contents), &result)
	if err != nil {
		errorChannel <- fmt.Errorf("unmarshal: %w", err)

		return
	}

	statements := make([]data_usage.Statement, 0, len(result.Records))

	for ind := range result.Records {
		record := result.Records[ind]
		isCloudTrailBucket := false
		accessedObjects := make([]data_usage.UsageDataObjectItem, 0, len(record.Resources))

		for _, resource := range record.Resources {
			if resource.Type != nil && resource.Arn != nil && strings.Contains(*resource.Arn, bucketName) {
				isCloudTrailBucket = true
				break
			}

			permission := fmt.Sprintf("%s:%s", constants.S3PermissionPrefix, *record.EventName)

			if resource.Type != nil && resource.Arn != nil && strings.EqualFold(*resource.Type, "AWS::S3::Object") {
				object := utils.ConvertArnToFullname(*resource.Arn)

				mappedWhatDataObject := dataObjectMapper.MapObject(fmt.Sprintf("%s:%s:%s", s.account, region, object))
				if mappedWhatDataObject == nil {
					utils.Logger.Info(fmt.Sprintf("Could not map object %q to anything known. Skipping", object))
					continue
				}

				objectItem := data_usage.UsageDataObjectItem{
					DataObject:  *mappedWhatDataObject,
					Permissions: []string{permission},
				}

				globalPermission, _ := permissions.GetS3Permission(permission)

				for _, a := range globalPermission.UsageGlobalPermissions {
					action, actionErr := data_usage.ActionTypeString(a)
					if actionErr != nil {
						utils.Logger.Warn(fmt.Sprintf("Could not parse action %q: %v", a, actionErr))
						continue
					}

					if objectItem.GlobalPermission < action {
						objectItem.GlobalPermission = action
					}
				}

				accessedObjects = append(accessedObjects, objectItem)
			}
		}

		if isCloudTrailBucket || len(accessedObjects) == 0 {
			utils.Logger.Info("Skipping cloud trail or no accessed objects found")
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

		var bytes int
		if record.Bytes != nil {
			bytes = int(record.Bytes.BytesIn) + int(record.Bytes.BytesOut)
		}

		if userName != "" {
			statements = append(statements, data_usage.Statement{
				ExternalId:          *record.EventID,
				StartTime:           record.EventTime.Unix(),
				Bytes:               bytes,
				AccessedDataObjects: accessedObjects,
				User:                userName,
				Success:             true,
			})
		}
	}

	if len(statements) > 0 {
		statementChannel <- statements
	}

	utils.Logger.Info(fmt.Sprintf("%d records fetched and processed in %d ms from %s", len(result.Records), time.Since(start).Milliseconds(), fileKeyShort))
}

func getFileContents(ctx context.Context, repo dataUsageRepository, bucketName string, bucketRegion string, fileKey string) (string, error) {
	reader, err := repo.GetFile(ctx, bucketName, fileKey, &bucketRegion)
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
