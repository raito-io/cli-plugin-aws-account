package aws

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/gammazero/workerpool"

	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"

	ds "github.com/raito-io/cli/base/data_source"
)

//go:generate go run github.com/vektra/mockery/v2 --name=dataSourceRepository --with-expecter --inpackage
type dataSourceRepository interface {
	ListBuckets(ctx context.Context) ([]AwsS3Entity, error)
	ListFiles(ctx context.Context, bucket string, prefix *string) ([]AwsS3Entity, error)
}

type DataSourceSyncer struct {
	configMap *config.ConfigMap
}

func NewDataSourceSyncer() *DataSourceSyncer {
	return &DataSourceSyncer{}
}

func (s *DataSourceSyncer) provideRepo() dataSourceRepository {
	return &AwsS3Repository{
		configMap: s.configMap,
	}
}

func getRegExList(input string) ([]*regexp.Regexp, error) {
	input = strings.TrimSpace(input)

	if input == "" {
		return []*regexp.Regexp{}, nil
	}

	inputSlice := strings.Split(input, ",")

	ret := make([]*regexp.Regexp, 0, len(inputSlice))

	for _, item := range inputSlice {
		if item == "" {
			continue
		}

		if strings.Contains(item, "*") {
			item = strings.ReplaceAll(item, "*", ".*")
		}

		item = "^" + item + "$"

		re, err := regexp.Compile(item)
		if err != nil {
			return nil, fmt.Errorf("unable to parse regular expression %s: %s", item, err.Error())
		}

		ret = append(ret, re)
	}

	return ret, nil
}

func filterBuckets(configMap *config.ConfigMap, buckets []AwsS3Entity) ([]AwsS3Entity, error) {
	logger.Debug(fmt.Sprintf("Input buckets: %+v", buckets))

	included, err := getRegExList(configMap.GetString(AwsS3IncludeBuckets))
	if err != nil {
		return nil, err
	}

	excluded, err := getRegExList(configMap.GetString(AwsS3ExcludeBuckets))
	if err != nil {
		return nil, err
	}

	if len(included) == 0 && len(excluded) == 0 {
		logger.Debug("No buckets to include or exclude, so using all buckets.")
		return buckets, nil
	}

	filteredBuckets := make([]AwsS3Entity, 0, len(buckets))

	for i := range buckets {
		bucket := buckets[i]

		include := true

		if len(included) > 0 {
			include = false

			for _, includedBucket := range included {
				if includedBucket.MatchString(bucket.Key) {
					logger.Debug(fmt.Sprintf("Including bucket %s", bucket.Key))
					include = true

					break
				}
			}
		}

		if include && len(excluded) > 0 {
			for _, excludedBucket := range excluded {
				if excludedBucket.MatchString(bucket.Key) {
					logger.Debug(fmt.Sprintf("Excluding bucket %s", bucket.Key))
					include = false

					break
				}
			}
		}

		if include {
			filteredBuckets = append(filteredBuckets, bucket)
		}
	}

	return filteredBuckets, nil
}

func (s *DataSourceSyncer) SyncDataSource(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler, configMap *config.ConfigMap) error {
	s.configMap = configMap

	// add AWS S3 as DataObject of type DataSource
	fileLock := new(sync.Mutex)

	err := s.addAwsAsDataSource(dataSourceHandler, configMap, nil)
	if err != nil {
		return err
	}

	// handle datasets
	buckets, err := s.provideRepo().ListBuckets(ctx)
	if err != nil {
		return err
	}

	buckets, err = filterBuckets(configMap, buckets)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Found %d buckets to handle: %+v", len(buckets), buckets))

	err = s.addS3Entities(buckets, dataSourceHandler, configMap, nil)
	if err != nil {
		return err
	}

	// handle files
	workerPool := workerpool.New(getConcurrency(configMap))
	var smu sync.Mutex
	var resultErr error

	for i := range buckets {
		bucket := buckets[i]

		workerPool.Submit(func() {
			bucketName := bucket.Key
			files, err2 := s.provideRepo().ListFiles(ctx, bucketName, nil)
			if err2 != nil {
				smu.Lock()
				resultErr = multierror.Append(resultErr, err2)
				smu.Unlock()

				return
			}

			err2 = s.addS3Entities(files, dataSourceHandler, configMap, fileLock)
			if err2 != nil {
				smu.Lock()
				resultErr = multierror.Append(resultErr, err2)
				smu.Unlock()

				return
			}
		})
	}

	workerPool.StopWait()

	return resultErr
}

func (s *DataSourceSyncer) GetDataSourceMetaData(ctx context.Context) (*ds.MetaData, error) {
	logger.Debug("Returning meta data for AWS S3 data source")

	return GetS3MetaData(), nil
}

func (s *DataSourceSyncer) addAwsAsDataSource(dataSourceHandler wrappers.DataSourceObjectHandler, configMap *config.ConfigMap, lock *sync.Mutex) error {
	awsAccount := configMap.GetString(AwsAccountId)

	if lock == nil {
		lock = new(sync.Mutex)
	}

	lock.Lock()
	defer lock.Unlock()

	return dataSourceHandler.AddDataObjects(&ds.DataObject{
		ExternalId:       awsAccount,
		Name:             awsAccount,
		FullName:         awsAccount,
		Type:             ds.Datasource,
		Description:      fmt.Sprintf("DataSource for AWS account %s", awsAccount),
		ParentExternalId: "",
	})
}

func (s *DataSourceSyncer) addS3Entities(entities []AwsS3Entity, dataSourceHandler wrappers.DataSourceObjectHandler, configMap *config.ConfigMap, lock *sync.Mutex) error {
	awsAccount := configMap.GetString(AwsAccountId)
	emulateFolders := configMap.GetBoolWithDefault(AwsS3EmulateFolderStructure, true)

	if lock == nil {
		lock = new(sync.Mutex)
	}

	doneFolders := make(map[string]struct{})

	for _, entity := range entities {
		if strings.EqualFold(entity.Type, ds.Bucket) {
			lock.Lock()
			err := dataSourceHandler.AddDataObjects(&ds.DataObject{
				ExternalId:       entity.Key,
				Name:             entity.Key,
				FullName:         entity.Key,
				Type:             ds.Bucket,
				Description:      fmt.Sprintf("AWS bucket %s:%s", awsAccount, entity.Key),
				ParentExternalId: awsAccount,
			})

			lock.Unlock()

			if err != nil {
				return err
			}
		} else if strings.EqualFold(entity.Type, ds.File) {
			if emulateFolders {
				maxFolderDepth := configMap.GetIntWithDefault(AwsS3MaxFolderDepth, 100)

				parts := strings.Split(entity.Key, "/")
				parentExternalId := entity.ParentKey

				for ind := range parts {
					if ind >= maxFolderDepth {
						continue
					}

					fullName := fmt.Sprintf("%s/%s", parentExternalId, parts[ind])
					doType := ds.Folder

					if ind == len(parts)-1 {
						doType = ds.File
					} else {
						// Make sure we don't handle folders multiple times
						if _, f := doneFolders[fullName]; f {
							parentExternalId = fullName
							continue
						} else {
							doneFolders[fullName] = struct{}{}
						}
					}

					lock.Lock()
					err := dataSourceHandler.AddDataObjects(&ds.DataObject{
						ExternalId:       fullName,
						Name:             parts[ind],
						FullName:         fullName,
						Type:             doType,
						Description:      fmt.Sprintf("AWS file %s %s", awsAccount, entity.Type),
						ParentExternalId: parentExternalId,
					})
					lock.Unlock()
					if err != nil {
						return err
					}

					parentExternalId = fullName
				}
			} else {
				lock.Lock()
				err := dataSourceHandler.AddDataObjects(&ds.DataObject{
					ExternalId:       entity.Key,
					Name:             entity.Key,
					FullName:         entity.Key,
					Type:             entity.Type,
					Description:      fmt.Sprintf("AWS file %s %s", awsAccount, entity.Type),
					ParentExternalId: entity.ParentKey,
				})
				lock.Unlock()
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
