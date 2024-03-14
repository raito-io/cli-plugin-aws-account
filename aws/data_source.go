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
	config *ds.DataSourceSyncConfig
}

func NewDataSourceSyncer() *DataSourceSyncer {
	return &DataSourceSyncer{}
}

func (s *DataSourceSyncer) provideRepo() dataSourceRepository {
	return &AwsS3Repository{
		configMap: s.config.ConfigMap,
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

func (s *DataSourceSyncer) SyncDataSource(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler, config *ds.DataSourceSyncConfig) error {
	s.config = config

	// add AWS S3 as DataObject of type DataSource
	fileLock := new(sync.Mutex)

	err := s.addAwsAsDataSource(dataSourceHandler, nil)
	if err != nil {
		return err
	}

	// handle datasets
	buckets, err := s.provideRepo().ListBuckets(ctx)
	if err != nil {
		return err
	}

	buckets, err = filterBuckets(config.ConfigMap, buckets)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Found %d buckets to handle: %+v", len(buckets), buckets))

	err = s.addS3Entities(buckets, dataSourceHandler, nil)
	if err != nil {
		return err
	}

	// handle files
	workerPool := workerpool.New(getConcurrency(config.ConfigMap))
	var smu sync.Mutex
	var resultErr error

	for i := range buckets {
		bucket := buckets[i]

		if !s.shouldGoInto(bucket.Key) {
			continue
		}

		workerPool.Submit(func() {
			bucketName := bucket.Key

			var prefix *string

			if p, f := strings.CutPrefix(config.DataObjectParent, bucketName+"/"); f {
				if !strings.HasSuffix(p, "/") {
					p += "/"
				}
				prefix = &p
				logger.Info(fmt.Sprintf("Handling files with prefix '%s' in bucket %s ", p, bucketName))
			} else {
				logger.Info(fmt.Sprintf("Handling all files in bucket %s", bucketName))
			}

			files, err2 := s.provideRepo().ListFiles(ctx, bucketName, prefix)
			if err2 != nil {
				smu.Lock()
				resultErr = multierror.Append(resultErr, err2)
				smu.Unlock()

				return
			}

			err2 = s.addS3Entities(files, dataSourceHandler, fileLock)
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

func (s *DataSourceSyncer) GetDataSourceMetaData(ctx context.Context, configParams *config.ConfigMap) (*ds.MetaData, error) {
	logger.Debug("Returning meta data for AWS S3 data source")

	return GetS3MetaData(), nil
}

func (s *DataSourceSyncer) addAwsAsDataSource(dataSourceHandler wrappers.DataSourceObjectHandler, lock *sync.Mutex) error {
	awsAccount := s.config.ConfigMap.GetString(AwsAccountId)

	if lock == nil {
		lock = new(sync.Mutex)
	}

	if !s.shouldHandle(awsAccount) {
		return nil
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

func (s *DataSourceSyncer) addS3Entities(entities []AwsS3Entity, dataSourceHandler wrappers.DataSourceObjectHandler, lock *sync.Mutex) error {
	awsAccount := s.config.ConfigMap.GetString(AwsAccountId)
	emulateFolders := s.config.ConfigMap.GetBoolWithDefault(AwsS3EmulateFolderStructure, true)

	if lock == nil {
		lock = new(sync.Mutex)
	}

	doneFolders := make(map[string]struct{})

	for _, entity := range entities {
		if strings.EqualFold(entity.Type, ds.Bucket) {
			if !s.shouldHandle(entity.Key) {
				continue
			}

			lock.Lock()
			err := dataSourceHandler.AddDataObjects(&ds.DataObject{
				ExternalId:       entity.Key,
				Name:             entity.Key,
				FullName:         entity.Key,
				Type:             ds.Bucket,
				ParentExternalId: awsAccount,
			})

			lock.Unlock()

			if err != nil {
				return err
			}
		} else if strings.EqualFold(entity.Type, ds.File) {
			if emulateFolders {
				maxFolderDepth := s.config.ConfigMap.GetIntWithDefault(AwsS3MaxFolderDepth, 20)

				parts := strings.Split(entity.Key, "/")
				parentExternalId := entity.ParentKey

				for ind := range parts {
					// In case we found a folder, the path ended with a slash and so the last part will be empty and so can be skipped.
					if ind == len(parts)-1 && parts[ind] == "" {
						break
					}

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

					if !s.shouldHandle(fullName) {
						parentExternalId = fullName
						continue
					}

					lock.Lock()
					err := dataSourceHandler.AddDataObjects(&ds.DataObject{
						ExternalId:       fullName,
						Name:             parts[ind],
						FullName:         fullName,
						Type:             doType,
						ParentExternalId: parentExternalId,
					})
					lock.Unlock()

					if err != nil {
						return err
					}

					// If we don't need to go deeper
					if doType == ds.Folder && !s.shouldGoInto(fullName) {
						break
					}

					parentExternalId = fullName
				}
			} else {
				if !s.shouldHandle(entity.Key) {
					continue
				}

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

// shouldHandle determines if this data object needs to be handled by the syncer or not. It does this by looking at the configuration options to only sync a part.
func (s *DataSourceSyncer) shouldHandle(fullName string) (ret bool) {
	defer func() {
		logger.Debug(fmt.Sprintf("shouldHandle %s: %t", fullName, ret))
	}()

	// No partial sync specified, so do everything
	if s.config.DataObjectParent == "" {
		return true
	}

	// Check if the data object is under the data object to start from
	if !strings.HasPrefix(fullName, s.config.DataObjectParent) || s.config.DataObjectParent == fullName {
		return false
	}

	// Check if we hit any excludes
	for _, exclude := range s.config.DataObjectExcludes {
		if strings.HasPrefix(fullName, s.config.DataObjectParent+"/"+exclude) {
			return false
		}
	}

	return true
}

// shouldGoInto checks if we need to go deeper into this data object or not.
func (s *DataSourceSyncer) shouldGoInto(fullName string) (ret bool) {
	defer func() {
		logger.Debug(fmt.Sprintf("shouldGoInto %s: %t", fullName, ret))
	}()

	// No partial sync specified, so do everything
	if s.config.DataObjectParent == "" || strings.HasPrefix(s.config.DataObjectParent, fullName) || strings.HasPrefix(fullName, s.config.DataObjectParent) {
		return true
	}

	return false
}
