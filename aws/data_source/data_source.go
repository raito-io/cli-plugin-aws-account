package data_source

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/golang-set/set"

	"github.com/gammazero/workerpool"

	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"

	ds "github.com/raito-io/cli/base/data_source"
)

type DataSourceSyncer struct {
	config *ds.DataSourceSyncConfig
}

func NewDataSourceSyncer() *DataSourceSyncer {
	return &DataSourceSyncer{}
}

func (s *DataSourceSyncer) SyncDataSource(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler, config *ds.DataSourceSyncConfig) error {
	s.config = config

	fileLock := new(sync.Mutex)

	err := s.addAwsAsDataSource(dataSourceHandler, nil)
	if err != nil {
		return err
	}

	s3Enabled := config.GetConfigMap().GetBoolWithDefault(constants.AwsS3Enabled, false)
	glueEnabled := config.GetConfigMap().GetBoolWithDefault(constants.AwsGlueEnabled, false)

	if s3Enabled && glueEnabled {
		return fmt.Errorf("both AWS S3 and AWS Glue are enabled, which is currently not supported")
	} else if !s3Enabled && !glueEnabled {
		return fmt.Errorf("neither AWS S3 nor AWS Glue are enabled; at least one of them must be enabled")
	}

	if s3Enabled {
		return s.FetchS3DataObjects(ctx, dataSourceHandler, fileLock)
	} else {
		return s.FetchGlueDataObjects(ctx, dataSourceHandler)
	}
}

func (s *DataSourceSyncer) FetchGlueDataObjects(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler) error {
	accountId := s.config.ConfigMap.GetString(constants.AwsAccountId)

	glueRepo := NewAwsGlueRepository(s.config.ConfigMap)
	dbs, err := glueRepo.ListDatabases(ctx, accountId)

	if err != nil {
		return fmt.Errorf("listing glue databases: %w", err)
	}

	pathsHandled := set.NewSet[string]()

	for _, db := range dbs {
		tables, err2 := glueRepo.ListTablesForDatabase(ctx, accountId, db)
		if err2 != nil {
			return fmt.Errorf("listing glue tables: %w", err2)
		}

		for tableName, location := range tables {
			if !strings.HasPrefix(location, "s3://") {
				continue
			}

			utils.Logger.Debug(fmt.Sprintf("Handling table %q with location %q", tableName, location))

			location = strings.TrimPrefix(location, "s3://")
			location = strings.TrimSuffix(location, "/")

			pathParts := strings.Split(location, "/")
			bucketName := pathParts[0]

			if !pathsHandled.Contains(bucketName) {
				err = dataSourceHandler.AddDataObjects(&ds.DataObject{
					ExternalId:       bucketName,
					Name:             bucketName,
					FullName:         bucketName,
					Type:             ds.Bucket,
					ParentExternalId: accountId,
				})

				if err != nil {
					return fmt.Errorf("adding bucket %q to file: %w", bucketName, err)
				}

				pathsHandled.Add(bucketName)
			}

			currentPath := bucketName

			// Now loop over the other parts
			for i := 1; i < len(pathParts); i++ {
				parentPath := currentPath
				currentPath += "/" + pathParts[i]

				if !pathsHandled.Contains(currentPath) {
					err = dataSourceHandler.AddDataObjects(&ds.DataObject{
						ExternalId:       currentPath,
						Name:             pathParts[i],
						FullName:         currentPath,
						Type:             ds.Folder,
						ParentExternalId: parentPath,
					})

					if err != nil {
						return fmt.Errorf("adding folder %q to file: %w", currentPath, err)
					}

					pathsHandled.Add(currentPath)
				}
			}
		}
	}

	return nil
}

func (s *DataSourceSyncer) FetchS3DataObjects(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler, fileLock *sync.Mutex) error {
	s3Repo := NewAwsS3Repository(s.config.ConfigMap)

	// handle datasets
	buckets, err := s3Repo.ListBuckets(ctx)
	if err != nil {
		return err
	}

	buckets, err = filterBuckets(s.config.ConfigMap, buckets)
	if err != nil {
		return err
	}

	utils.Logger.Info(fmt.Sprintf("Found %d buckets to handle: %+v", len(buckets), buckets))

	err = s.addS3Entities(buckets, dataSourceHandler, nil)
	if err != nil {
		return err
	}

	// handle files
	workerPool := workerpool.New(utils.GetConcurrency(s.config.ConfigMap))
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

			if p, f := strings.CutPrefix(s.config.DataObjectParent, bucketName+"/"); f {
				if !strings.HasSuffix(p, "/") {
					p += "/"
				}
				prefix = &p
				utils.Logger.Info(fmt.Sprintf("Handling files with prefix '%s' in bucket %s ", p, bucketName))
			} else {
				utils.Logger.Info(fmt.Sprintf("Handling all files in bucket %s", bucketName))
			}

			files, err2 := s3Repo.ListFiles(ctx, bucketName, prefix)
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
	utils.Logger.Debug("Returning meta data for AWS S3 data source")

	return GetS3MetaData(), nil
}

func (s *DataSourceSyncer) addAwsAsDataSource(dataSourceHandler wrappers.DataSourceObjectHandler, lock *sync.Mutex) error {
	awsAccount := s.config.ConfigMap.GetString(constants.AwsAccountId)

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

func (s *DataSourceSyncer) addS3Entities(entities []model.AwsS3Entity, dataSourceHandler wrappers.DataSourceObjectHandler, lock *sync.Mutex) error {
	awsAccount := s.config.ConfigMap.GetString(constants.AwsAccountId)
	emulateFolders := s.config.ConfigMap.GetBoolWithDefault(constants.AwsS3EmulateFolderStructure, true)

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
				maxFolderDepth := s.config.ConfigMap.GetIntWithDefault(constants.AwsS3MaxFolderDepth, 20)

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
		utils.Logger.Debug(fmt.Sprintf("shouldHandle %s: %t", fullName, ret))
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
		utils.Logger.Debug(fmt.Sprintf("shouldGoInto %s: %t", fullName, ret))
	}()

	// No partial sync specified, so do everything
	if s.config.DataObjectParent == "" || strings.HasPrefix(s.config.DataObjectParent, fullName) || strings.HasPrefix(fullName, s.config.DataObjectParent) {
		return true
	}

	return false
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

func filterBuckets(configMap *config.ConfigMap, buckets []model.AwsS3Entity) ([]model.AwsS3Entity, error) {
	utils.Logger.Debug(fmt.Sprintf("Input buckets: %+v", buckets))

	included, err := getRegExList(configMap.GetString(constants.AwsS3IncludeBuckets))
	if err != nil {
		return nil, err
	}

	excluded, err := getRegExList(configMap.GetString(constants.AwsS3ExcludeBuckets))
	if err != nil {
		return nil, err
	}

	if len(included) == 0 && len(excluded) == 0 {
		utils.Logger.Debug("No buckets to include or exclude, so using all buckets.")
		return buckets, nil
	}

	filteredBuckets := make([]model.AwsS3Entity, 0, len(buckets))

	for i := range buckets {
		bucket := buckets[i]

		include := true

		if len(included) > 0 {
			include = false

			for _, includedBucket := range included {
				if includedBucket.MatchString(bucket.Key) {
					utils.Logger.Debug(fmt.Sprintf("Including bucket %s", bucket.Key))
					include = true

					break
				}
			}
		}

		if include && len(excluded) > 0 {
			for _, excludedBucket := range excluded {
				if excludedBucket.MatchString(bucket.Key) {
					utils.Logger.Debug(fmt.Sprintf("Excluding bucket %s", bucket.Key))
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