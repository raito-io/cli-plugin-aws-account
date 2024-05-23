package data_source

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/repo"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	"github.com/gammazero/workerpool"

	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"

	ds "github.com/raito-io/cli/base/data_source"
)

type DataSourceSyncer struct {
	config             *config.ConfigMap
	account            string
	dataObjectParent   string
	dataObjectExcludes []string
}

func NewDataSourceSyncer() *DataSourceSyncer {
	return &DataSourceSyncer{}
}

// GetAvailableObjects is used by the data usage component to fetch all available data objects in a map structure for easy lookup of what is available
func (s *DataSourceSyncer) GetAvailableObjects(ctx context.Context, cfg *config.ConfigMap) (map[string]interface{}, error) {
	err := s.initialize(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("initializing data source syncer: %w", err)
	}

	bucketMap := map[string]interface{}{}

	dataSourceHandler := mapDataSourceHandler{
		bucketMap: bucketMap,
	}

	err = s.fetchDataObjects(ctx, dataSourceHandler)
	if err != nil {
		return nil, err
	}

	return bucketMap, nil
}

func (s *DataSourceSyncer) initialize(ctx context.Context, cfg *config.ConfigMap) error {
	s.config = cfg

	var err error

	s.account, err = repo.GetAccountId(ctx, cfg)
	if err != nil {
		return fmt.Errorf("getting account id: %w", err)
	}

	return nil
}

func (s *DataSourceSyncer) SyncDataSource(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler, cfg *ds.DataSourceSyncConfig) error {
	err := s.initialize(ctx, cfg.ConfigMap)
	if err != nil {
		return fmt.Errorf("initializing data source syncer: %w", err)
	}

	s.dataObjectParent = cfg.DataObjectParent
	s.dataObjectExcludes = cfg.DataObjectExcludes

	err = s.addAwsAsDataSource(dataSourceHandler, nil)
	if err != nil {
		return err
	}

	return s.fetchDataObjects(ctx, dataSourceHandler)
}

func (s *DataSourceSyncer) fetchDataObjects(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler) error {
	s3Enabled := s.config.GetBoolWithDefault(constants.AwsS3Enabled, false)
	glueEnabled := s.config.GetBoolWithDefault(constants.AwsGlueEnabled, false)

	if s3Enabled && glueEnabled {
		return fmt.Errorf("both AWS S3 and AWS Glue are enabled, which is currently not supported")
	} else if !s3Enabled && !glueEnabled {
		return fmt.Errorf("neither AWS S3 nor AWS Glue are enabled; at least one of them must be enabled")
	}

	if s3Enabled {
		utils.Logger.Debug(fmt.Sprintf("Fetching data objects for account %s using AWS S3", s.account))

		err := s.FetchS3DataObjects(ctx, dataSourceHandler)
		if err != nil {
			return fmt.Errorf("fetch s3 data objects: %w", err)
		}
	} else {
		utils.Logger.Debug(fmt.Sprintf("Start fetching glue tables in account %q", s.account))

		var err error

		// Glue is not cross-regional so needs to be fetched per region
		for _, region := range utils.GetRegions(s.config) {
			utils.Logger.Debug(fmt.Sprintf("Fetching glue tables in region %q", region))

			glueErr := s.FetchGlueDataObjects(ctx, dataSourceHandler, region)
			if glueErr != nil {
				err = multierror.Append(err, fmt.Errorf("fetch glue data objects in region %q: %w", region, glueErr))
			}
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *DataSourceSyncer) FetchGlueDataObjects(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler, region string) error {
	glueRepo := NewAwsGlueRepository(s.config)
	dbs, err := glueRepo.ListDatabases(ctx, s.account, region)

	if err != nil {
		return fmt.Errorf("listing glue databases: %w", err)
	}

	pathsHandled := set.NewSet[string]()

	for _, db := range dbs {
		tables, err2 := glueRepo.ListTablesForDatabase(ctx, s.account, db, region)
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
			fullName := fmt.Sprintf("%s:%s:%s", s.account, region, bucketName)

			if !pathsHandled.Contains(fullName) {
				err = dataSourceHandler.AddDataObjects(&ds.DataObject{
					ExternalId:       fullName,
					Name:             bucketName,
					FullName:         fullName,
					Type:             ds.Bucket,
					ParentExternalId: s.account,
				})

				if err != nil {
					return fmt.Errorf("adding bucket %q to file: %w", fullName, err)
				}

				pathsHandled.Add(fullName)
			}

			currentPath := fullName

			// Now loop over the other parts
			for i := 1; i < len(pathParts); i++ {
				parentPath := currentPath
				currentPath += "/" + pathParts[i]

				if !pathsHandled.Contains(currentPath) {
					doType := ds.Folder

					// The last one we specify as type glue table
					if i == len(pathParts)-1 {
						doType = model.GlueTable
					}

					err = dataSourceHandler.AddDataObjects(&ds.DataObject{
						ExternalId:       currentPath,
						Name:             pathParts[i],
						FullName:         currentPath,
						Type:             doType,
						ParentExternalId: parentPath,
					})

					if err != nil {
						return fmt.Errorf("adding %s %q to file: %w", doType, currentPath, err)
					}

					pathsHandled.Add(currentPath)
				}
			}
		}
	}

	return nil
}

func (s *DataSourceSyncer) FetchS3DataObjects(ctx context.Context, dataSourceHandler wrappers.DataSourceObjectHandler) error {
	fileLock := new(sync.Mutex)
	s3Repo := NewAwsS3Repository(s.config)

	// handle datasets
	buckets, err := s3Repo.ListBuckets(ctx)
	if err != nil {
		return err
	}

	buckets, err = filterBuckets(s.config, buckets)
	if err != nil {
		return err
	}

	utils.Logger.Info(fmt.Sprintf("Found %d buckets to handle: %+v", len(buckets), buckets))

	err = s.addS3Entities(buckets, "", dataSourceHandler, nil)
	if err != nil {
		return err
	}

	// handle files
	workerPool := workerpool.New(utils.GetConcurrency(s.config))
	var smu sync.Mutex
	var resultErr error

	for i := range buckets {
		bucket := buckets[i]

		if !s.shouldGoInto(bucket.Key) {
			continue
		}

		workerPool.Submit(func() {
			bucketName := bucket.Key
			bucketFullName := fmt.Sprintf("%s::%s:%s", s.account, bucket.Region, bucketName)

			var prefix *string

			if p, f := strings.CutPrefix(s.dataObjectParent, bucketFullName+"/"); f {
				if !strings.HasSuffix(p, "/") {
					p += "/"
				}
				prefix = &p
				utils.Logger.Info(fmt.Sprintf("Handling files with prefix '%s' in bucket %s ", p, bucketFullName))
			} else {
				utils.Logger.Info(fmt.Sprintf("Handling all files in bucket %s", bucketFullName))
			}

			files, err2 := s3Repo.ListFiles(ctx, bucketName, prefix)
			if err2 != nil {
				smu.Lock()
				resultErr = multierror.Append(resultErr, err2)
				smu.Unlock()

				return
			}

			err2 = s.addS3Entities(files, bucket.Region, dataSourceHandler, fileLock)
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
	if lock == nil {
		lock = new(sync.Mutex)
	}

	if !s.shouldHandle(s.account) {
		return nil
	}

	lock.Lock()
	defer lock.Unlock()

	err := dataSourceHandler.AddDataObjects(&ds.DataObject{
		ExternalId:       s.account,
		Name:             s.account,
		FullName:         s.account,
		Type:             ds.Datasource,
		Description:      fmt.Sprintf("DataSource for AWS account %s", s.account),
		ParentExternalId: "",
	})

	if err != nil {
		return fmt.Errorf("add data object to handler: %w", err)
	}

	return nil
}

func (s *DataSourceSyncer) addS3Entities(entities []model.AwsS3Entity, region string, dataSourceHandler wrappers.DataSourceObjectHandler, lock *sync.Mutex) error {
	emulateFolders := s.config.GetBoolWithDefault(constants.AwsS3EmulateFolderStructure, true)

	if lock == nil {
		lock = new(sync.Mutex)
	}

	doneFolders := make(map[string]struct{})

	for _, entity := range entities {
		if strings.EqualFold(entity.Type, ds.Bucket) {
			if !s.shouldHandle(entity.Key) {
				continue
			}

			fullName := fmt.Sprintf("%s:%s:%s", s.account, entity.Region, entity.Key)

			lock.Lock()
			err := dataSourceHandler.AddDataObjects(&ds.DataObject{
				ExternalId:       fullName,
				Name:             entity.Key,
				FullName:         fullName,
				Type:             ds.Bucket,
				ParentExternalId: s.account,
			})

			lock.Unlock()

			if err != nil {
				return fmt.Errorf("add data object to handler: %w", err)
			}
		} else if strings.EqualFold(entity.Type, ds.File) {
			if emulateFolders {
				maxFolderDepth := s.config.GetIntWithDefault(constants.AwsS3MaxFolderDepth, 20)

				parts := strings.Split(entity.Key, "/")
				parentExternalId := fmt.Sprintf("%s:%s:%s", s.account, region, entity.ParentKey)

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
						return fmt.Errorf("add data object to handler: %w", err)
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

				fullName := fmt.Sprintf("%s:%s:%s", s.account, region, entity.Key)
				parent := fmt.Sprintf("%s:%s:%s", s.account, region, entity.ParentKey)

				err := dataSourceHandler.AddDataObjects(&ds.DataObject{
					ExternalId:       fullName,
					Name:             entity.Key,
					FullName:         fullName,
					Type:             entity.Type,
					ParentExternalId: parent,
				})
				lock.Unlock()

				if err != nil {
					return fmt.Errorf("add data object to handler: %w", err)
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
	if s.dataObjectParent == "" {
		return true
	}

	// Check if the data object is under the data object to start from
	if !strings.HasPrefix(fullName, s.dataObjectParent) || s.dataObjectParent == fullName {
		return false
	}

	// Check if we hit any excludes
	for _, exclude := range s.dataObjectExcludes {
		if strings.HasPrefix(fullName, s.dataObjectParent+"/"+exclude) {
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
	if s.dataObjectParent == "" || strings.HasPrefix(s.dataObjectParent, fullName) || strings.HasPrefix(fullName, s.dataObjectParent) {
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

type mapDataSourceHandler struct {
	bucketMap map[string]interface{}
}

func (m mapDataSourceHandler) AddDataObjects(dataObjects ...*ds.DataObject) error {
	for _, dataObject := range dataObjects {
		parts := strings.Split(dataObject.FullName, "/")

		currentMap := m.bucketMap

		for _, part := range parts {
			partMap, found := currentMap[part]
			if !found {
				partMap = map[string]interface{}{}
				currentMap[part] = partMap
			}

			currentMap = partMap.(map[string]interface{})
		}
	}

	return nil
}

func (m mapDataSourceHandler) SetDataSourceName(name string) {
}

func (m mapDataSourceHandler) SetDataSourceFullname(name string) {
}

func (m mapDataSourceHandler) SetDataSourceDescription(desc string) {
}
