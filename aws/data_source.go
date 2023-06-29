package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

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

	err = s.addS3Entities(buckets, dataSourceHandler, configMap, nil)
	if err != nil {
		return err
	}

	// handle files
	wg := new(sync.WaitGroup)
	for _, bucket := range buckets {
		wg.Add(1)

		go func(ctx context.Context, configMap *config.ConfigMap, bucketName string, wg *sync.WaitGroup) {
			defer wg.Done()

			files, err := s.provideRepo().ListFiles(ctx, bucketName, nil)
			if err != nil {
				return
			}

			err = s.addS3Entities(files, dataSourceHandler, configMap, fileLock)
			if err != nil {
				return
			}
		}(ctx, configMap, bucket.Key, wg)
	}

	wg.Wait()

	return nil
}

func (s *DataSourceSyncer) GetDataSourceMetaData(ctx context.Context) (*ds.MetaData, error) {
	logger.Debug("Returning meta data for AWS S3 data source")

	metadata := GetS3MetaData()

	return &metadata, nil
}

func (s *DataSourceSyncer) addAwsAsDataSource(dataSourceHandler wrappers.DataSourceObjectHandler, configMap *config.ConfigMap, lock *sync.Mutex) error {
	awsAccount := strconv.Itoa(configMap.GetInt(AwsAccountId))

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
	awsAccount := strconv.Itoa(configMap.GetInt(AwsAccountId))
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
