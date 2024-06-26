package usage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/raito-io/cli/base/data_usage"
	"github.com/raito-io/cli/base/util/config"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils/trie"
)

type ObjectMapper interface {
	MapObject(object string) *data_usage.UsageDataObjectReference
}

type FileUsageObjectMapper struct {
	pathDepth           int
	dataObjectsWithType *trie.Trie[string]
}

func NewFileUsageObjectMapper(pathDepth int, dataObjectsWithType *trie.Trie[string]) FileUsageObjectMapper {
	return FileUsageObjectMapper{pathDepth: pathDepth, dataObjectsWithType: dataObjectsWithType}
}

func (m FileUsageObjectMapper) MapObject(object string) *data_usage.UsageDataObjectReference {
	path := object

	parts := strings.Split(object, "/")
	if len(parts) > m.pathDepth {
		path = strings.Join(parts[:m.pathDepth], "/")
	}

	if doType, found := m.dataObjectsWithType.Get(path); found {
		return &data_usage.UsageDataObjectReference{
			FullName: path,
			Type:     doType,
		}
	}

	return nil
}

type GlueUsageObjectMapper struct {
	dataObjectsWithType *trie.Trie[string]
}

func NewGlueUsageObjectMapper(dataObjectsWithType *trie.Trie[string]) GlueUsageObjectMapper {
	return GlueUsageObjectMapper{dataObjectsWithType: dataObjectsWithType}
}

func (m GlueUsageObjectMapper) MapObject(object string) *data_usage.UsageDataObjectReference {
	commonPrefix, dataObjectType := m.dataObjectsWithType.GetClosest(object)

	if commonPrefix == "" {
		return nil
	}

	return &data_usage.UsageDataObjectReference{
		FullName: commonPrefix,
		Type:     dataObjectType,
	}
}

func ObjectMapperFactory(ctx context.Context, repo dataObjectRepository, configMap *config.ConfigMap) (ObjectMapper, error) {
	s3Enabled := configMap.GetBoolWithDefault(constants.AwsS3Enabled, false)
	glueEnabled := configMap.GetBoolWithDefault(constants.AwsGlueEnabled, false)

	if s3Enabled && glueEnabled {
		return nil, errors.New("both S3 and Glue are enabled")
	} else if !s3Enabled && !glueEnabled {
		return nil, errors.New("neither S3 nor Glue are enabled")
	}

	dataObjectsWithType, err := repo.GetAvailableObjectTypes(ctx, configMap)
	if err != nil {
		return nil, fmt.Errorf("get available object types: %w", err)
	}

	if s3Enabled {
		pathDepth := configMap.GetIntWithDefault(constants.AwsS3MaxFolderDepth, constants.AwsS3MaxFolderDepthDefault)
		return NewFileUsageObjectMapper(pathDepth, dataObjectsWithType), nil
	} else {
		return NewGlueUsageObjectMapper(dataObjectsWithType), nil
	}
}
