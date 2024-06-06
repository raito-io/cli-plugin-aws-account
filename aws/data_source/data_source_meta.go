package data_source

import (
	"sync"

	ds "github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/util/config"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
)

var metaData *ds.MetaData
var dataObjects map[string]*ds.DataObjectType
var mu sync.Mutex

type MetadataProvider interface {
	DataObjectTypes() []*ds.DataObjectType
	UsageMetaInfo() *ds.UsageMetaInput
	AccessProviderTypes() []*ds.AccessProviderType
}

func GetDataObjectType(name string, cfg *config.ConfigMap) *ds.DataObjectType {
	GetS3MetaData(cfg)

	return dataObjects[name]
}

func GetS3MetaData(cfg *config.ConfigMap) *ds.MetaData {
	mu.Lock()
	defer mu.Unlock()

	if metaData == nil {
		metaDataProvider := getMetadataProvider(cfg)

		dataObjectTypes := metaDataProvider.DataObjectTypes()
		usageMetadataInfo := metaDataProvider.UsageMetaInfo()

		accessProviderTypes := []*ds.AccessProviderType{
			{
				Type:                          string(model.Role),
				Label:                         "AWS Role",
				Icon:                          "",
				IsNamedEntity:                 true,
				CanBeCreated:                  true,
				CanBeAssumed:                  true,
				CanAssumeMultiple:             false,
				AllowedWhoAccessProviderTypes: []string{string(model.Role)},
			},
			{
				Type:                          string(model.Policy),
				Label:                         "AWS Policy",
				Icon:                          "",
				IsNamedEntity:                 true,
				CanBeCreated:                  true,
				CanBeAssumed:                  false,
				CanAssumeMultiple:             false,
				AllowedWhoAccessProviderTypes: []string{string(model.Policy), string(model.Role)},
			},
			{
				Type:                          string(model.AccessPoint),
				Label:                         "AWS S3 Access Point",
				Icon:                          "",
				IsNamedEntity:                 true,
				CanBeCreated:                  true,
				CanBeAssumed:                  false,
				CanAssumeMultiple:             false,
				AllowedWhoAccessProviderTypes: []string{string(model.AccessPoint), string(model.Role)},
			},
		}
		accessProviderTypes = append(accessProviderTypes, metaDataProvider.AccessProviderTypes()...)

		if cfg.GetStringWithDefault(constants.AwsOrganizationProfile, "") != "" {
			for _, apt := range accessProviderTypes {
				apt.AllowedWhoAccessProviderTypes = append(apt.AllowedWhoAccessProviderTypes, string(model.SSORole))
			}

			accessProviderTypes = append(accessProviderTypes, &ds.AccessProviderType{
				Type:                          string(model.SSORole),
				Label:                         "AWS SSO Role",
				Icon:                          "",
				IsNamedEntity:                 true,
				CanBeCreated:                  false,
				CanBeAssumed:                  true,
				CanAssumeMultiple:             false,
				AllowedWhoAccessProviderTypes: []string{string(model.SSORole)},
				IdentityStoreTypeForWho:       "aws-organization",
			})
		}

		metaData = &ds.MetaData{
			Type:                  "aws-account",
			SupportedFeatures:     []string{""},
			SupportsApInheritance: true,
			DataObjectTypes:       dataObjectTypes,
			UsageMetaInfo:         usageMetadataInfo,
			AccessProviderTypes:   accessProviderTypes,
		}

		dataObjects = make(map[string]*ds.DataObjectType)

		for _, dot := range metaData.DataObjectTypes {
			dataObjects[dot.Name] = dot
		}
	}

	return metaData
}

func getMetadataProvider(cfg *config.ConfigMap) MetadataProvider {
	if cfg.GetBoolWithDefault(constants.AwsGlueEnabled, false) {
		return S3GlueMetadataProvider{}
	}

	return S3FileMetadataProvider{}
}

func ClearMetadata() {
	mu.Lock()
	defer mu.Unlock()

	metaData = nil
	dataObjects = nil
}
