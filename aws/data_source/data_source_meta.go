package data_source

import (
	"sync"

	ds "github.com/raito-io/cli/base/data_source"

	"github.com/raito-io/cli-plugin-aws-account/aws/data_source/permissions"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
)

var metaData *ds.MetaData
var dataObjects map[string]*ds.DataObjectType
var mu sync.Mutex

func GetDataObjectType(name string) *ds.DataObjectType {
	GetS3MetaData()

	return dataObjects[name]
}

func GetS3MetaData() *ds.MetaData {
	mu.Lock()
	defer mu.Unlock()

	if metaData == nil {
		metaData = &ds.MetaData{
			Type:                  "aws-account",
			SupportedFeatures:     []string{""},
			SupportsApInheritance: true,
			DataObjectTypes: []*ds.DataObjectType{
				{
					Name:        ds.Datasource,
					Type:        ds.Datasource,
					Permissions: permissions.AllS3Permissions,
					Children:    []string{ds.Bucket},
				},
				{
					Name:        ds.Bucket,
					Type:        ds.Bucket,
					Label:       "S3 Bucket",
					Permissions: permissions.AllS3Permissions,
					Children:    []string{ds.Folder, ds.File, model.GlueTable},
				},
				{
					Name:        ds.Folder,
					Type:        ds.Folder,
					Label:       "S3 Folder",
					Permissions: permissions.S3ObjectPermissions,
					Children:    []string{ds.Folder, ds.File, model.GlueTable},
				},
				{
					Name:        ds.File,
					Type:        ds.File,
					Label:       "S3 File",
					Permissions: permissions.S3ObjectPermissions,
					Children:    []string{},
				},
				{
					Name:        model.GlueTable,
					Type:        ds.Table,
					Label:       "Glue Table",
					Permissions: permissions.S3AccessPointPermissions,
					Children:    []string{},
				},
			},
			UsageMetaInfo: &ds.UsageMetaInput{
				DefaultLevel: ds.File,
				Levels: []*ds.UsageMetaInputDetail{
					{
						Name:            ds.File,
						DataObjectTypes: []string{ds.File},
					},
				},
			},
			AccessProviderTypes: []*ds.AccessProviderType{
				{
					Type:                          string(model.Role),
					Label:                         "AWS Role",
					Icon:                          "",
					IsNamedEntity:                 true,
					CanBeCreated:                  true,
					CanBeAssumed:                  true,
					CanAssumeMultiple:             false,
					AllowedWhoAccessProviderTypes: []string{string(model.Role), string(model.SSORole)},
				},
				{
					Type:                          string(model.SSORole),
					Label:                         "AWS SSO Role",
					Icon:                          "",
					IsNamedEntity:                 true,
					CanBeCreated:                  false,
					CanBeAssumed:                  true,
					CanAssumeMultiple:             false,
					AllowedWhoAccessProviderTypes: []string{string(model.SSORole)},
					IdentityStoreTypeForWho:       "aws-organization",
				},
				{
					Type:                          string(model.Policy),
					Label:                         "AWS Policy",
					Icon:                          "",
					IsNamedEntity:                 true,
					CanBeCreated:                  true,
					CanBeAssumed:                  false,
					CanAssumeMultiple:             false,
					AllowedWhoAccessProviderTypes: []string{string(model.Policy), string(model.Role), string(model.SSORole)},
				},
				{
					Type:                          string(model.AccessPoint),
					Label:                         "AWS S3 Access Point",
					Icon:                          "",
					IsNamedEntity:                 true,
					CanBeCreated:                  true,
					CanBeAssumed:                  false,
					CanAssumeMultiple:             false,
					AllowedWhoAccessProviderTypes: []string{string(model.AccessPoint), string(model.Role), string(model.SSORole)},
				},
			},
		}

		dataObjects = make(map[string]*ds.DataObjectType)

		for _, dot := range metaData.DataObjectTypes {
			dataObjects[dot.Name] = dot
		}
	}

	return metaData
}
