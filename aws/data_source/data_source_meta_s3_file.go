package data_source

import (
	ds "github.com/raito-io/cli/base/data_source"

	"github.com/raito-io/cli-plugin-aws-account/aws/data_source/permissions"
)

type S3FileMetadataProvider struct {
}

func (p S3FileMetadataProvider) DataObjectTypes() []*ds.DataObjectType {
	return []*ds.DataObjectType{
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
			Children:    []string{ds.Folder, ds.File},
		},
		{
			Name:        ds.Folder,
			Type:        ds.Folder,
			Label:       "S3 Folder",
			Permissions: permissions.S3ObjectPermissions,
			Children:    []string{ds.Folder, ds.File},
		},
		{
			Name:        ds.File,
			Type:        ds.File,
			Label:       "S3 File",
			Permissions: permissions.S3ObjectPermissions,
			Children:    []string{},
		},
	}
}

func (p S3FileMetadataProvider) UsageMetaInfo() *ds.UsageMetaInput {
	return &ds.UsageMetaInput{
		DefaultLevel: ds.File,
		Levels: []*ds.UsageMetaInputDetail{
			{
				Name:            ds.File,
				DataObjectTypes: []string{ds.File, ds.Folder},
			},
		},
	}
}

func (p S3FileMetadataProvider) AccessProviderTypes() []*ds.AccessProviderType {
	return nil
}
