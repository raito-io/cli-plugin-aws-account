package data_source

import (
	ds "github.com/raito-io/cli/base/data_source"

	"github.com/raito-io/cli-plugin-aws-account/aws/data_source/permissions"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
)

type S3GlueMetadataProvider struct {
}

func (p S3GlueMetadataProvider) DataObjectTypes() []*ds.DataObjectType {
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
			Children:    []string{ds.Folder, model.GlueTableType},
		},
		{
			Name:        ds.Folder,
			Type:        ds.Folder,
			Label:       "S3 Folder",
			Permissions: permissions.S3ObjectPermissions,
			Children:    []string{ds.Folder, model.GlueTableType},
		},
		{
			Name:        model.GlueTableType,
			Type:        ds.Table,
			Label:       "Glue Table",
			Permissions: permissions.S3AccessPointPermissions,
			Children:    []string{ds.Column},
		},
		{
			Name:     ds.Column,
			Type:     ds.Column,
			Label:    "Column",
			Children: []string{},
		},
	}
}

func (p S3GlueMetadataProvider) UsageMetaInfo() *ds.UsageMetaInput {
	return &ds.UsageMetaInput{
		DefaultLevel: model.GlueTableType,
		Levels: []*ds.UsageMetaInputDetail{
			{
				Name:            model.GlueTableType,
				DataObjectTypes: []string{model.GlueTableType, ds.Folder},
			},
		},
	}
}

func (p S3GlueMetadataProvider) AccessProviderTypes() []*ds.AccessProviderType {
	return nil
}
