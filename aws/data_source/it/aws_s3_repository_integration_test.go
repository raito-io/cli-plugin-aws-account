//go:build integration

package it

import (
	"context"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	baseit "github.com/raito-io/cli-plugin-aws-account/aws/it"
	ds2 "github.com/raito-io/cli/base/data_source"
	"github.com/stretchr/testify/suite"
)

type S3RepositoryTestSuite struct {
	baseit.AWSTestSuite
	repo *data_source.AwsGlueRepository
}

func TestS3RepositoryTestSuite(t *testing.T) {
	ts := S3RepositoryTestSuite{}
	repo := data_source.NewAwsGlueRepository(ts.GetConfig())

	ts.repo = repo
	suite.Run(t, &ts)
}

func (s *S3RepositoryTestSuite) TestS3Repository_SyncDataSource() {
	config := s.GetConfig()
	syncer := data_source.NewDataSourceSyncer()
	dsHandler := DummyDataSourceHandler{}

	config.Parameters[constants.AwsGlueEnabled] = "false"
	config.Parameters[constants.AwsS3Enabled] = "true"
	config.Parameters[constants.AwsRegion] = "eu-central-1"
	config.Parameters[constants.AwsS3IncludeBuckets] = "raito-corporate-data"

	err := syncer.SyncDataSource(context.Background(), &dsHandler, &ds2.DataSourceSyncConfig{ConfigMap: config})

	s.Require().NoError(err)
	doMap := map[string]string{
		config.Parameters[constants.AwsAccountId]:                               "datasource",
		"raito-corporate-data":                                                  "bucket",
		"raito-corporate-data/operations":                                       "folder",
		"raito-corporate-data/operations/weather":                               "folder",
		"raito-corporate-data/marketing":                                        "folder",
		"raito-corporate-data/marketing/passengers":                             "folder",
		"raito-corporate-data/sales":                                            "folder",
		"raito-corporate-data/sales/housing":                                    "folder",
		"raito-corporate-data/sales/housing/prices":                             "folder",
		"raito-corporate-data/marketing/passengers/passengers.parquet":          "file",
		"raito-corporate-data/operations/weather/weather.parquet":               "file",
		"raito-corporate-data/sales/housing/prices/housing-prices-2023.parquet": "file",
	}

	s.Require().Len(dsHandler.DataObjects, len(doMap))

	for _, do := range dsHandler.DataObjects {
		s.Require().Contains(doMap, do.FullName)
		s.Require().Equal(doMap[do.FullName], do.Type)
	}
}
