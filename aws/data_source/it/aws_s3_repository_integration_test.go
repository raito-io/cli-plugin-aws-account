//go:build integration

package it

import (
	"context"
	"testing"

	ds2 "github.com/raito-io/cli/base/data_source"
	"github.com/stretchr/testify/suite"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	baseit "github.com/raito-io/cli-plugin-aws-account/aws/it"
	"github.com/raito-io/cli-plugin-aws-account/aws/repo"
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
	config.Parameters[constants.AwsRegions] = "eu-central-1,eu-west-1"
	config.Parameters[constants.AwsS3ExcludeBuckets] = "raito-cloudtrail,cdk-*"

	err := syncer.SyncDataSource(context.Background(), &dsHandler, &ds2.DataSourceSyncConfig{ConfigMap: config})

	account, _ := repo.GetAccountId(context.Background(), config)

	s.Require().NoError(err)
	doMap := map[string]string{
		account: "datasource",
		"077954824694:eu-central-1:raito-data-corporate":                                                  "bucket",
		"077954824694:eu-central-1:raito-data-corporate/operations":                                       "folder",
		"077954824694:eu-central-1:raito-data-corporate/operations/weather":                               "folder",
		"077954824694:eu-central-1:raito-data-corporate/marketing":                                        "folder",
		"077954824694:eu-central-1:raito-data-corporate/marketing/passengers":                             "folder",
		"077954824694:eu-central-1:raito-data-corporate/sales":                                            "folder",
		"077954824694:eu-central-1:raito-data-corporate/sales/housing":                                    "folder",
		"077954824694:eu-central-1:raito-data-corporate/sales/housing/prices":                             "folder",
		"077954824694:eu-central-1:raito-data-corporate/marketing/passengers/passengers.parquet":          "file",
		"077954824694:eu-central-1:raito-data-corporate/operations/weather/weather.parquet":               "file",
		"077954824694:eu-central-1:raito-data-corporate/sales/housing/prices/housing-prices-2023.parquet": "file",
		"077954824694:eu-west-1:raito-data-west":                                                          "bucket",
		"077954824694:eu-west-1:raito-data-west/cars":                                                     "folder",
		"077954824694:eu-west-1:raito-data-west/cars/analysis":                                            "folder",
		"077954824694:eu-west-1:raito-data-west/cars/analysis/cars.parquet":                               "file",
		"077954824694:eu-west-1:raito-data-west/operations":                                               "folder",
		"077954824694:eu-west-1:raito-data-west/operations/weather":                                       "folder",
		"077954824694:eu-west-1:raito-data-west/operations/weather/weather.parquet":                       "file",
	}

	s.Require().Len(dsHandler.DataObjects, len(doMap))

	for _, do := range dsHandler.DataObjects {
		s.Require().Contains(doMap, do.FullName)
		s.Require().Equal(doMap[do.FullName], do.Type)
	}
}
