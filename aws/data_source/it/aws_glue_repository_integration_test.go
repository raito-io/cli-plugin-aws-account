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

type GlueRepositoryTestSuite struct {
	baseit.AWSTestSuite
	repo *data_source.AwsGlueRepository
}

func TestGlueRepositoryTestSuite(t *testing.T) {
	ts := GlueRepositoryTestSuite{}
	repo := data_source.NewAwsGlueRepository(ts.GetConfig())

	ts.repo = repo
	suite.Run(t, &ts)
}

func (s *GlueRepositoryTestSuite) TestGlueRepository_FetchTest() {
	config := s.GetConfig()
	syncer := data_source.NewDataSourceSyncer()
	dsHandler := DummyDataSourceHandler{}

	config.Parameters[constants.AwsGlueEnabled] = "true"
	config.Parameters[constants.AwsS3Enabled] = "false"
	config.Parameters[constants.AwsRegions] = "eu-central-1,eu-west-1"

	err := syncer.SyncDataSource(context.Background(), &dsHandler, &ds2.DataSourceSyncConfig{ConfigMap: config})

	s.Require().NoError(err)

	account, _ := repo.GetAccountId(context.Background(), config)

	doMap := map[string]string{
		account: "datasource",
		"077954824694:eu-central-1:raito-data-corporate":            "bucket",
		"077954824694:eu-central-1:raito-data-corporate/operations": "glue-table",
		"077954824694:eu-central-1:raito-data-corporate/marketing":  "glue-table",
		"077954824694:eu-central-1:raito-data-corporate/sales":      "glue-table",
		"077954824694:eu-west-1:raito-data-west":                    "bucket",
		"077954824694:eu-west-1:raito-data-west/cars":               "glue-table",
		"077954824694:eu-west-1:raito-data-west/operations":         "glue-table",
	}

	dataObjectmap := make(map[string]string)

	fetchedDOs := []*ds2.DataObject{}

	for _, do := range dsHandler.DataObjects {
		if do.Type != ds2.Column { // We ignore columns for this test
			dataObjectmap[do.FullName] = do.Type
			fetchedDOs = append(fetchedDOs, do)
		}
	}

	s.Require().Lenf(fetchedDOs, len(doMap), "Expected %d data objects, got %d: %+v != %+v", len(doMap), len(fetchedDOs), doMap, dataObjectmap)

	for _, do := range fetchedDOs {
		s.Require().Contains(doMap, do.FullName)
		s.Require().Equal(doMap[do.FullName], do.Type)
	}
}

func (s *GlueRepositoryTestSuite) TestGlueRepository_FetchTest_WithExclusions() {
	config := s.GetConfig()
	syncer := data_source.NewDataSourceSyncer()
	dsHandler := DummyDataSourceHandler{}

	config.Parameters[constants.AwsGlueEnabled] = "true"
	config.Parameters[constants.AwsS3Enabled] = "false"
	config.Parameters[constants.AwsRegions] = "eu-central-1,eu-west-1"
	config.Parameters[constants.AwsGlueExcludeDatabases] = "raito-data-corporate"
	config.Parameters[constants.AwsGlueExcludeTables] = "car.*"

	err := syncer.SyncDataSource(context.Background(), &dsHandler, &ds2.DataSourceSyncConfig{ConfigMap: config})

	s.Require().NoError(err)

	account, _ := repo.GetAccountId(context.Background(), config)

	doMap := map[string]string{
		account: "datasource",
		// raito-data-corporate database in eu-central-1 is excluded
		"077954824694:eu-west-1:raito-data-west": "bucket",
		// cars table in raito-data-west database in eu-west-1 is excluded
		"077954824694:eu-west-1:raito-data-west/operations": "glue-table",
	}

	dataObjectmap := make(map[string]string)

	fetchedDOs := []*ds2.DataObject{}

	for _, do := range dsHandler.DataObjects {
		if do.Type != ds2.Column { // We ignore columns for this test
			dataObjectmap[do.FullName] = do.Type
			fetchedDOs = append(fetchedDOs, do)
		}
	}

	s.Require().Lenf(fetchedDOs, len(doMap), "Expected %d data objects, got %d: %+v != %+v", len(doMap), len(fetchedDOs), doMap, dataObjectmap)

	for _, do := range fetchedDOs {
		s.Require().Contains(doMap, do.FullName)
		s.Require().Equal(doMap[do.FullName], do.Type)
	}
}

type DummyDataSourceHandler struct {
	DataObjects []*ds2.DataObject
}

func (dsh *DummyDataSourceHandler) AddDataObjects(dataObjects ...*ds2.DataObject) error {
	dsh.DataObjects = append(dsh.DataObjects, dataObjects...)
	return nil
}

func (dsh *DummyDataSourceHandler) SetDataSourceName(name string) {}

func (dsh *DummyDataSourceHandler) SetDataSourceFullname(name string) {}

func (dsh *DummyDataSourceHandler) SetDataSourceDescription(desc string) {}
