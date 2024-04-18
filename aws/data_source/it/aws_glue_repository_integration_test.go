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

	err := syncer.SyncDataSource(context.Background(), &dsHandler, &ds2.DataSourceSyncConfig{ConfigMap: config})

	s.Require().NoError(err)
	s.Require().NotEmpty(dsHandler.DataObjects)
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