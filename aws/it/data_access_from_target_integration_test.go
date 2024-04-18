//go:build integration

package it

import (
	"context"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/stretchr/testify/suite"
)

type DataAccessFromTargetTestSuite struct {
	AWSTestSuite
	accessSyncer *aws.AccessSyncer
}

func TestDataAccessFromTargetTestSuiteTestSuite(t *testing.T) {
	ts := DataAccessFromTargetTestSuite{}

	ts.accessSyncer = aws.NewDataAccessSyncerFromConfig(ts.GetConfig())

	suite.Run(t, &ts)
}

func (s *DataAccessFromTargetTestSuite) TestAccessSyncer__FetchTest() {
	aps, err := s.accessSyncer.FetchS3AccessPointAccessProviders(context.Background(), s.GetConfig(), nil)
	s.NoError(err)
	s.Len(aps, 1)
	s.Equal("operations", aps[0].ApInput.Name)
	s.Equal("operations", aps[0].ApInput.ActualName)
	s.Equal(string(model.AccessPoint), *aps[0].ApInput.Type)
	s.Equal(sync_from_target.Grant, aps[0].ApInput.Action)
	s.Len(aps[0].ApInput.Who.Users, 1)
	s.Equal(aps[0].ApInput.Who.Users[0], "m_carissa")
	s.Len(aps[0].ApInput.Who.AccessProviders, 1)
	s.Equal(aps[0].ApInput.Who.AccessProviders[0], constants.RoleTypePrefix+"SalesRole")
	s.Equal(aps[0].ApInput.What[0].DataObject.FullName, "raito-corporate-data/operations")
	s.Equal(aps[0].ApInput.What[0].Permissions[0], "s3:GetObject")

}
