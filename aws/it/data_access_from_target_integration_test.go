//go:build integration

package it

import (
	"context"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws"
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
}
