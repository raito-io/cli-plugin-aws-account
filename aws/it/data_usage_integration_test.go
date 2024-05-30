//go:build integration

package it

import (
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws"
	"github.com/stretchr/testify/suite"
)

type DataUsageTestSuite struct {
	AWSTestSuite
	usageSyncer *aws.DataUsageSyncer
}

func TestDataUsageTestSuiteTestSuiteTestSuite(t *testing.T) {
	ts := DataUsageTestSuite{}

	ts.usageSyncer = aws.NewDataUsageSyncer()

	suite.Run(t, &ts)
}

/*func (s *DataUsageTestSuite) TestUsageSyncer_TestSync() {
	handler := mocks.NewSimpleDataUsageStatementHandler(s.T())
	config := s.GetConfig()
	config.Parameters[constants.AwsS3CloudTrailBucket] = "raito-cloudtrail"
	config.Parameters[constants.AwsGlueEnabled] = "true"
	s.usageSyncer.SyncDataUsage(context.Background(), handler, config)
}*/
