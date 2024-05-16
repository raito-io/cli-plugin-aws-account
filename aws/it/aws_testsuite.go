//go:build integration

package it

import (
	"os"
	"sync"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli/base/util/config"
	"github.com/stretchr/testify/suite"
)

var (
	awsAccountId string
	awsProfile   string
	awsRegion    string
	lock         = &sync.Mutex{}
)

func getConfig() *config.ConfigMap {
	lock.Lock()
	defer lock.Unlock()

	if awsAccountId == "" {
		awsAccountId = os.Getenv("AWS_ACCOUNT")
		awsProfile = os.Getenv("AWS_PROFILE")
		awsRegion = os.Getenv("AWS_REGION")
	}

	return &config.ConfigMap{
		Parameters: map[string]string{
			constants.AwsProfile: awsProfile,
			constants.AwsRegions: awsRegion,
		},
	}
}

type AWSTestSuite struct {
	suite.Suite
}

func (s *AWSTestSuite) GetConfig() *config.ConfigMap {
	return getConfig()
}
