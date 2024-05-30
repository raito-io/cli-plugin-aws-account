//go:build integration

package it

import (
	"os"
	"sync"

	"github.com/raito-io/cli/base/util/config"
	"github.com/stretchr/testify/suite"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
)

var (
	awsAccountId                             string
	awsProfile                               string
	awsRegion                                string
	awsOrganizationProfile                   string
	awsOrganizationRegion                    string
	awsOrganizationIdentityCenterInstanceArn string
	awsOrganizationIdentityStore             string
	lock                                     = &sync.Mutex{}
)

func getConfig() *config.ConfigMap {
	lock.Lock()
	defer lock.Unlock()

	if awsAccountId == "" {
		awsAccountId = os.Getenv("AWS_ACCOUNT")
		awsProfile = os.Getenv("AWS_PROFILE")
		awsRegion = os.Getenv("AWS_REGION")
		awsOrganizationProfile = os.Getenv("AWS_ORGANIZATION_PROFILE")
		awsOrganizationRegion = os.Getenv("AWS_ORGANIZATION_REGION")
		awsOrganizationIdentityCenterInstanceArn = os.Getenv("AWS_ORGANIZATION_IDENTITY_CENTER_INSTANCE_ARN")
		awsOrganizationIdentityStore = os.Getenv("AWS_ORGANIZATION_IDENTITY_STORE")
	}

	return &config.ConfigMap{
		Parameters: map[string]string{
			constants.AwsProfile:                               awsProfile,
			constants.AwsRegions:                               awsRegion,
			constants.AwsOrganizationProfile:                   awsOrganizationProfile,
			constants.AwsOrganizationRegion:                    awsOrganizationRegion,
			constants.AwsOrganizationIdentityCenterInstanceArn: awsOrganizationIdentityCenterInstanceArn,
			constants.AwsOrganizationIdentityStore:             awsOrganizationIdentityStore,
		},
	}
}

type AWSTestSuite struct {
	suite.Suite
}

func (s *AWSTestSuite) GetConfig() *config.ConfigMap {
	return getConfig()
}
