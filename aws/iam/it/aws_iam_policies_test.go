//go:build integration

package it

import (
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	baseit "github.com/raito-io/cli-plugin-aws-account/aws/it"
	"github.com/stretchr/testify/suite"
)

type IAMPoliciesTestSuite struct {
	baseit.AWSTestSuite
	repo *iam.AwsIamRepository
}

func TestIAMPoliciesTestSuite(t *testing.T) {
	ts := IAMPoliciesTestSuite{}
	repo := iam.NewAwsIamRepository(ts.GetConfig())

	ts.repo = repo
	suite.Run(t, &ts)
}

func (s *IAMPoliciesTestSuite) TestIAMPolicies_FetchTest() {

}
