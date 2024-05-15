//go:build integration

package it

import (
	"context"
	"strings"
	"testing"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
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
	config := ts.GetConfig()
	repo := iam.NewAwsIamRepository(config)

	ts.repo = repo
	suite.Run(t, &ts)
}

func (s *IAMPoliciesTestSuite) TestIAMPolicies_GetManagedPolicies() {
	s.repo.ClearManagedPoliciesCache()

	s.repo.GetConfig().Parameters[constants.AwsAccessSkipAWSManagedPolicies] = "false"
	s.repo.GetConfig().Parameters[constants.AwsAccessManagedPolicyExcludes] = "Amazon.+,AWS.+"
	policies, err := s.repo.GetManagedPolicies(context.Background())
	s.Assert().NoError(err)
	s.Assert().NotEmpty(policies)

	marketingPolicyFound := false

	for _, policy := range policies {
		s.Assert().NotEmpty(policy.ARN)
		s.Assert().NotEmpty(policy.Name)

		if policy.Name == "marketing_policy" {
			marketingPolicyFound = true
			s.Assert().Len(policy.PolicyParsed.Statements, 1)
			s.Assert().Equal("Allow", policy.PolicyParsed.Statements[0].Effect)
			s.Assert().ElementsMatch([]string{"s3:GetObject", "s3:PutObject"}, policy.PolicyParsed.Statements[0].Action)
			s.Assert().Len(policy.PolicyParsed.Statements[0].Resource, 1)
			s.Assert().True(strings.HasSuffix(policy.PolicyParsed.Statements[0].Resource[0], "/marketing/*"))
		}
	}

	s.Assert().True(marketingPolicyFound)

	s.repo.ClearManagedPoliciesCache()
	s.repo.GetConfig().Parameters[constants.AwsAccessSkipAWSManagedPolicies] = "true"
	nonAWSManagedPolicies, err := s.repo.GetManagedPolicies(context.Background())
	s.Assert().NoError(err)
	s.Assert().NotEmpty(nonAWSManagedPolicies)
	s.Assert().True(len(policies) > len(nonAWSManagedPolicies))

	marketingPolicyFound = false

	for _, policy := range policies {
		if policy.Name == "marketing_policy" {
			marketingPolicyFound = true
		}
	}

	s.Assert().True(marketingPolicyFound)
}

func (s *IAMPoliciesTestSuite) TestIAMPolicies_CreateManagedPolicy() {
	policyName := "INT_TestPolicy1"
	p, err := s.repo.CreateManagedPolicy(context.Background(), policyName, []*awspolicy.Statement{
		{
			Effect:   "Allow",
			Action:   []string{"s3:GetObject"},
			Resource: []string{"arn:aws:s3:::raito-data-corporate/*"},
		},
	})

	s.Assert().NoError(err)
	s.Assert().NotNil(p)
	s.Assert().Equal(policyName, *p.PolicyName)

	err = s.repo.AttachUserToManagedPolicy(context.Background(), *p.Arn, []string{"m_carissa"})
	s.Assert().NoError(err)

	err = s.repo.AttachGroupToManagedPolicy(context.Background(), *p.Arn, []string{"Sales"})
	s.Assert().NoError(err)

	err = s.repo.AttachRoleToManagedPolicy(context.Background(), *p.Arn, []string{"MarketingRole"})
	s.Assert().NoError(err)

	s.repo.ClearManagedPoliciesCache()
	s.repo.GetConfig().Parameters[constants.AwsAccessSkipAWSManagedPolicies] = "true"
	policies, err := s.repo.GetManagedPolicies(context.Background())

	policyFound := false

	for _, policy := range policies {
		if policy.Name == policyName {
			s.Assert().Len(policy.GroupBindings, 1)
			s.Assert().Len(policy.UserBindings, 1)
			s.Assert().Len(policy.RoleBindings, 1)
			s.Assert().Len(policy.PolicyParsed.Statements, 1)
			s.Assert().Equal(policy.PolicyParsed.Statements[0].Effect, "Allow")
			s.Assert().ElementsMatch(policy.PolicyParsed.Statements[0].Action, []string{"s3:GetObject"})
			s.Assert().ElementsMatch(policy.PolicyParsed.Statements[0].Resource, []string{"arn:aws:s3:::raito-data-corporate/*"})

			policyFound = true
		}
	}

	s.Assert().True(policyFound)

	err = s.repo.DeleteManagedPolicy(context.Background(), policyName, false)
	s.Assert().NoError(err)
}

func (s *IAMPoliciesTestSuite) TestIAMPolicies_UpdateManagedPolicy() {
	policyName := "INT_UpdateManagedPolicy1"
	p, err := s.repo.CreateManagedPolicy(context.Background(), policyName, []*awspolicy.Statement{
		{
			Effect:   "Allow",
			Action:   []string{"s3:GetObject"},
			Resource: []string{"arn:aws:s3:::raito-data-corporate/sub-path1/*"},
		},
	})

	s.Assert().NoError(err)
	s.Assert().NotNil(p)
	s.Assert().Equal(policyName, *p.PolicyName)

	s.repo.UpdateManagedPolicy(context.Background(), policyName, false, []*awspolicy.Statement{
		{
			Effect:   "Allow",
			Action:   []string{"s3:PutObject", "s3:GetObject"},
			Resource: []string{"arn:aws:s3:::raito-data-corporate/sub-path2/*"},
		},
	})

	s.repo.ClearManagedPoliciesCache()
	s.repo.GetConfig().Parameters[constants.AwsAccessSkipAWSManagedPolicies] = "true"
	policies, err := s.repo.GetManagedPolicies(context.Background())

	policyFound := false

	for _, policy := range policies {
		if policy.Name == policyName {
			s.Assert().Len(policy.GroupBindings, 0)
			s.Assert().Len(policy.UserBindings, 0)
			s.Assert().Len(policy.RoleBindings, 0)
			s.Assert().Len(policy.PolicyParsed.Statements, 1)
			s.Assert().Equal(policy.PolicyParsed.Statements[0].Effect, "Allow")
			s.Assert().ElementsMatch(policy.PolicyParsed.Statements[0].Action, []string{"s3:PutObject", "s3:GetObject"})
			s.Assert().ElementsMatch(policy.PolicyParsed.Statements[0].Resource, []string{"arn:aws:s3:::raito-data-corporate/sub-path2/*"})
			policyFound = true
		}
	}

	s.Assert().True(policyFound)

	err = s.repo.DeleteManagedPolicy(context.Background(), policyName, false)
	s.Assert().NoError(err)
}

func (s *IAMPoliciesTestSuite) TestIAMPolicies_GetInlinePoliciesForEntities() {
	policies, err := s.repo.GetInlinePoliciesForEntities(context.Background(), []string{"Sales"}, iam.GroupResourceType)
	s.Assert().NoError(err)
	s.Assert().NotEmpty(policies)
	s.Assert().Len(policies, 1)
	s.Assert().Len(policies["Sales"], 1)
	s.Assert().Len(policies["Sales"][0].PolicyParsed.Statements, 1)
	s.Assert().Equal(policies["Sales"][0].PolicyParsed.Statements[0].Effect, "Allow")
	s.Assert().ElementsMatch(policies["Sales"][0].PolicyParsed.Statements[0].Action, []string{"s3:GetObject", "s3:PutObject"})
	s.Assert().True(strings.HasSuffix(policies["Sales"][0].PolicyParsed.Statements[0].Resource[0], "/sales/*"))
}

func (s *IAMPoliciesTestSuite) TestIAMPolicies_ListAccessPoints() {
	accessPoints, err := s.repo.ListAccessPoints(context.Background())
	s.Assert().NoError(err)
	s.Assert().Len(accessPoints, 1)
	s.Assert().Equal("operations", accessPoints[0].Name)
	s.Assert().Equal("raito-data-corporate", accessPoints[0].Bucket)
	s.Assert().Len(accessPoints[0].PolicyParsed.Statements, 1)
	s.Assert().Equal(accessPoints[0].PolicyParsed.Statements[0].Effect, "Allow")
	s.Assert().ElementsMatch([]string{"s3:GetObject"}, accessPoints[0].PolicyParsed.Statements[0].Action)
	s.Assert().True(strings.HasSuffix(accessPoints[0].PolicyParsed.Statements[0].Resource[0], "/object/operations/*"))
	s.Assert().ElementsMatch([]string{"arn:aws:iam::077954824694:user/m_carissa", "arn:aws:iam::077954824694:role/MarketingRole"}, accessPoints[0].PolicyParsed.Statements[0].Principal["AWS"])

	who, what, incomplete := iam.CreateWhoAndWhatFromAccessPointPolicy(accessPoints[0].PolicyParsed, accessPoints[0].Bucket, accessPoints[0].Name, s.GetConfig())
	s.Assert().False(incomplete)

	s.Assert().Len(who.Groups, 0)
	s.Assert().Len(who.AccessProviders, 1)
	s.Assert().Equal(who.AccessProviders[0], "role:MarketingRole")
	s.Assert().Len(who.Users, 1)
	s.Assert().Equal(who.Users[0], "m_carissa")

	s.Assert().Len(what, 1)
	s.Assert().Equal("raito-data-corporate/operations", what[0].DataObject.FullName)
	s.Assert().ElementsMatch([]string{"s3:GetObject"}, what[0].Permissions)
}
