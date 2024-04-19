//go:build integration

package it

import (
	"context"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	baseit "github.com/raito-io/cli-plugin-aws-account/aws/it"
	"github.com/raito-io/golang-set/set"
	"github.com/stretchr/testify/suite"
)

type IAMIdentitiesTestSuite struct {
	baseit.AWSTestSuite
	repo *iam.AwsIamRepository
}

func TestIAMIdentitiesTestSuite(t *testing.T) {
	ts := IAMIdentitiesTestSuite{}
	repo := iam.NewAwsIamRepository(ts.GetConfig())

	ts.repo = repo
	suite.Run(t, &ts)
}

func (s *IAMIdentitiesTestSuite) TestIAMIdentities_FetchUsers() {
	users, err := s.repo.GetUsers(context.Background(), true)

	s.Require().NoError(err)
	s.Require().NotNil(users)

	knownUsers := map[string]string{
		"m_carissa": "",
		"d_hayden":  "",
		"clirunner": "",
	}

	s.Require().Len(users, len(knownUsers))

	for _, user := range users {
		s.Require().Contains(knownUsers, user.Name)
		s.Require().NotEmpty(user.ExternalId)
	}
}

func (s *IAMIdentitiesTestSuite) TestIAMIdentities_FetchGroups() {
	users, err := s.repo.GetUsers(context.Background(), true)
	userMap := make(map[string]string)
	for _, user := range users {
		userMap[user.ExternalId] = user.Name
	}

	groups, err := s.repo.GetGroups(context.Background())

	s.Require().NoError(err)
	s.Require().NotNil(groups)

	knownGroups := map[string]set.Set[string]{
		"Sales":     set.NewSet("d_hayden"),
		"Marketing": set.NewSet("m_carissa"),
	}

	s.Require().Len(groups, len(knownGroups))

	for _, group := range groups {
		s.Require().Contains(knownGroups, group.Name)
		s.Require().NotEmpty(group.ExternalId)
		s.Require().Len(group.Members, len(knownGroups[group.Name]))
		for _, member := range group.Members {
			s.Require().Contains(userMap, member)
			s.Require().Contains(knownGroups[group.Name], userMap[member])
		}
	}
}

func (s *IAMIdentitiesTestSuite) TestIAMIdentities_FetchRoles() {
	roles, err := s.repo.GetRoles(context.Background())

	s.Require().NoError(err)
	s.Require().NotNil(roles)

	marketingFound := false
	salesFound := false

	for _, role := range roles {
		s.Require().NotEmpty(role.Name)
		s.Require().NotEmpty(role.ARN)

		if role.Name == "MarketingRole" {
			marketingFound = true
		} else if role.Name == "SalesRole" {
			salesFound = true
		}
	}

	s.Require().True(marketingFound)
	s.Require().True(salesFound)
}
