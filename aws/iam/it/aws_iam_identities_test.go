//go:build integration

package it

import (
	"context"
	"fmt"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	baseit "github.com/raito-io/cli-plugin-aws-account/aws/it"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
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
	s.repo.ClearManagedPoliciesCache()

	users, err := s.repo.GetUsers(context.Background(), true)

	s.Require().NoError(err)
	s.Require().NotNil(users)

	knownUsers := map[string]string{
		"m_carissa": "",
		"d_hayden":  "",
		"clirunner": "",
		"root":      "",
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

	for _, role := range roles {
		s.Require().NotEmpty(role.Name)
		s.Require().NotEmpty(role.ARN)

		if role.Name == "MarketingRole" {
			marketingFound = true
		}
	}

	s.Require().True(marketingFound)
}

func (s *IAMIdentitiesTestSuite) TestIAMIdentities_CreatePolicy() {
	s.repo.ClearRolesCache()
	name := "INT_TestRole1"

	err := s.repo.CreateRole(context.Background(), name, "Some description", []string{"m_carissa"})
	s.Assert().NoError(err)

	defer func() {
		err = s.repo.DeleteRole(context.Background(), name)
		s.Assert().NoError(err)
	}()

	roles, err := s.repo.GetRoles(context.Background())
	s.Assert().NoError(err)
	s.Assert().NotNil(roles)
	found := false
	for _, role := range roles {
		if role.Name == name {
			found = true

			s.checkRole(role, name, []string{"m_carissa"})

			break
		}
	}
	s.Assert().True(found)
}

func (s *IAMIdentitiesTestSuite) TestIAMIdentities_UpdateRole() {
	s.repo.ClearRolesCache()
	name := "INT_UpdateTestRole1"

	err := s.repo.CreateRole(context.Background(), name, "Some description", []string{"m_carissa"})
	s.Assert().NoError(err)

	defer func() {
		err = s.repo.DeleteRole(context.Background(), name)
		s.Assert().NoError(err)
	}()

	err = s.repo.UpdateAssumeEntities(context.Background(), name, []string{"d_hayden"})
	s.Assert().NoError(err)

	roles, err := s.repo.GetRoles(context.Background())
	s.Assert().NoError(err)
	s.Assert().NotNil(roles)
	found := false
	for _, role := range roles {
		fmt.Println(role.Name)
		if role.Name == name {
			found = true

			s.checkRole(role, name, []string{"d_hayden"})

			break
		}
	}
	s.Assert().True(found)
}

func (s *IAMIdentitiesTestSuite) checkRole(role model.RoleEntity, expectedName string, expectedUsers []string) {
	s.Assert().Equal(expectedName, role.Name)

	s.Assert().Len(role.Tags, 1)
	s.Assert().Equal("creator", role.Tags[0].Key)
	s.Assert().Equal("RAITO", role.Tags[0].Value)

	whoItem, incomplete := iam.CreateWhoFromTrustPolicyDocument(role.AssumeRolePolicy, role.Name, "077954824694")
	s.Assert().False(incomplete)
	s.Assert().Len(whoItem.Users, len(expectedUsers))
	s.Assert().ElementsMatch(expectedUsers, whoItem.Users)
}
