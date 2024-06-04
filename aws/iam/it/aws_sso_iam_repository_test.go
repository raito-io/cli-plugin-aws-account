//go:build integration

package it

import (
	"context"
	"strings"
	"testing"
	"time"

	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	baseit "github.com/raito-io/cli-plugin-aws-account/aws/it"
	repo2 "github.com/raito-io/cli-plugin-aws-account/aws/repo"
)

type AwsSsoIAMRepositoryTestSuite struct {
	baseit.AWSTestSuite
	repo *iam.AwsSsoIamRepository
}

func TestAwsSsoIAMRepositoryTestSuite(t *testing.T) {
	ts := AwsSsoIAMRepositoryTestSuite{}
	config := ts.GetConfig()

	account, err := repo2.GetAccountId(context.Background(), config)
	require.NoError(t, err)

	ssoRepo, err := iam.NewSsoClient(context.Background(), config, account)
	require.NoError(t, err)

	ts.repo = ssoRepo
	suite.Run(t, &ts)
}

func (s *AwsSsoIAMRepositoryTestSuite) TestSsoIamRepository_SsoRole_CreateDelete() {
	name := "RAITO-TEST_create_sso_role"
	description := "Test Role for integration tests"

	var arn string

	s.T().Run("Create sso role", func(t *testing.T) {
		var err error

		arn, err = s.repo.CreateSsoRole(context.Background(), name, description)

		require.NoError(t, err)
		require.NotEmpty(t, arn)
	})

	s.T().Run("List sso role", func(t *testing.T) {
		roles, err := s.repo.ListSsoRole(context.Background())

		assert.NoError(t, err)
		assert.Contains(t, roles, arn)
	})

	s.T().Run("Update sso role", func(t *testing.T) {
		err := s.repo.UpdateSsoRole(context.Background(), arn, "Updated Role Description")

		assert.NoError(t, err)
	})

	s.T().Run("Delete sso role", func(t *testing.T) {
		err := s.repo.DeleteSsoRole(context.Background(), arn)

		require.NoError(t, err)
	})
}

func (s *AwsSsoIAMRepositoryTestSuite) TestSsoIamRepository_AssignUnassignPermissionSet() {
	name := "RAITO-TEST_assign_unassign_role"
	description := "Test Role for integration tests"

	users, err := s.repo.GetUsers(context.Background())

	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), users)

	arn, err := s.repo.CreateSsoRole(context.Background(), name, description)

	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), arn)

	s.T().Cleanup(func() {
		s.T().Logf("Cleaning up %s", arn)

		err2 := s.repo.DeleteSsoRole(context.Background(), arn)
		if err2 != nil {
			s.T().Logf("Failed to cleanup %s: %s", arn, err2)
		}

	})

	var user string

	usersMap := users.ReverseMap()
	for mail, userId := range usersMap {
		if strings.HasSuffix(mail, "@raito.io") {
			user = userId
			break
		}
	}

	s.T().Run("Assign permission set", func(t *testing.T) {
		err = s.repo.AssignPermissionSet(context.Background(), arn, ssoTypes.PrincipalTypeUser, user)
		require.NoError(s.T(), err)

		err = s.repo.ProvisionPermissionSetAndWait(context.Background(), arn)
		assert.NoError(t, err)
	})

	time.Sleep(time.Second * 3)

	s.T().Run("List permission set assignment", func(t *testing.T) {
		assignments, err2 := s.repo.ListPermissionSetAssignment(context.Background(), arn)
		require.NoError(s.T(), err2)
		require.Len(s.T(), assignments, 1)

		assert.Equal(t, arn, *assignments[0].PermissionSetArn)
		assert.Equal(t, ssoTypes.PrincipalTypeUser, assignments[0].PrincipalType)
		assert.Equal(t, user, *assignments[0].PrincipalId)
	})

	s.T().Run("Unassign permission set", func(t *testing.T) {
		err = s.repo.UnassignPermissionSet(context.Background(), arn, ssoTypes.PrincipalTypeUser, user)
		require.NoError(s.T(), err)

		err = s.repo.ProvisionPermissionSetAndWait(context.Background(), arn)
		assert.NoError(t, err)
	})
}
