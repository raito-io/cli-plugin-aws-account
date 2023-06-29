package aws

import (
	"context"
	"testing"

	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupMockImportEnvironment(t *testing.T, configMap *config.ConfigMap) (*mockDataAccessRepository, *AccessSyncer) {
	repoMock := newMockDataAccessRepository(t)

	syncer := &AccessSyncer{
		repoProvider: func() dataAccessRepository {
			return repoMock
		},
		managedPolicies: nil,
		inlinePolicies:  nil,
	}

	managedPolicies, err := getObjects[PolicyEntity]("testdata/aws/test_managed_policies.json")
	require.Nil(t, err)
	roles, err := getObjects[RoleEntity]("testdata/aws/test_roles.json")
	require.Nil(t, err)
	groups, err := getObjects[GroupEntity]("testdata/aws/test_groups.json")
	require.Nil(t, err)
	users, err := getObjects[UserEntity]("testdata/aws/test_users.json")
	require.Nil(t, err)
	roleInlinePolicies, err := getObjects[PolicyEntity]("testdata/aws/test_role_inline_policies.json")
	require.Nil(t, err)
	groupInlinePolicies, err := getObjects[PolicyEntity]("testdata/aws/test_group_inline_policies.json")
	require.Nil(t, err)
	userInlinePolicies, err := getObjects[PolicyEntity]("testdata/aws/test_user_inline_policies.json")
	require.Nil(t, err)

	roleNames := []string{}
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	userNames := []string{}
	for _, user := range users {
		userNames = append(userNames, user.Name)
	}

	groupNames := []string{}
	for _, group := range groups {
		groupNames = append(groupNames, group.Name)
	}

	repoMock.EXPECT().GetManagedPolicies(context.TODO(), mock.Anything, true).Return(managedPolicies, nil).Once()
	repoMock.EXPECT().GetRoles(context.TODO(), configMap).Return(roles, nil).Once()
	repoMock.EXPECT().GetGroups(context.TODO(), configMap, false).Return(groups, nil).Once()
	repoMock.EXPECT().GetUsers(context.TODO(), configMap, false).Return(users, nil).Once()
	repoMock.EXPECT().GetInlinePoliciesForEntities(context.TODO(), configMap, roleNames, "role").Return(roleInlinePolicies, nil).Once()
	repoMock.EXPECT().GetInlinePoliciesForEntities(context.TODO(), configMap, userNames, "user").Return(userInlinePolicies, nil).Once()
	repoMock.EXPECT().GetInlinePoliciesForEntities(context.TODO(), configMap, groupNames, "group").Return(groupInlinePolicies, nil).Once()

	return repoMock, syncer
}

func TestTargetToAccessProvider_BasicImport(t *testing.T) {
	configmap := config.ConfigMap{}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}
	_, syncer := setupMockImportEnvironment(t, &configmap)
	ctx := context.Background()

	apHandler := mocks.NewAccessProviderHandler(t)

	inputs := []interface{}{}
	for i := 0; i < 22; i++ {
		inputs = append(inputs, mock.Anything)
	}

	apHandler.EXPECT().AddAccessProviders(inputs...).Return(nil).Once()

	//When
	err := syncer.SyncAccessProvidersFromTarget(ctx, apHandler, &configmap)

	// Then
	require.Nil(t, err)
}
