package aws

import (
	"context"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/data_source"
	"github.com/stretchr/testify/assert"

	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupMockImportEnvironment(t *testing.T) (*mockDataAccessRepository, *AccessSyncer) {
	repoMock := newMockDataAccessRepository(t)

	syncer := &AccessSyncer{
		repo:            repoMock,
		managedPolicies: nil,
	}

	managedPolicies, err := getObjects[model.PolicyEntity]("testdata/aws/test_managed_policies.json")
	require.Nil(t, err)
	roles, err := getObjects[model.RoleEntity]("testdata/aws/test_roles.json")
	require.Nil(t, err)
	groups, err := getObjects[model.GroupEntity]("testdata/aws/test_groups.json")
	require.Nil(t, err)
	users, err := getObjects[model.UserEntity]("testdata/aws/test_users.json")
	require.Nil(t, err)
	roleInlinePolicies, err := getObjects[model.PolicyEntity]("testdata/aws/test_role_inline_policies.json")
	require.Nil(t, err)
	groupInlinePolicies, err := getObjects[model.PolicyEntity]("testdata/aws/test_group_inline_policies.json")
	require.Nil(t, err)
	userInlinePolicies, err := getObjects[model.PolicyEntity]("testdata/aws/test_user_inline_policies.json")
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

	roleInlineMap := make(map[string][]model.PolicyEntity)
	for _, rip := range roleInlinePolicies {
		for _, rb := range rip.RoleBindings {
			roleInlineMap[rb.ResourceName] = append(roleInlineMap[rb.ResourceName], rip)
		}
	}

	userInlineMap := make(map[string][]model.PolicyEntity)
	for _, uip := range userInlinePolicies {
		for _, ub := range uip.RoleBindings {
			userInlineMap[ub.ResourceName] = append(userInlineMap[ub.ResourceName], uip)
		}
	}

	groupInlineMap := make(map[string][]model.PolicyEntity)
	for _, gip := range groupInlinePolicies {
		for _, gb := range gip.RoleBindings {
			groupInlineMap[gb.ResourceName] = append(groupInlineMap[gb.ResourceName], gip)
		}
	}

	repoMock.EXPECT().GetManagedPolicies(mock.Anything).Return(managedPolicies, nil).Once()
	repoMock.EXPECT().GetRoles(mock.Anything).Return(roles, nil).Once()
	repoMock.EXPECT().GetGroups(mock.Anything).Return(groups, nil).Once()
	repoMock.EXPECT().GetUsers(mock.Anything, false).Return(users, nil).Once()
	repoMock.EXPECT().GetInlinePoliciesForEntities(mock.Anything, roleNames, iam.RoleResourceType).Return(roleInlineMap, nil).Once()
	repoMock.EXPECT().GetInlinePoliciesForEntities(mock.Anything, userNames, iam.UserResourceType).Return(userInlineMap, nil).Once()
	repoMock.EXPECT().GetInlinePoliciesForEntities(mock.Anything, groupNames, iam.GroupResourceType).Return(groupInlineMap, nil).Once()
	repoMock.EXPECT().ListAccessPoints(mock.Anything).Return([]model.AwsS3AccessPoint{}, nil).Once()

	return repoMock, syncer
}

func TestMergeWhatItem(t *testing.T) {
	var whatItems []sync_from_target.WhatItem
	whatItems = mergeWhatItem(whatItems, sync_from_target.WhatItem{
		DataObject: &data_source.DataObjectReference{
			FullName: "1.2.3",
			Type:     "t1",
		},
		Permissions: []string{"p1", "p2"},
	})

	whatItems = mergeWhatItem(whatItems, sync_from_target.WhatItem{
		DataObject: &data_source.DataObjectReference{
			FullName: "1.2.3",
			Type:     "t1",
		},
		Permissions: []string{"p2", "p3"},
	})

	whatItems = mergeWhatItem(whatItems, sync_from_target.WhatItem{
		DataObject: &data_source.DataObjectReference{
			FullName: "1.2.4",
			Type:     "t1",
		},
		Permissions: []string{"p1"},
	})

	assert.Equal(t, []sync_from_target.WhatItem{
		{
			DataObject: &data_source.DataObjectReference{
				FullName: "1.2.3",
				Type:     "t1",
			},
			Permissions: []string{"p1", "p2", "p3"},
		},
		{
			DataObject: &data_source.DataObjectReference{
				FullName: "1.2.4",
				Type:     "t1",
			},
			Permissions: []string{"p1"},
		}}, whatItems)
}

func TestTargetToAccessProvider_BasicImport(t *testing.T) {
	configmap := config.ConfigMap{}
	configmap.Parameters = map[string]string{constants.AwsAccountId: "123456"}
	_, syncer := setupMockImportEnvironment(t)
	ctx := context.Background()

	apHandler := mocks.NewAccessProviderHandler(t)

	inputs := []interface{}{}
	for i := 0; i < 22; i++ {
		inputs = append(inputs, mock.Anything)
	}

	apHandler.EXPECT().AddAccessProviders(inputs...).Return(nil).Once()

	//When
	err := syncer.doSyncAccessProvidersFromTarget(ctx, apHandler, &configmap)

	// Then
	require.Nil(t, err)
}
