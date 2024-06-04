package data_access

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils/bimap"

	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/ptr"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupMockExportEnvironment(t *testing.T, ssoEnabled bool) (*MockdataAccessRepository, *MockdataAccessSsoRepository, *MockdataAccessIamRepository, *AccessSyncer) {
	t.Helper()

	repoMock := NewMockdataAccessRepository(t)

	var ssoRepoMock *MockdataAccessSsoRepository
	if ssoEnabled {
		ssoRepoMock = NewMockdataAccessSsoRepository(t)
	}

	iamRepo := NewMockdataAccessIamRepository(t)

	nameGenerator, err := NewNameGenerator("123456789012")
	require.NoError(t, err)

	syncer := &AccessSyncer{
		repo:          repoMock,
		ssoRepo:       ssoRepoMock,
		iamRepo:       iamRepo,
		nameGenerator: nameGenerator,
	}

	roles, err := getObjects[model.RoleEntity]("../testdata/aws/test_roles.json")
	require.NoError(t, err)
	managedPolicies, err := getObjects[model.PolicyEntity]("../testdata/aws/test_managed_policies.json")
	require.NoError(t, err)
	accessPoints, err := getObjects[model.AwsS3AccessPoint]("../testdata/aws/test_access_points.json")
	require.NoError(t, err)

	repoMock.EXPECT().GetManagedPolicies(mock.Anything).Return(managedPolicies, nil).Once()
	repoMock.EXPECT().GetRoles(mock.Anything).Return(roles, nil).Once()
	repoMock.EXPECT().ListAccessPoints(mock.Anything, "us-west-1").Return(accessPoints, nil).Once()

	return repoMock, ssoRepoMock, iamRepo, syncer
}

func TestSimplifyPermissions(t *testing.T) {
	tests := []struct {
		allPermissions   []string
		userPermissions  []string
		expectedSimplify []string
	}{
		{
			[]string{"s3:getObject", "s3:getList", "s3:putObject", "s3:deleteObject"},
			[]string{"s3:getObject", "s3:getList"},
			[]string{"s3:get*"},
		},
		{
			[]string{"s3:getObject", "s3:getList", "s3:putObject", "s3:deleteObject"},
			[]string{"s3:getObject", "s3:getList", "s3:putObject", "s3:deleteObject"},
			[]string{"s3:*"},
		},
		{
			[]string{"ec2:doStuff", "s3:getObject", "s3:getList", "s3:putObject", "s3:deleteObject"},
			[]string{"s3:getObject", "s3:getList", "s3:putObject", "s3:deleteObject"},
			[]string{"s3:*"},
		},
		{
			[]string{"s3:getObject", "s3:getList", "s3:putObject"},
			[]string{"s3:getObject", "s3:putObject"},
			[]string{"s3:getObject", "s3:putObject"},
		},
		{
			[]string{"s3:getObject", "s3:getObjectVersions", "s3:putObject", "s3:putObjectAcl", "s3:deleteObject", "ec2:doStuff"},
			[]string{"s3:getObject", "s3:getObjectVersions", "s3:putObject", "s3:putObjectAcl", "s3:deleteObject", "ec2:doStuff"},
			[]string{"*"},
		},
		{
			[]string{"s3:getObject", "s3:getObjectVersions", "s3:putObject", "s3:putObjectAcl", "s3:deleteObject", "ec2:doStuff"},
			[]string{},
			[]string{},
		},
		{
			[]string{},
			[]string{"s3:getObject", "s3:getObjectVersions", "s3:putObject", "s3:putObjectAcl", "s3:deleteObject", "ec2:doStuff"},
			[]string{},
		},
	}

	for i, test := range tests {
		simplified := optimizePermissions(test.allPermissions, test.userPermissions)
		if (len(simplified) == 0 && len(test.expectedSimplify) == 0) || reflect.DeepEqual(simplified, test.expectedSimplify) {
			fmt.Printf("Test case %d passed\n", i+1)
		} else {
			fmt.Printf("Test case %d failed. Got %v but expected %v\n", i+1, simplified, test.expectedSimplify)
			t.Fail()
		}
	}
}

func TestSyncAccessProviderToTarget_CreateRole(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				Description: "a test role",
				NamingHint:  "test role",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},
			},
		},
	}

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", []string{"stewart_b"}).Return(true, nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_role", ExternalId: ptr.String(constants.RoleTypePrefix + "test_role"), Type: ptr.String(string(model.Role))}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	// repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	// repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_CreateRoleWithGroups(t *testing.T) {
	repoMock, _, iamRepo, syncer := setupMockExportEnvironment(t, false)

	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				Description: "a test role",
				NamingHint:  "test role",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users:  []string{"stewart_b"},
					Groups: []string{"engineers", "human_resources"},
				},
			},
		},
	}

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", mock.Anything).RunAndReturn(func(_ context.Context, _ string, _ string, usernames []string) (bool, error) {
		assert.ElementsMatch(t, []string{"stewart_b", "nick_n", "bart", "rudi"}, usernames)
		return true, nil
	}).Once()
	iamRepo.EXPECT().GetGroups(ctx).Return([]model.GroupEntity{
		{
			ARN:        "engineers_arn",
			ExternalId: "engineers_external_id",
			Name:       "engineers",
			Members:    []string{"stewart_b", "nick_n"},
		},
		{
			ARN:        "human_resources_arn",
			ExternalId: "human_resources_external_id",
			Name:       "human_resources",
			Members:    []string{"bart", "rudi"},
		},
		{
			ARN:        "other_arn",
			ExternalId: "other_external_id",
			Name:       "other",
			Members:    []string{"steven"},
		},
	}, nil)

	iamRepo.EXPECT().GetUsers(ctx, false).Return([]model.UserEntity{
		{
			ARN:        "stewart_b_arn",
			ExternalId: "stewart_b",
			Name:       "stewart_b",
			Email:      "stewart_b@raito.io",
			Tags:       nil,
		},
		{
			ARN:        "nick_n_arn",
			ExternalId: "nick_n",
			Name:       "nick_n",
			Email:      "nick_n@raito.io",
			Tags:       nil,
		},
		{
			ARN:        "bart_arn",
			ExternalId: "bart",
			Name:       "bart",
			Email:      "bart@raito.io",
			Tags:       nil,
		},
		{
			ARN:        "rudi_arn",
			ExternalId: "rudi",
			Name:       "rudi",
			Email:      "rudi@raito.io",
			Tags:       nil,
		},
		{
			ARN:        "steven_arn",
			ExternalId: "steven",
			Name:       "steven",
			Email:      "steven@raito.io",
			Tags:       nil,
		},
	}, nil)

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_role", ExternalId: ptr.String(constants.RoleTypePrefix + "test_role"), Type: ptr.String(string(model.Role))}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	// repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	// repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_CreateRoleWithWhat(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				Description: "a test role",
				NamingHint:  "test role",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},

				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "test_file",
							Type:     "file",
						},
						Permissions: []string{"s3:GetObject", "s3:GetObjectAcl"},
					},
				},
			},
		},
	}

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", []string{"stewart_b"}).Return(true, nil).Once()
	repoMock.EXPECT().CreateRoleInlinePolicy(ctx, "test_role", "Raito_Inline_test_role", []*awspolicy.Statement{{
		Effect: "Allow",
		Action: []string{"s3:GetObject", "s3:GetObjectAcl"},
		Resource: []string{
			"arn:aws:s3:::test_file",
		},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_role", Type: ptr.String(string(model.Role)), ExternalId: ptr.String(constants.RoleTypePrefix + "test_role")}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	// repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	// repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_CreateRolesWithInheritance(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				Description: "a test role",
				NamingHint:  "test role",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "file1",
							Type:     "file",
						},
						Permissions: []string{"s3:GetObject", "s3:GetObjectAcl"},
					},
				},
			},
			{
				Id:          "another",
				Name:        "AnotherRole",
				Description: "another role",
				NamingHint:  "another role",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users:       []string{"nick_n"},
					InheritFrom: []string{"ID:something"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "folder1",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObjectAttributes"},
					},
				},
			},
		},
	}

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", []string{"stewart_b"}).Return(true, nil).Once()
	repoMock.EXPECT().CreateRole(ctx, "another_role", "another role", []string{"nick_n", "stewart_b"}).Return(true, nil).Once()

	repoMock.EXPECT().CreateRoleInlinePolicy(ctx, "test_role", "Raito_Inline_test_role", mock.Anything).RunAndReturn(func(ctx context.Context, s string, s2 string, statements []*awspolicy.Statement) error {
		assert.Equal(t, 2, len(statements))

		file := false
		folder := false
		for _, statement := range statements {
			if statement.Resource[0] == "arn:aws:s3:::file1" {
				file = true
				assert.True(t, slices.Contains(statement.Action, "s3:GetObject"))
				assert.True(t, slices.Contains(statement.Action, "s3:GetObjectAcl"))
			} else if statement.Resource[0] == "arn:aws:s3:::folder1" {
				folder = true
				assert.True(t, slices.Contains(statement.Action, "s3:GetObjectAttributes"))
			}
		}

		assert.True(t, file && folder)
		return nil
	}).Once()

	repoMock.EXPECT().CreateRoleInlinePolicy(ctx, "another_role", "Raito_Inline_another_role", []*awspolicy.Statement{{
		Effect:   "Allow",
		Action:   []string{"s3:GetObjectAttributes"},
		Resource: []string{"arn:aws:s3:::folder1"},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_role", Type: ptr.String(string(model.Role)), ExternalId: ptr.String(constants.RoleTypePrefix + "test_role")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "another", ActualName: "another_role", Type: ptr.String(string(model.Role)), ExternalId: ptr.String(constants.RoleTypePrefix + "another_role")}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	// repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	// repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_UpdateRole(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "Data Engineering Sync",
				ExternalId:  ptr.String("role:data_engineer_sync"),
				Description: "a test role",
				NamingHint:  "data engineering sync",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b", "n_nguyen"},
				},
			},
		},
	}

	repoMock.EXPECT().UpdateAssumeEntities(ctx, "data_engineering_sync", []string{"n_nguyen", "stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().DeleteRoleInlinePolicies(ctx, "data_engineering_sync").Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "data_engineering_sync", Type: ptr.String(string(model.Role)), ExternalId: ptr.String(constants.RoleTypePrefix + "data_engineering_sync")}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_DeleteRole(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				ExternalId:  ptr.String("role:TestRole"),
				Description: "a test role",
				Delete:      true,
				NamingHint:  "data_engineering_sync",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("data_engineering_sync"),
			},
		},
	}

	repoMock.EXPECT().DeleteRole(ctx, "data_engineering_sync").Return(nil).Once()

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t)

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_CreatePolicy(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				// To fake that this is an internalized AP that was representing the inline policies of a user called 'userke'
				ExternalId:  ptr.String(constants.UserTypePrefix + "userke|" + constants.InlinePrefix + "inline1|inline2"),
				Id:          "something",
				Name:        "TestPolicy",
				Description: "a test policy",
				NamingHint:  "test_policy",
				Type:        aws.String(string(model.Policy)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("test_policy"),

				Who: sync_to_target.WhoItem{
					Users:  []string{"stewart_b"},
					Groups: []string{"g1"},
				},

				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "test_file",
							Type:     "file",
						},
						Permissions: []string{"s3:GetObject", "s3:GetObjectAcl"},
					},
				},
			},
		},
	}

	repoMock.EXPECT().CreateManagedPolicy(ctx, "test_policy", []*awspolicy.Statement{{
		StatementID: "",
		Effect:      "Allow",
		Action:      []string{"s3:GetObject", "s3:GetObjectAcl"},
		Resource: []string{
			"arn:aws:s3:::test_file",
		},
	}}).Return(&types.Policy{}, nil).Once()
	repoMock.EXPECT().GetPolicyArn("test_policy", false, mock.Anything).Return("arn:test_policy").Twice()
	repoMock.EXPECT().DeleteInlinePolicy(ctx, "inline1", "userke", iam.UserResourceType).Return(nil).Once()
	repoMock.EXPECT().DeleteInlinePolicy(ctx, "inline2", "userke", iam.UserResourceType).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:test_policy", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().AttachGroupToManagedPolicy(ctx, "arn:test_policy", []string{"g1"}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_policy", Type: ptr.String(string(model.Policy)), ExternalId: ptr.String(constants.PolicyTypePrefix + "test_policy")}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
}

func TestSyncAccessProviderToTarget_CreatePoliciesWithInheritance(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestPolicy",
				Description: "a test policy",
				NamingHint:  "test policy",
				Type:        aws.String(string(model.Policy)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},
			},
			{
				Id:          "another",
				Name:        "AnotherPolicy",
				Description: "another policy",
				NamingHint:  "another policy",
				Type:        aws.String(string(model.Policy)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users:       []string{"nick_n"},
					InheritFrom: []string{"ID:something"},
				},
			},
		},
	}

	repoMock.EXPECT().CreateManagedPolicy(ctx, "test_policy", mock.Anything).Return(&types.Policy{}, nil).Once()
	repoMock.EXPECT().CreateManagedPolicy(ctx, "another_policy", mock.Anything).Return(&types.Policy{}, nil).Once()
	repoMock.EXPECT().GetPolicyArn("test_policy", false, mock.Anything).Return("arn:test_policy")
	repoMock.EXPECT().GetPolicyArn("another_policy", false, mock.Anything).Return("arn:another_policy").Twice()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:test_policy", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:another_policy", []string{"nick_n"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:another_policy", []string{"stewart_b"}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_policy", Type: ptr.String(string(model.Policy)), ExternalId: ptr.String(constants.PolicyTypePrefix + "test_policy")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "another", ActualName: "another_policy", Type: ptr.String(string(model.Policy)), ExternalId: ptr.String(constants.PolicyTypePrefix + "another_policy")}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	// repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	// repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_CreatePolicyRoleInheritance(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "p1",
				Name:        "P1",
				Description: "test policy1",
				NamingHint:  "p1",
				Type:        aws.String(string(model.Policy)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users:       []string{"user1"},
					InheritFrom: []string{"ID:p3"},
				},
			},
			{
				Id:          "p2",
				Name:        "P2",
				Description: "test policy2",
				NamingHint:  "p2",
				Type:        aws.String(string(model.Policy)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users:       []string{"user2"},
					InheritFrom: []string{"ID:p3"},
				},
			},
			{
				Id:          "p3",
				Name:        "P3",
				Description: "test policy3",
				NamingHint:  "p3",
				Type:        aws.String(string(model.Policy)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users:       []string{"user3"},
					InheritFrom: []string{"ID:r1"},
				},
			},
			{
				Id:          "r1",
				Name:        "r1",
				Description: "test role1",
				NamingHint:  "r1",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users:       []string{"user4"},
					InheritFrom: []string{"ID:r2"},
				},
			},
			{
				Id:          "r2",
				Name:        "r2",
				Description: "test role2",
				NamingHint:  "r2",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"user5"},
				},
			},
		},
	}

	repoMock.EXPECT().CreateManagedPolicy(ctx, "p1", mock.Anything).Return(&types.Policy{}, nil).Once()
	repoMock.EXPECT().CreateManagedPolicy(ctx, "p2", mock.Anything).Return(&types.Policy{}, nil).Once()
	repoMock.EXPECT().CreateManagedPolicy(ctx, "p3", mock.Anything).Return(&types.Policy{}, nil).Once()
	repoMock.EXPECT().GetPolicyArn("p1", false, mock.Anything).Return("arn:p1")
	repoMock.EXPECT().GetPolicyArn("p2", false, mock.Anything).Return("arn:p2")
	repoMock.EXPECT().GetPolicyArn("p3", false, mock.Anything).Return("arn:p3")
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:p1", []string{"user1"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:p1", []string{"user3"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:p2", []string{"user2"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:p2", []string{"user3"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:p3", []string{"user3"}).Return(nil).Once()

	repoMock.EXPECT().CreateRole(ctx, "r1", "test role1", []string{"user4", "user5"}).Return(true, nil).Once()
	repoMock.EXPECT().CreateRole(ctx, "r2", "test role2", []string{"user5"}).Return(true, nil).Once()

	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p1", []string{"r1"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p2", []string{"r1"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p3", []string{"r1"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p1", []string{"r2"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p2", []string{"r2"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p3", []string{"r2"}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "p1", ActualName: "p1", Type: ptr.String(string(model.Policy)), ExternalId: ptr.String(constants.PolicyTypePrefix + "p1")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "p2", ActualName: "p2", Type: ptr.String(string(model.Policy)), ExternalId: ptr.String(constants.PolicyTypePrefix + "p2")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "p3", ActualName: "p3", Type: ptr.String(string(model.Policy)), ExternalId: ptr.String(constants.PolicyTypePrefix + "p3")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "r1", ActualName: "r1", Type: ptr.String(string(model.Role)), ExternalId: ptr.String(constants.RoleTypePrefix + "r1")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "r2", ActualName: "r2", Type: ptr.String(string(model.Role)), ExternalId: ptr.String(constants.RoleTypePrefix + "r2")}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	// repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	// repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_DeletePolicy(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "HumanResourcesReadS3Policy",
				Description: "a test policy",
				Delete:      true,
				NamingHint:  "HumanResourcesReadS3Policy",
				Type:        aws.String(string(model.Policy)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("HumanResourcesReadS3Policy"),
			},
		},
	}

	repoMock.EXPECT().DeleteManagedPolicy(ctx, "HumanResourcesReadS3Policy", false).Return(nil).Once()

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t)

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_NotExistingDeletePolicy(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "test_policy",
				Description: "a test policy",
				Delete:      true,
				NamingHint:  "test_policy",
				Type:        aws.String(string(model.Policy)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("test_policy"),
			},
		},
	}

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t)

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_CreateAccessPoint(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "Test Access Point",
				Description: "a test access point",
				NamingHint:  "Test Access Point",
				Type:        aws.String(string(model.AccessPoint)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "account:us-west-1:bucketname/folder1/folder2",
							Type:     "glue-table",
						},
						Permissions: []string{"s3:GetObject", "s3:GetObjectAcl"},
					},
				},
			},
		},
	}

	repoMock.EXPECT().CreateAccessPoint(ctx, "test-access-point", "bucketname", "us-west-1", []*awspolicy.Statement{{
		Effect: "Allow",
		Action: []string{"s3:GetObject", "s3:GetObjectAcl"},
		Principal: map[string][]string{
			"AWS": {"arn:aws:iam:::user/stewart_b"},
		},
		Resource: []string{
			"arn:aws:s3:us-west-1::accesspoint/test-access-point/object/folder1/folder2/*",
		},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test-access-point", ExternalId: ptr.String(constants.AccessPointTypePrefix + "test-access-point"), Type: ptr.String(string(model.AccessPoint))}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_CreateAccessPointWithGroups(t *testing.T) {
	repoMock, _, iamRepo, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "Test Access Point",
				Description: "a test access point",
				NamingHint:  "Test Access Point",
				Type:        aws.String(string(model.AccessPoint)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users:  []string{"stewart_b"},
					Groups: []string{"engineers", "human_resources"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "account:us-west-1:bucketname/folder1/folder2",
							Type:     "glue-table",
						},
						Permissions: []string{"s3:GetObject", "s3:GetObjectAcl"},
					},
				},
			},
		},
	}

	iamRepo.EXPECT().GetGroups(ctx).Return([]model.GroupEntity{
		{
			ARN:        "engineers_arn",
			ExternalId: "engineers_external_id",
			Name:       "engineers",
			Members:    []string{"stewart_b", "nick_n"},
		},
		{
			ARN:        "human_resources_arn",
			ExternalId: "human_resources_external_id",
			Name:       "human_resources",
			Members:    []string{"bart", "rudi"},
		},
		{
			ARN:        "other_arn",
			ExternalId: "other_external_id",
			Name:       "other",
			Members:    []string{"steven"},
		},
	}, nil)

	iamRepo.EXPECT().GetUsers(ctx, false).Return([]model.UserEntity{
		{
			ARN:        "arn:aws:iam:::user/stewart_b",
			ExternalId: "stewart_b",
			Name:       "stewart_b",
			Email:      "stewart_b@raito.io",
			Tags:       nil,
		},
		{
			ARN:        "arn:aws:iam:::user/nick_n",
			ExternalId: "nick_n",
			Name:       "nick_n",
			Email:      "nick_n@raito.io",
			Tags:       nil,
		},
		{
			ARN:        "arn:aws:iam:::user/bart",
			ExternalId: "bart",
			Name:       "bart",
			Email:      "bart@raito.io",
			Tags:       nil,
		},
		{
			ARN:        "arn:aws:iam:::user/rudi",
			ExternalId: "rudi",
			Name:       "rudi",
			Email:      "rudi@raito.io",
			Tags:       nil,
		},
		{
			ARN:        "arn:aws:iam:::user/steven",
			ExternalId: "steven",
			Name:       "steven",
			Email:      "steven@raito.io",
			Tags:       nil,
		},
	}, nil)

	repoMock.EXPECT().CreateAccessPoint(ctx, "test-access-point", "bucketname", "us-west-1", []*awspolicy.Statement{{
		Effect: "Allow",
		Action: []string{"s3:GetObject", "s3:GetObjectAcl"},
		Principal: map[string][]string{
			"AWS": {
				"arn:aws:iam:::user/bart",
				"arn:aws:iam:::user/nick_n",
				"arn:aws:iam:::user/rudi",
				"arn:aws:iam:::user/stewart_b",
			},
		},
		Resource: []string{
			"arn:aws:s3:us-west-1::accesspoint/test-access-point/object/folder1/folder2/*",
		},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test-access-point", ExternalId: ptr.String(constants.AccessPointTypePrefix + "test-access-point"), Type: ptr.String(string(model.AccessPoint))}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_UpdateAccessPoint(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "existingaccesspoint",
				Name:        "existingaccesspoint",
				ExternalId:  ptr.String("accessPoint:TestAccessPoint"),
				Description: "a test access point",
				NamingHint:  "existingaccesspoint",
				Type:        aws.String(string(model.AccessPoint)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "account:us-west-1:bucketname/folder1/folder2",
							Type:     "glue-table",
						},
						Permissions: []string{"s3:GetObject", "s3:GetObjectAcl"},
					},
				},
			},
		},
	}

	repoMock.EXPECT().UpdateAccessPoint(ctx, "existingaccesspoint", "us-west-1", []*awspolicy.Statement{{
		Effect: "Allow",
		Action: []string{"s3:GetObject", "s3:GetObjectAcl"},
		Principal: map[string][]string{
			"AWS": {"arn:aws:iam:::user/stewart_b"},
		},
		Resource: []string{
			"arn:aws:s3:us-west-1::accesspoint/existingaccesspoint/object/folder1/folder2/*",
		},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "existingaccesspoint", ActualName: "existingaccesspoint", ExternalId: ptr.String(constants.AccessPointTypePrefix + "existingaccesspoint"), Type: ptr.String(string(model.AccessPoint))}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_DeleteAccessPoint(t *testing.T) {
	repoMock, _, _, syncer := setupMockExportEnvironment(t, false)
	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{constants.AwsRegions: "us-west-1"},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "existingaccesspoint",
				Name:        "existingaccesspoint",
				ExternalId:  ptr.String("accessPoint:us-west-1:TestAccessPoint"),
				Description: "a test access point",
				NamingHint:  "existingaccesspoint",
				Type:        aws.String(string(model.AccessPoint)),

				Action: sync_to_target.Grant,
				Delete: true,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "account:us-west-1:bucketname/folder1/folder2",
							Type:     "glue-table",
						},
						Permissions: []string{"s3:GetObject", "s3:GetObjectAcl"},
					},
				},
			},
		},
	}

	repoMock.EXPECT().DeleteAccessPoint(ctx, "existingaccesspoint", "us-west-1").Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "existingaccesspoint", ActualName: "existingaccesspoint", Type: ptr.String(string(model.AccessPoint))}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_CreateSsoRole(t *testing.T) {
	repo, ssoRepoMock, _, syncer := setupMockExportEnvironment(t, true)

	ctx := context.Background()
	configmap := config.ConfigMap{
		Parameters: map[string]string{
			constants.AwsRegions:             "us-west-1",
			constants.AwsOrganizationProfile: "master",
		},
	}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestSsoRole",
				Description: "a test sso role",
				NamingHint:  "sso test role",

				Action: sync_to_target.Purpose,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},
			},
			{
				Id:          "another",
				Name:        "AnotherRole",
				Description: "another role",
				NamingHint:  "another role",
				Type:        aws.String(string(model.Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					InheritFrom: []string{"ID:something"},
					Users:       []string{"nick_n"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "folder1",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObjectAttributes"},
					},
				},
			},
		},
	}

	repo.EXPECT().CreateRole(ctx, "another_role", "another role", []string{"nick_n"}).Return(true, nil).Once()

	ssoRepoMock.EXPECT().ListSsoRole(ctx).Return([]string{}, nil).Once()
	ssoRepoMock.EXPECT().GetUsers(ctx).Return(bimap.Of(map[string]string{"stewart_b_id": "stewart_b"}), nil).Maybe()
	ssoRepoMock.EXPECT().GetGroups(ctx).Return(bimap.New[string, string](), nil).Maybe()
	ssoRepoMock.EXPECT().CreateSsoRole(ctx, "RAITO_sso_test_role_123456789012", "a test sso role").Return("arn::::permissionset:id", nil).Once()
	ssoRepoMock.EXPECT().AssignPermissionSet(ctx, "arn::::permissionset:id", ssoTypes.PrincipalTypeUser, "stewart_b_id").Return(nil).Once()
	ssoRepoMock.EXPECT().UpdateInlinePolicyToPermissionSet(ctx, "arn::::permissionset:id", []*awspolicy.Statement{
		{
			StatementID: "",
			Effect:      "Allow",
			Action:      []string{"s3:GetObjectAttributes"},
			Resource:    []string{"arn:aws:s3:::folder1"},
		},
	}).Return(nil).Once()
	ssoRepoMock.EXPECT().ListAwsManagedPolicyFromPermissionSet(ctx, "arn::::permissionset:id").Return(set.NewSet[string](), nil).Once()
	ssoRepoMock.EXPECT().ListCustomerManagedPolicyFromPermissionSet(ctx, "arn::::permissionset:id").Return(set.NewSet[string](), nil).Once()
	ssoRepoMock.EXPECT().ProvisionPermissionSet(ctx, "arn::::permissionset:id").Return(&ssoTypes.PermissionSetProvisioningStatus{Status: ssoTypes.StatusValuesSucceeded}, nil).Once()

	repo.EXPECT().GetManagedPolicies(ctx).Return([]model.PolicyEntity{}, nil).Once()
	repo.EXPECT().CreateRoleInlinePolicy(ctx, "another_role", "Raito_Inline_another_role", []*awspolicy.Statement{{
		Effect:   "Allow",
		Action:   []string{"s3:GetObjectAttributes"},
		Resource: []string{"arn:aws:s3:::folder1"},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "another", ActualName: "another_role", ExternalId: ptr.String(constants.RoleTypePrefix + "another_role"), Type: ptr.String(string(model.Role))}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "RAITO_sso_test_role_123456789012", ExternalId: ptr.String(constants.SsoRoleTypePrefix + "arn::::permissionset:id"), Type: ptr.String(string(model.SSORole))}).Return(nil).Once()

	// When
	err := syncer.doSyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)
}

func TestMergeStatementsOnPermissions(t *testing.T) {
	var tests = []struct {
		Name       string
		Statements []*awspolicy.Statement
		Expected   []*awspolicy.Statement
	}{
		{
			Name:       "No statements",
			Statements: []*awspolicy.Statement{},
			Expected:   []*awspolicy.Statement{},
		},
		{
			Name: "Single statement",
			Statements: []*awspolicy.Statement{
				{Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::test_file"}},
			},
			Expected: []*awspolicy.Statement{
				{Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::test_file"}},
			},
		},
		{
			Name: "Advanced",
			Statements: []*awspolicy.Statement{
				{Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::f1", "arn:aws:s3:::f2"}},
				{Action: []string{"s3:GetObject", "s3:PutObject"}, Resource: []string{"arn:aws:s3:::f3"}},
				{Action: []string{"s3:PutObject", "s3:GetObject"}, Resource: []string{"arn:aws:s3:::f4"}},
			},
			Expected: []*awspolicy.Statement{
				{Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::f1", "arn:aws:s3:::f2"}},
				{Action: []string{"s3:GetObject", "s3:PutObject"}, Resource: []string{"arn:aws:s3:::f3", "arn:aws:s3:::f4"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result := mergeStatementsOnPermissions(test.Statements)
			assert.ElementsMatch(t, result, test.Expected)
		})
	}
}

func TestExtractBucketForAccessPoint(t *testing.T) {
	var tests = []struct {
		Name          string
		WhatItems     []sync_to_target.WhatItem
		Region        string
		Expected      string
		ExpectedError string
	}{
		{
			Name: "Single bucket",
			WhatItems: []sync_to_target.WhatItem{
				{
					DataObject: &data_source.DataObjectReference{FullName: "account:eu-central-1:bucket"},
				},
			},
			Expected:      "bucket",
			Region:        "eu-central-1",
			ExpectedError: "",
		},
		{
			Name: "No bucket",
			WhatItems: []sync_to_target.WhatItem{
				{
					DataObject: &data_source.DataObjectReference{FullName: "blah"},
				},
			},
			Expected:      "",
			Region:        "",
			ExpectedError: "unexpected full name for S3 object",
		},
		{
			Name:          "No statements",
			WhatItems:     []sync_to_target.WhatItem{},
			Expected:      "",
			Region:        "",
			ExpectedError: "unable to determine the bucket",
		},
		{
			Name: "Multiple statements",
			WhatItems: []sync_to_target.WhatItem{
				{
					DataObject: &data_source.DataObjectReference{FullName: "account:eu-west-1:bucket"},
				},
				{
					DataObject: &data_source.DataObjectReference{FullName: "account:eu-west-1:bucket/folder3"},
				},
			},
			Expected:      "bucket",
			Region:        "eu-west-1",
			ExpectedError: "",
		},
		{
			Name: "Multiple buckets",
			WhatItems: []sync_to_target.WhatItem{
				{
					DataObject: &data_source.DataObjectReference{FullName: "account:eu-west-1:bucket"},
				},
				{
					DataObject: &data_source.DataObjectReference{FullName: "account:eu-west-1:bucket2"},
				},
			},
			Expected:      "",
			Region:        "",
			ExpectedError: "an access point can only have one bucket associated with it",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result, region, err := extractBucketForAccessPoint(test.WhatItems)
			assert.Equal(t, result, test.Expected)
			assert.Equal(t, region, test.Region)
			if test.ExpectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConvertResourceURLsForAccessPoint(t *testing.T) {
	var tests = []struct {
		Name      string
		Statement *awspolicy.Statement
		Expected  []string
	}{
		{
			Name: "Bucket level",
			Statement: &awspolicy.Statement{
				Resource: []string{"arn:aws:s3:::bucket"},
			},
			Expected: []string{"arn:aws:s3:eu-central-1:077954824694:accesspoint/operations"},
		},
		{
			Name: "Folder level",
			Statement: &awspolicy.Statement{
				Resource: []string{"arn:aws:s3:::bucket/folder1"},
			},
			Expected: []string{"arn:aws:s3:eu-central-1:077954824694:accesspoint/operations/object/folder1/*"},
		},
		{
			Name: "Multiple resources",
			Statement: &awspolicy.Statement{
				Resource: []string{"arn:aws:s3:::bucket/folder1", "arn:aws:s3:::bucket/folder2/folder3"},
			},
			Expected: []string{"arn:aws:s3:eu-central-1:077954824694:accesspoint/operations/object/folder1/*", "arn:aws:s3:eu-central-1:077954824694:accesspoint/operations/object/folder2/folder3/*"},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			convertResourceURLsForAccessPoint([]*awspolicy.Statement{test.Statement}, "arn:aws:s3:eu-central-1:077954824694:accesspoint/operations")
			assert.ElementsMatch(t, test.Expected, test.Statement.Resource)
		})
	}
}
