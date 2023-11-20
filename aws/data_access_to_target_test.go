package aws

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"reflect"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/ptr"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/raito-io/golang-set/set"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupMockExportEnvironment(t *testing.T) (*mockDataAccessRepository, *AccessSyncer) {
	repoMock := newMockDataAccessRepository(t)

	syncer := &AccessSyncer{
		repo:            repoMock,
		managedPolicies: nil,
	}

	roles, err := getObjects[RoleEntity]("testdata/aws/test_roles.json")
	require.Nil(t, err)
	managedPolicies, err := getObjects[PolicyEntity]("testdata/aws/test_managed_policies.json")
	require.Nil(t, err)

	repoMock.EXPECT().GetManagedPolicies(mock.Anything).Return(managedPolicies, nil).Once()
	repoMock.EXPECT().GetRoles(mock.Anything).Return(roles, nil).Once()

	return repoMock, syncer
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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				Description: "a test role",
				NamingHint:  "test role",
				Type:        aws.String(string(Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b"},
				},
			},
		},
	}

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_role", ExternalId: ptr.String(RoleTypePrefix + "test_role"), Type: ptr.String(string(Role))}).Return(nil).Once()

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				Description: "a test role",
				NamingHint:  "test role",
				Type:        aws.String(string(Role)),

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

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)
	repoMock.EXPECT().CreateRoleInlinePolicy(ctx, "test_role", "Raito_Inline_test_role", []awspolicy.Statement{{
		Effect: "Allow",
		Action: []string{"s3:GetObject", "s3:GetObjectAcl"},
		Resource: []string{
			"arn:aws:s3:::test_file",
		},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_role", Type: ptr.String(string(Role)), ExternalId: ptr.String(RoleTypePrefix + "test_role")}).Return(nil).Once()

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				Description: "a test role",
				NamingHint:  "test role",
				Type:        aws.String(string(Role)),

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
				Type:        aws.String(string(Role)),

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

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().CreateRole(ctx, "another_role", "another role", []string{"nick_n", "stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	repoMock.EXPECT().CreateRoleInlinePolicy(ctx, "test_role", "Raito_Inline_test_role", mock.Anything).RunAndReturn(func(ctx context.Context, s string, s2 string, statements []awspolicy.Statement) error {
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

	repoMock.EXPECT().CreateRoleInlinePolicy(ctx, "another_role", "Raito_Inline_another_role", []awspolicy.Statement{{
		Effect:   "Allow",
		Action:   []string{"s3:GetObjectAttributes"},
		Resource: []string{"arn:aws:s3:::folder1"},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_role", Type: ptr.String(string(Role)), ExternalId: ptr.String(RoleTypePrefix + "test_role")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "another", ActualName: "another_role", Type: ptr.String(string(Role)), ExternalId: ptr.String(RoleTypePrefix + "another_role")}).Return(nil).Once()

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "Data Engineering Sync",
				Description: "a test role",
				NamingHint:  "data engineering sync",
				Type:        aws.String(string(Role)),

				Action: sync_to_target.Grant,

				Who: sync_to_target.WhoItem{
					Users: []string{"stewart_b", "n_nguyen"},
				},
			},
		},
	}

	repoMock.EXPECT().UpdateAssumeEntities(ctx, "data_engineering_sync", []string{"n_nguyen", "stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)
	repoMock.EXPECT().DeleteRoleInlinePolicies(ctx, "data_engineering_sync").Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "data_engineering_sync", Type: ptr.String(string(Role)), ExternalId: ptr.String(RoleTypePrefix + "data_engineering_sync")}).Return(nil).Once()

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestRole",
				Description: "a test role",
				Delete:      true,
				NamingHint:  "data_engineering_sync",
				Type:        aws.String(string(Role)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("data_engineering_sync"),
			},
		},
	}

	repoMock.EXPECT().DeleteRole(ctx, "data_engineering_sync").Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				// To fake that this is an internalized AP that was representing the inline policies of a user called 'userke'
				ExternalId:  ptr.String(UserTypePrefix + "userke|" + InlinePrefix + "inline1|inline2"),
				Id:          "something",
				Name:        "TestPolicy",
				Description: "a test policy",
				NamingHint:  "test_policy",
				Type:        aws.String(string(Policy)),

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

	repoMock.EXPECT().CreateManagedPolicy(ctx, "test_policy", []awspolicy.Statement{{
		StatementID: "",
		Effect:      "Allow",
		Action:      []string{"s3:GetObject", "s3:GetObjectAcl"},
		Resource: []string{
			"arn:aws:s3:::test_file",
		},
	}}).Return(&types.Policy{}, nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)
	repoMock.EXPECT().GetPolicyArn("test_policy", false, mock.Anything).Return("arn:test_policy").Twice()
	repoMock.EXPECT().DeleteInlinePolicy(ctx, "inline1", "userke", UserResourceType).Return(nil).Once()
	repoMock.EXPECT().DeleteInlinePolicy(ctx, "inline2", "userke", UserResourceType).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:test_policy", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().AttachGroupToManagedPolicy(ctx, "arn:test_policy", []string{"g1"}).Return(nil).Once()

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_policy", Type: ptr.String(string(Policy)), ExternalId: ptr.String(PolicyTypePrefix + "test_policy")}).Return(nil).Once()

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "TestPolicy",
				Description: "a test policy",
				NamingHint:  "test policy",
				Type:        aws.String(string(Policy)),

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
				Type:        aws.String(string(Policy)),

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
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "something", ActualName: "test_policy", Type: ptr.String(string(Policy)), ExternalId: ptr.String(PolicyTypePrefix + "test_policy")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "another", ActualName: "another_policy", Type: ptr.String(string(Policy)), ExternalId: ptr.String(PolicyTypePrefix + "another_policy")}).Return(nil).Once()

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "p1",
				Name:        "P1",
				Description: "test policy1",
				NamingHint:  "p1",
				Type:        aws.String(string(Policy)),

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
				Type:        aws.String(string(Policy)),

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
				Type:        aws.String(string(Policy)),

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
				Type:        aws.String(string(Role)),

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
				Type:        aws.String(string(Role)),

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

	repoMock.EXPECT().CreateRole(ctx, "r1", "test role1", []string{"user4", "user5"}).Return(nil).Once()
	repoMock.EXPECT().CreateRole(ctx, "r2", "test role2", []string{"user5"}).Return(nil).Once()

	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p1", []string{"r1"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p2", []string{"r1"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p3", []string{"r1"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p1", []string{"r2"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p2", []string{"r2"}).Return(nil).Once()
	repoMock.EXPECT().AttachRoleToManagedPolicy(ctx, "arn:p3", []string{"r2"}).Return(nil).Once()

	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewAccessProviderFeedbackHandler(t)
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "p1", ActualName: "p1", Type: ptr.String(string(Policy)), ExternalId: ptr.String(PolicyTypePrefix + "p1")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "p2", ActualName: "p2", Type: ptr.String(string(Policy)), ExternalId: ptr.String(PolicyTypePrefix + "p2")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "p3", ActualName: "p3", Type: ptr.String(string(Policy)), ExternalId: ptr.String(PolicyTypePrefix + "p3")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "r1", ActualName: "r1", Type: ptr.String(string(Role)), ExternalId: ptr.String(RoleTypePrefix + "r1")}).Return(nil).Once()
	feedbackHandler.EXPECT().AddAccessProviderFeedback(sync_to_target.AccessProviderSyncFeedback{AccessProvider: "r2", ActualName: "r2", Type: ptr.String(string(Role)), ExternalId: ptr.String(RoleTypePrefix + "r2")}).Return(nil).Once()

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "HumanResourcesReadS3Policy",
				Description: "a test policy",
				Delete:      true,
				NamingHint:  "HumanResourcesReadS3Policy",
				Type:        aws.String(string(Policy)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("HumanResourcesReadS3Policy"),
			},
		},
	}

	repoMock.EXPECT().DeleteManagedPolicy(ctx, "HumanResourcesReadS3Policy", false).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

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
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	if configmap.Parameters == nil {
		configmap.Parameters = map[string]string{}
	}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := sync_to_target.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          "something",
				Name:        "test_policy",
				Description: "a test policy",
				Delete:      true,
				NamingHint:  "test_policy",
				Type:        aws.String(string(Policy)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("test_policy"),
			},
		},
	}

	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

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

func TestGetRecursiveInheritedAPs(t *testing.T) {
	var tests = []struct {
		Start          string
		InheritanceMap map[string]set.Set[string]
		ExpectedResult []string
	}{
		{"r1", map[string]set.Set[string]{
			"r1": set.NewSet("r2"),
			"r2": set.NewSet("r3"),
		}, []string{"r2", "r3"}},

		{"r1", map[string]set.Set[string]{
			"r0": set.NewSet("r1"),
			"r1": set.NewSet("r2", "r3"),
			"r3": set.NewSet("r5"),
			"r4": set.NewSet("r2"),
		}, []string{"r2", "r3", "r5"}},
	}

	for _, test := range tests {
		inherited := set.NewSet[string]()

		getRecursiveInheritedAPs(test.Start, test.InheritanceMap, inherited)

		res := inherited.Slice()
		sort.Strings(res)

		assert.Equal(t, res, test.ExpectedResult)
	}
}
