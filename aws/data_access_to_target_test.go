package aws

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/ptr"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
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

	repoMock.EXPECT().GetManagedPolicies(mock.Anything, true).Return(managedPolicies, nil).Once()
	repoMock.EXPECT().GetRoles(mock.Anything).Return(roles, nil).Once()

	return repoMock, syncer
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

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))
	feedbackHandler.EXPECT().AddAccessProviderFeedback("something", sync_to_target.AccessSyncFeedbackInformation{AccessId: "something", ActualName: "test_role", ExternalId: ptr.String(RoleTypePrefix + "test_role")})

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
						Permissions: []string{"p1", "p2"},
					},
				},
			},
		},
	}

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)
	repoMock.EXPECT().CreateRoleInlinePolicy(ctx, "test_role", "Raito_Inline_test_role", []awspolicy.Statement{{
		Effect: "Allow",
		Action: []string{"p1", "p2"},
		Resource: []string{
			"arn:aws:s3:::test_file",
		},
	}}).Return(nil).Once()

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))
	feedbackHandler.EXPECT().AddAccessProviderFeedback("something", sync_to_target.AccessSyncFeedbackInformation{AccessId: "something", ActualName: "test_role", ExternalId: ptr.String(RoleTypePrefix + "test_role")})

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
			},
		},
	}

	repoMock.EXPECT().CreateRole(ctx, "test_role", "a test role", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().CreateRole(ctx, "another_role", "another role", []string{"nick_n", "stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))
	feedbackHandler.EXPECT().AddAccessProviderFeedback("something", sync_to_target.AccessSyncFeedbackInformation{AccessId: "something", ActualName: "test_role", ExternalId: ptr.String(RoleTypePrefix + "test_role")})
	feedbackHandler.EXPECT().AddAccessProviderFeedback("another", sync_to_target.AccessSyncFeedbackInformation{AccessId: "another", ActualName: "another_role", ExternalId: ptr.String(RoleTypePrefix + "another_role")})

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

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))
	feedbackHandler.EXPECT().AddAccessProviderFeedback("something", sync_to_target.AccessSyncFeedbackInformation{AccessId: "something", ActualName: "data_engineering_sync", ExternalId: ptr.String(RoleTypePrefix + "data_engineering_sync")})

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

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

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
						Permissions: []string{"p1", "p2"},
					},
				},
			},
		},
	}

	repoMock.EXPECT().CreateManagedPolicy(ctx, "test_policy", []awspolicy.Statement{{
		Effect: "Allow",
		Action: []string{"p1", "p2"},
		Resource: []string{
			"arn:aws:s3:::test_file",
		},
	}}).Return(nil, nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)
	repoMock.EXPECT().GetPolicyArn("test_policy", mock.Anything).Return("arn:test_policy").Twice()
	repoMock.EXPECT().DeleteInlinePolicy(ctx, "inline1", "userke", UserResourceType).Return(nil).Once()
	repoMock.EXPECT().DeleteInlinePolicy(ctx, "inline2", "userke", UserResourceType).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:test_policy", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().AttachGroupToManagedPolicy(ctx, "arn:test_policy", []string{"g1"}).Return(nil).Once()

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))
	feedbackHandler.EXPECT().AddAccessProviderFeedback("something", sync_to_target.AccessSyncFeedbackInformation{AccessId: "something", ActualName: "test_policy", ExternalId: ptr.String(PolicyTypePrefix + "test_policy")})

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

	repoMock.EXPECT().CreateManagedPolicy(ctx, "test_policy", mock.Anything).Return(nil, nil).Once()
	repoMock.EXPECT().CreateManagedPolicy(ctx, "another_policy", mock.Anything).Return(nil, nil).Once()
	repoMock.EXPECT().GetPolicyArn("test_policy", mock.Anything).Return("arn:test_policy")
	repoMock.EXPECT().GetPolicyArn("another_policy", mock.Anything).Return("arn:another_policy").Twice()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:test_policy", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:another_policy", []string{"nick_n"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, "arn:another_policy", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))
	feedbackHandler.EXPECT().AddAccessProviderFeedback("something", sync_to_target.AccessSyncFeedbackInformation{AccessId: "something", ActualName: "test_policy", ExternalId: ptr.String(PolicyTypePrefix + "test_policy")})
	feedbackHandler.EXPECT().AddAccessProviderFeedback("another", sync_to_target.AccessSyncFeedbackInformation{AccessId: "another", ActualName: "another_policy", ExternalId: ptr.String(PolicyTypePrefix + "another_policy")})

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

	repoMock.EXPECT().CreateManagedPolicy(ctx, "p1", mock.Anything).Return(nil, nil).Once()
	repoMock.EXPECT().CreateManagedPolicy(ctx, "p2", mock.Anything).Return(nil, nil).Once()
	repoMock.EXPECT().CreateManagedPolicy(ctx, "p3", mock.Anything).Return(nil, nil).Once()
	repoMock.EXPECT().GetPolicyArn("p1", mock.Anything).Return("arn:p1")
	repoMock.EXPECT().GetPolicyArn("p2", mock.Anything).Return("arn:p2")
	repoMock.EXPECT().GetPolicyArn("p3", mock.Anything).Return("arn:p3")
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

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))
	feedbackHandler.EXPECT().AddAccessProviderFeedback("p1", sync_to_target.AccessSyncFeedbackInformation{AccessId: "p1", ActualName: "p1", ExternalId: ptr.String(PolicyTypePrefix + "p1")})
	feedbackHandler.EXPECT().AddAccessProviderFeedback("p2", sync_to_target.AccessSyncFeedbackInformation{AccessId: "p2", ActualName: "p2", ExternalId: ptr.String(PolicyTypePrefix + "p2")})
	feedbackHandler.EXPECT().AddAccessProviderFeedback("p3", sync_to_target.AccessSyncFeedbackInformation{AccessId: "p3", ActualName: "p3", ExternalId: ptr.String(PolicyTypePrefix + "p3")})
	feedbackHandler.EXPECT().AddAccessProviderFeedback("r1", sync_to_target.AccessSyncFeedbackInformation{AccessId: "r1", ActualName: "r1", ExternalId: ptr.String(RoleTypePrefix + "r1")})
	feedbackHandler.EXPECT().AddAccessProviderFeedback("r2", sync_to_target.AccessSyncFeedbackInformation{AccessId: "r2", ActualName: "r2", ExternalId: ptr.String(RoleTypePrefix + "r2")})

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

	repoMock.EXPECT().DeleteManagedPolicy(ctx, "HumanResourcesReadS3Policy").Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

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

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

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
