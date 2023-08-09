package aws

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
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
		inlinePolicies:  nil,
	}

	roles, err := getObjects[RoleEntity]("testdata/aws/test_roles.json")
	require.Nil(t, err)
	managedPolicies, err := getObjects[PolicyEntity]("testdata/aws/test_managed_policies.json")
	require.Nil(t, err)

	repoMock.EXPECT().GetManagedPolicies(context.TODO(), true).Return(managedPolicies, nil).Once()
	repoMock.EXPECT().GetRoles(context.TODO()).Return(roles, nil).Once()

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

	repoMock.EXPECT().CreateRole(ctx, "test_role", "", []string{"stewart_b"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

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

	repoMock.EXPECT().UpdateAssumeEntities(ctx, "data_engineering_sync", []string{"stewart_b", "n_nguyen"}).Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

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
	// repoMock.AssertCalled(t, "DeleteRole")
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

/*
func TestSyncAccessProviderToTarget_NoInternalApRequiresNoProcessing(t *testing.T) {
	repo := newMockDataAccessRepository(t)

	syncer := &AccessSyncer{
		repoProvider: func() dataAccessRepository {
			return repo
		},
		managedPolicies: nil,
		inlinePolicies:  nil,
	}

	//When
	err := syncer.SyncAccessProviderToTarget(context.Background(), nil, nil, nil)

	// Then
	require.Nil(t, err)
	repo.AssertNotCalled(t, "GetRoles")
	repo.AssertNotCalled(t, "GetManagedPolicies")

	exportedAps := importer.AccessProviderImport{
		LastCalculated:  time.Now().Unix(),
		AccessProviders: []*importer.AccessProvider{},
	}

	//When
	err = syncer.SyncAccessProviderToTarget(context.Background(), &exportedAps, nil, nil)

	// Then
	require.Nil(t, err)
	repo.AssertNotCalled(t, "GetRoles")
	repo.AssertNotCalled(t, "GetManagedPolicies")
}

func TestSyncAccessProviderToTarget_CreatedNewManagedPolicy(t *testing.T) {
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := importer.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*importer.AccessProvider{
			{
				Id:          "something",
				Name:        "Test Access Provider",
				Description: "something",
				NamingHint:  "test_access_provider",
				Type:        aws.String(string(ManagedPolicy)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("test_access_provider"),
				What: []sync_to_target.WhatItem{
					{
						Permissions: []string{"ListBucket"},
						DataObject: &data_source.DataObjectReference{
							Type:     data_source.File,
							FullName: "s3://raito-data-usage/testfile.parquet",
						},
					},
				},
				Who: sync_to_target.WhoItem{
					Users: []string{"benjamin_stewart"},
				},
			},
		},
	}

	statements := []awspolicy.Statement{
		{
			Effect:   "Allow",
			Action:   []string{"s3:ListBucket"},
			Resource: []string{"arn:aws:s3:::s3://raito-data-usage/testfile.parquet"},
		},
	}
	repoMock.EXPECT().CreateManagedPolicy(ctx, &configmap, "test_access_provider", statements).Return(nil, nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything, &configmap, mock.Anything).Return([]string{}, nil)
	repoMock.EXPECT().GetPolicyArn("test_access_provider", &configmap).Return("dummy_arn").Twice()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, &configmap, "dummy_arn", []string{"benjamin_stewart"}).Return(nil).Once()

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

	// When
	err := syncer.SyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	// repoMock.AssertCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	// repoMock.AssertCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_DeleteManagedPolicy(t *testing.T) {
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := importer.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*importer.AccessProvider{
			{
				Id:          "something",
				Name:        "SalesReadS3Policy",
				Description: "something",
				Delete:      true,
				NamingHint:  "SalesReadS3Policy",
				Type:        aws.String(string(ManagedPolicy)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("SalesReadS3Policy"),
				What: []sync_to_target.WhatItem{
					{
						Permissions: []string{"GetObject"},
						DataObject: &data_source.DataObjectReference{
							Type:     data_source.File,
							FullName: "raito-operational-data/clean/Sales",
						},
					},
					{
						Permissions: []string{"GetObject"},
						DataObject: &data_source.DataObjectReference{
							Type:     data_source.File,
							FullName: "raito-operational-data/derived/sales_overview.parquet",
						},
					},
				},
				Who: sync_to_target.WhoItem{
					Users: []string{"benjamin_stewart"},
				},
			},
		},
	}

	// Detaching users happens under the hood
	repoMock.EXPECT().DeleteManagedPolicy(ctx, &configmap, "SalesReadS3Policy").Return(nil).Once()
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything, &configmap, mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

	// When
	err := syncer.SyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	repoMock.AssertNotCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	// repoMock.AssertCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	repoMock.AssertNotCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func TestSyncAccessProviderToTarget_DeleteNonExistingManagedPolicy(t *testing.T) {
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := importer.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*importer.AccessProvider{
			{
				Id:          "something",
				Name:        "SalesReadS3Policydkdkdkdkd",
				Description: "something",
				Delete:      true,
				NamingHint:  "SalesReadS3Policydkdkdkdkd",
				Type:        aws.String(string(ManagedPolicy)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("SalesReadS3Policydkdkdkdkd"),
			},
		},
	}

	// Detaching users happens under the hood
	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything, &configmap, mock.Anything).Return([]string{}, nil)

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

	// When
	err := syncer.SyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
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

func TestSyncAccessProviderToTarget_InternalizedInlinePolicyBecomesManagedPolicyWhenAddingWho(t *testing.T) {
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps := importer.AccessProviderImport{
		LastCalculated: time.Now().Unix(),
		AccessProviders: []*importer.AccessProvider{
			{
				Id:          "something",
				Name:        "Test Access Provider",
				Description: "something",
				NamingHint:  "test_access_provider",
				Type:        aws.String(string(InlinePolicyUser)),

				Action: sync_to_target.Grant,

				ActualName: aws.String("test_access_provider"),
				What: []sync_to_target.WhatItem{
					{
						Permissions: []string{"ListBucket"},
						DataObject: &data_source.DataObjectReference{
							Type:     data_source.File,
							FullName: "s3://raito-data-usage/testfile.parquet",
						},
					},
				},
				Who: sync_to_target.WhoItem{
					Users: []string{"benjamin_stewart", "dustin_hayden"},
				},
			},
		},
	}

	statements := []awspolicy.Statement{
		{
			Effect:   "Allow",
			Action:   []string{"s3:ListBucket"},
			Resource: []string{"arn:aws:s3:::s3://raito-data-usage/testfile.parquet"},
		},
	}

	repoMock.EXPECT().CreateManagedPolicy(ctx, &configmap, "test_access_provider", statements).Return(nil, nil).Once()

	repoMock.EXPECT().GetAttachedEntity(*exportedAps.AccessProviders[0]).Return("user1", "user", nil).Once()
	repoMock.EXPECT().DeleteInlinePolicy(ctx, &configmap, "test_access_provider", "user1", "user").Return(nil).Once()

	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything, &configmap, mock.Anything).Return([]string{}, nil)
	repoMock.EXPECT().GetPolicyArn("test_access_provider", &configmap).Return("dummy_arn").Twice()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, &configmap, "dummy_arn", []string{"benjamin_stewart"}).Return(nil).Once()
	repoMock.EXPECT().AttachUserToManagedPolicy(ctx, &configmap, "dummy_arn", []string{"dustin_hayden"}).Return(nil).Once()

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

	// When
	err := syncer.SyncAccessProviderToTarget(ctx, &exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	// repoMock.AssertCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	// repoMock.AssertCalled(t, "AttachUserToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	// repoMock.AssertNotCalled(t, "DeleteInlinePolicy")
}

func SyncAccessProviderToTarget_PolicyCannotBeTheWhoOfRole(t *testing.T) {

}

func TestSyncAccessProviderToTarget_ApInheritanceWorksAsExpected(t *testing.T) {
	repoMock, syncer := setupMockExportEnvironment(t)
	ctx := context.Background()
	configmap := config.ConfigMap{}
	configmap.Parameters = map[string]string{AwsAccountId: "123456"}

	exportedAps, err := getObject[importer.AccessProviderImport]("testdata/raito/test_ap_inheritance.json")
	require.Nil(t, err)

	repoMock.EXPECT().GetPrincipalsFromAssumeRolePolicyDocument(mock.Anything, &configmap, mock.Anything).Return([]string{}, nil)

	// RoleDataEngineer
	repoMock.On("CreateRole", ctx, &configmap, "RoleDataEngineer", "",
		mock.MatchedBy(func(userNames []string) bool {
			return elementsMatch(userNames, []string{"stewart_b", "jobs_de"})
		})).Return(nil).Once()
	repoMock.On("UpdateAssumeEntities", ctx, &configmap, "RoleDataEngineer",
		mock.MatchedBy(func(userNames []string) bool {
			return elementsMatch(userNames, []string{"stewart_b", "jobs_de"})
		})).Return(nil).Once()

	// RoleDataAnalyst
	repoMock.On("CreateRole", ctx, &configmap, "RoleDataAnalyst", "", mock.MatchedBy(func(userNames []string) bool {
		return elementsMatch(userNames, []string{"atkinson_a", "stewart_b", "jobs_de"})
	})).Return(nil).Once()
	repoMock.On("UpdateAssumeEntities", ctx, &configmap, "RoleDataAnalyst", mock.MatchedBy(func(userNames []string) bool {
		return elementsMatch(userNames, []string{"atkinson_a", "stewart_b", "jobs_de"})
	})).Return(nil).Once()

	// TestFileProvider
	statements := []awspolicy.Statement{
		{
			Effect:   "Allow",
			Action:   []string{"s3:ListBucket"},
			Resource: []string{"arn:aws:s3:::raito-operational-data"},
		},
	}
	repoMock.EXPECT().CreateManagedPolicy(ctx, &configmap, "TestFileProvider", statements).Return(nil, nil).Once()
	repoMock.EXPECT().GetPolicyArn("TestFileProvider", &configmap).Return("ARN_TestFileProvider").Twice()
	repoMock.On("AttachUserToManagedPolicy", ctx, &configmap, "ARN_TestFileProvider", []string{"jobs_de"}).Return(nil).Once()
	repoMock.On("AttachUserToManagedPolicy", ctx, &configmap, "ARN_TestFileProvider", []string{"stewart_b"}).Return(nil).Once()
	repoMock.On("AttachGroupToManagedPolicy", ctx, &configmap, "ARN_TestFileProvider", []string{"data_engineer"}).Return(nil).Once()
	repoMock.On("AttachGroupToManagedPolicy", ctx, &configmap, "ARN_TestFileProvider", []string{"data_analyst"}).Return(nil).Once()
	repoMock.On("AttachRoleToManagedPolicy", ctx, &configmap, "ARN_TestFileProvider", []string{"RoleDataAnalyst"}).Return(nil).Once()
	repoMock.On("AttachRoleToManagedPolicy", ctx, &configmap, "ARN_TestFileProvider", []string{"RoleDataEngineer"}).Return(nil).Once()

	// TestProvider
	statements = []awspolicy.Statement{
		{
			Effect:   "Allow",
			Action:   []string{"s3:GetBucketLocation"},
			Resource: []string{"arn:aws:s3:::raito-operational-data"},
		},
	}
	repoMock.EXPECT().CreateManagedPolicy(ctx, &configmap, "TestProvider", statements).Return(nil, nil).Once()
	repoMock.EXPECT().GetPolicyArn("TestProvider", &configmap).Return("ARN_TestProvider").Twice()
	repoMock.On("AttachUserToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"jobs_de"}).Return(nil).Once()
	repoMock.On("AttachUserToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"stewart_b"}).Return(nil).Once()
	repoMock.On("AttachGroupToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"marketing"}).Return(nil).Once()
	repoMock.On("AttachGroupToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"human_resources"}).Return(nil).Once()
	repoMock.On("AttachGroupToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"finance"}).Return(nil).Once()
	repoMock.On("AttachGroupToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"sales"}).Return(nil).Once()
	repoMock.On("AttachGroupToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"data_engineer"}).Return(nil).Once()
	repoMock.On("AttachGroupToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"data_analyst"}).Return(nil).Once()
	repoMock.On("AttachRoleToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"RoleDataAnalyst"}).Return(nil).Once()
	repoMock.On("AttachRoleToManagedPolicy", ctx, &configmap, "ARN_TestProvider", []string{"RoleDataEngineer"}).Return(nil).Once()

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(t, len(exportedAps.AccessProviders))

	// When
	err = syncer.SyncAccessProviderToTarget(ctx, exportedAps, feedbackHandler, &configmap)
	require.Nil(t, err)

	// Then
	repoMock.AssertNotCalled(t, "GetPrincipalsFromAssumeRolePolicyDocument")
	repoMock.AssertNotCalled(t, "GetAttachedEntity")
	// repoMock.AssertNotCalled(t, "CreateRole")
	repoMock.AssertNotCalled(t, "DeleteRole")
	repoMock.AssertNotCalled(t, "UpdateAssumeEntities")
	// repoMock.AssertCalled(t, "CreateManagedPolicy")
	repoMock.AssertNotCalled(t, "UpdateManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteManagedPolicy")
	repoMock.AssertNotCalled(t, "GetPolicyArn")
	// repoMock.AssertCalled(t, "AttachUserToManagedPolicy")
	// repoMock.AssertNotCalled(t, "AttachGroupToManagedPolicy")
	// repoMock.AssertNotCalled(t, "AttachRoleToManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachUserFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachGroupFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DetachRoleFromManagedPolicy")
	repoMock.AssertNotCalled(t, "DeleteInlinePolicy")

}

func contains(element string, list []string) bool {
	for _, el := range list {
		if el == element {
			return true
		}
	}
	return false
}

func elementsMatch(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		diff[_x]++
	}
	for _, _y := range y {
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y] -= 1
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	return len(diff) == 0
}*/
