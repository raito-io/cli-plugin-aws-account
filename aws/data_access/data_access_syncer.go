package data_access

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/repo"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
)

//go:generate go run github.com/vektra/mockery/v2 --name=dataAccessRepository --with-expecter --inpackage

type dataAccessRepository interface {
	GetManagedPolicies(ctx context.Context) ([]model.PolicyEntity, error)
	CreateManagedPolicy(ctx context.Context, policyName string, statements []*awspolicy.Statement) (*types.Policy, error)
	UpdateManagedPolicy(ctx context.Context, policyName string, awsManaged bool, statements []*awspolicy.Statement) error
	DeleteManagedPolicy(ctx context.Context, policyName string, awsManaged bool) error
	CreateRoleInlinePolicy(ctx context.Context, roleName string, policyName string, statements []*awspolicy.Statement) error
	DeleteRoleInlinePolicies(ctx context.Context, roleName string) error
	AttachUserToManagedPolicy(ctx context.Context, policyArn string, userNames []string) error
	AttachGroupToManagedPolicy(ctx context.Context, policyArn string, groupNames []string) error
	AttachRoleToManagedPolicy(ctx context.Context, policyArn string, roleNames []string) error
	DetachUserFromManagedPolicy(ctx context.Context, policyArn string, userNames []string) error
	DetachGroupFromManagedPolicy(ctx context.Context, policyArn string, groupNames []string) error
	DetachRoleFromManagedPolicy(ctx context.Context, policyArn string, roleNames []string) error
	GetUsers(ctx context.Context, withDetails bool) ([]model.UserEntity, error)
	GetGroups(ctx context.Context) ([]model.GroupEntity, error)
	GetRoles(ctx context.Context) ([]model.RoleEntity, error)
	CreateRole(ctx context.Context, name, description string, userNames []string) (bool, error)
	DeleteRole(ctx context.Context, name string) error
	UpdateAssumeEntities(ctx context.Context, roleName string, userNames []string) error
	GetInlinePoliciesForEntities(ctx context.Context, entityNames []string, entityType string) (map[string][]model.PolicyEntity, error)
	ListAccessPoints(ctx context.Context, region string) ([]model.AwsS3AccessPoint, error)
	DeleteInlinePolicy(ctx context.Context, policyName, resourceName, resourceType string) error
	UpdateInlinePolicy(ctx context.Context, policyName, resourceName, resourceType string, statements []*awspolicy.Statement) error
	GetPolicyArn(policyName string, awsManaged bool, configMap *config.ConfigMap) string
	CreateAccessPoint(ctx context.Context, name, bucket string, region string, statements []*awspolicy.Statement) error
	UpdateAccessPoint(ctx context.Context, name string, region string, statements []*awspolicy.Statement) error
	DeleteAccessPoint(ctx context.Context, name string, region string) error
}

type dataAccessSsoRepository interface {
	GetSsoRole(ctx context.Context, permissionSetArn string) (*ssoTypes.PermissionSet, error)
	CreateSsoRole(ctx context.Context, name, description string) (arn string, err error)
	UpdateSsoRole(ctx context.Context, arn string, description string) error
	DeleteSsoRole(ctx context.Context, permissionSetArn string) error
	AssignPermissionSet(ctx context.Context, permissionSetArn string, principalType ssoTypes.PrincipalType, principal string) error
	UnassignPermissionSet(ctx context.Context, permissionSetArn string, principalType ssoTypes.PrincipalType, principal string) error
	ProvisionPermissionSet(ctx context.Context, permissionSetArn string) error
	AttachAwsManagedPolicyToPermissionSet(ctx context.Context, permissionSetArn string, policyArn string) error
	DetachAwsManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string, policyArn string) error
	ListAwsManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string) (set.Set[string], error)
	AttachCustomerManagedPolicyToPermissionSet(ctx context.Context, permissionSetArn string, name string, path *string) error
	DetachCustomerManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string, name string, path *string) error
	ListCustomerManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string) (set.Set[string], error)
	UpdateInlinePolicyToPermissionSet(ctx context.Context, permissionSetArn string, statements []*awspolicy.Statement) error
}

type AccessSyncer struct {
	repo            dataAccessRepository
	ssoRepo         dataAccessSsoRepository
	account         string
	managedPolicies []model.PolicyEntity
	userGroupMap    map[string][]string
}

func NewDataAccessSyncer() *AccessSyncer {
	return &AccessSyncer{}
}

func NewDataAccessSyncerFromConfig(configMap *config.ConfigMap) *AccessSyncer {
	as := &AccessSyncer{}

	err := as.initialize(context.Background(), configMap)

	if err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to initialize AccessSyncer: %s", err.Error()))
		return nil
	}

	return as
}

func (a *AccessSyncer) initialize(ctx context.Context, configMap *config.ConfigMap) error {
	a.repo = iam.NewAwsIamRepository(configMap)

	var err error

	a.account, err = repo.GetAccountId(ctx, configMap)
	if err != nil {
		return fmt.Errorf("get account id: %w", err)
	}

	instanceArn := configMap.GetStringWithDefault(constants.AwsOrganizationIdentityCenterInstanceArn, "")
	if instanceArn != "" {
		a.ssoRepo, err = iam.NewSsoClient(ctx, configMap, a.account)
		if err != nil {
			utils.Logger.Error(fmt.Sprintf("Error while setting up iam SSO admin client: %s", err.Error()))
		}
	}

	return nil
}
