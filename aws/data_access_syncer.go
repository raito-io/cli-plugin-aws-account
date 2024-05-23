package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/util/config"

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

type AccessSyncer struct {
	repo            dataAccessRepository
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
		return err
	}

	return nil
}
