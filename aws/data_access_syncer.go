package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
)

type dataAccessRepository interface {
	GetManagedPolicies(ctx context.Context, withAttachedEntities bool) ([]PolicyEntity, error)
	CreateManagedPolicy(ctx context.Context, policyName string, statements []awspolicy.Statement) (*types.Policy, error)
	UpdateManagedPolicy(ctx context.Context, policyName string, awsManaged bool, statements []awspolicy.Statement) error
	DeleteManagedPolicy(ctx context.Context, policyName string, awsManaged bool) error
	CreateRoleInlinePolicy(ctx context.Context, roleName string, policyName string, statements []awspolicy.Statement) error
	DeleteRoleInlinePolicies(ctx context.Context, roleName string) error
	AttachUserToManagedPolicy(ctx context.Context, policyArn string, userNames []string) error
	AttachGroupToManagedPolicy(ctx context.Context, policyArn string, groupNames []string) error
	AttachRoleToManagedPolicy(ctx context.Context, policyArn string, roleNames []string) error
	DetachUserFromManagedPolicy(ctx context.Context, policyArn string, userNames []string) error
	DetachGroupFromManagedPolicy(ctx context.Context, policyArn string, groupNames []string) error
	DetachRoleFromManagedPolicy(ctx context.Context, policyArn string, roleNames []string) error
	GetUsers(ctx context.Context, withDetails bool) ([]UserEntity, error)
	GetGroups(ctx context.Context) ([]GroupEntity, error)
	GetRoles(ctx context.Context) ([]RoleEntity, error)
	CreateRole(ctx context.Context, name, description string, userNames []string) error
	DeleteRole(ctx context.Context, name string) error
	GetPrincipalsFromAssumeRolePolicyDocument(policyDocument *string) ([]string, error)
	UpdateAssumeEntities(ctx context.Context, roleName string, userNames []string) error
	// RemoveAssumeRole(ctx context.Context, configMap *config.ConfigMap, roleName string, userNames ...string) error
	GetInlinePoliciesForEntities(ctx context.Context, entityNames []string, entityType string) (map[string][]PolicyEntity, error)
	DeleteInlinePolicy(ctx context.Context, policyName, resourceName, resourceType string) error
	UpdateInlinePolicy(ctx context.Context, policyName, resourceName, resourceType string, statements []awspolicy.Statement) error
	GetAttachedEntity(ap sync_to_target.AccessProvider) (string, string, error)
	GetPolicyArn(policyName string, awsManaged bool, configMap *config.ConfigMap) string
	// processApInheritance(inheritanceMap map[string]set.Set[string], policyMap map[string]string, roleMap map[string]string,
	// 	newBindings *map[string]set.Set[PolicyBinding], existingBindings map[string]set.Set[PolicyBinding]) error
	// resolveInheritedApNames(exportedAps []*importer.AccessProvider, aps ...string) []string
}
type AccessSyncer struct {
	repo            dataAccessRepository
	managedPolicies []PolicyEntity
}

func NewDataAccessSyncer() *AccessSyncer {
	return &AccessSyncer{}
}
