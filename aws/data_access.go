package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/smithy-go/ptr"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"
)

//go:generate go run github.com/vektra/mockery/v2 --name=dataAccessRepository --with-expecter --inpackage
type dataAccessRepository interface {
	GetManagedPolicies(ctx context.Context, configMap *config.ConfigMap, withAttachedEntities bool) ([]PolicyEntity, error)
	CreateManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyName string, statements []awspolicy.Statement) (*types.Policy, error)
	UpdateManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyName string, statements []awspolicy.Statement) error
	DeleteManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyName string) error
	AttachUserToManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, userNames []string) error
	AttachGroupToManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, groupNames []string) error
	AttachRoleToManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, roleNames []string) error
	DetachUserFromManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, userNames []string) error
	DetachGroupFromManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, groupNames []string) error
	DetachRoleFromManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, roleNames []string) error
	GetUsers(ctx context.Context, configMap *config.ConfigMap, withDetails bool) ([]UserEntity, error)
	GetGroups(ctx context.Context, configMap *config.ConfigMap, withDetails bool) ([]GroupEntity, error)
	GetRoles(ctx context.Context, configMap *config.ConfigMap) ([]RoleEntity, error)
	CreateRole(ctx context.Context, configMap *config.ConfigMap, name, description string, userNames []string) error
	DeleteRole(ctx context.Context, configMap *config.ConfigMap, name string) error
	GetPrincipalsFromAssumeRolePolicyDocument(ctx context.Context, configMap *config.ConfigMap, policyDocument *string) ([]string, error)
	UpdateAssumeEntities(ctx context.Context, configMap *config.ConfigMap, roleName string, userNames []string) error
	// RemoveAssumeRole(ctx context.Context, configMap *config.ConfigMap, roleName string, userNames ...string) error
	GetInlinePoliciesForEntities(ctx context.Context, configMap *config.ConfigMap, entityNames []string, entityType string) ([]PolicyEntity, error)
	DeleteInlinePolicy(ctx context.Context, configMap *config.ConfigMap, policyName, resourceName, resourceType string) error
	UpdateInlinePolicy(ctx context.Context, configMap *config.ConfigMap, policyName, resourceName, resourceType string, statements []awspolicy.Statement) error
	GetAttachedEntity(ap sync_to_target.AccessProvider) (string, string, error)
	GetPolicyArn(policyName string, configMap *config.ConfigMap) string
	// processApInheritance(inheritanceMap map[string]set.Set[string], policyMap map[string]string, roleMap map[string]string,
	// 	newBindings *map[string]set.Set[PolicyBinding], existingBindings map[string]set.Set[PolicyBinding]) error
	// getApNames(exportedAps []*importer.AccessProvider, aps ...string) []string
}

type AccessSyncer struct {
	repoProvider    func() dataAccessRepository
	managedPolicies []PolicyEntity
	inlinePolicies  []PolicyEntity
}

func NewDataAccessSyncer() *AccessSyncer {
	return &AccessSyncer{
		repoProvider: newDataAccessRepo,
	}
}

func newDataAccessRepo() dataAccessRepository {
	return &AwsIamRepository{}
}

const (
	CreateAction string = "create"
	UpdateAction string = "update"
	DeleteAction string = "delete"
)

func (a *AccessSyncer) SyncAccessProvidersFromTarget(ctx context.Context, accessProviderHandler wrappers.AccessProviderHandler, configMap *config.ConfigMap) error {
	apImportList, err := a.fetchAllAccessProviders(ctx, configMap)
	if err != nil {
		return err
	}

	filteredList := filterApImportList(apImportList)
	// import of an AP fails if any of the access providers in the 'who' are missing
	// re-add those (roles), even if they have been excluded before
	filteredListWithChildren := addChildren(filteredList, apImportList)
	// only re-add inline role policies, for roles that are going to be imported
	filteredListWithChildrenAndInlineRolePolicies := addRoleInlinePolicies(filteredListWithChildren, apImportList)

	err = newRoleEnricher(ctx, configMap).enrich(filteredListWithChildrenAndInlineRolePolicies)
	if err != nil {
		return err
	}

	err = accessProviderHandler.AddAccessProviders(getProperFormatForImport(filteredListWithChildrenAndInlineRolePolicies)...)

	return err
}

func (a *AccessSyncer) fetchAllAccessProviders(ctx context.Context, configMap *config.ConfigMap) ([]AccessProviderInputExtended, error) {
	repo := a.repoProvider()

	apImportList := []AccessProviderInputExtended{}

	logger.Info("Get all roles")
	roles, err := repo.GetRoles(ctx, configMap)

	if err != nil {
		return nil, err
	}

	for _, role := range roles {
		roleName := fmt.Sprintf("%s%s", RolePrefix, role.Name)

		userNames := []string{}

		apImportList = append(apImportList, AccessProviderInputExtended{
			LastUsedDate: role.LastUsedDate,
			PolicyType:   Role,
			ApInput: &sync_from_target.AccessProvider{
				ExternalId: role.Id,
				Name:       roleName,
				ActualName: roleName,
				NamingHint: roleName,
				Type:       aws.String(string(Role)),
				Action:     sync_from_target.Grant,
				Policy:     "",
				Who: &sync_from_target.WhoItem{
					// Groups:          groupBindings,
					Users: userNames,
				},
				What:             []sync_from_target.WhatItem{},
				WhatLocked:       aws.Bool(true),
				WhatLockedReason: aws.String("AWS Role cannot have a What"),
			}})
	}

	logger.Info("Get all managed policies")
	policies, err := repo.GetManagedPolicies(ctx, configMap, true)

	if err != nil {
		return nil, err
	}

	if policies == nil {
		return nil, err
	}

	for ind := range policies {
		policy := policies[ind]

		isAWSManaged := strings.HasPrefix(policy.ARN, "arn:aws:iam::aws:")

		groupBindings := []string{}
		userBindings := []string{}
		roleBindings := []string{}

		for _, tag := range policy.Tags {
			if tag.Key == "creator" && tag.Value == "raito" {
				// TODO, shouldn't we return here (see log message)?
				logger.Info(fmt.Sprintf("%s is raito policy, skipping import", policy.Name))
			}
		}

		for _, groupBinding := range policy.GroupBindings {
			groupBindings = append(groupBindings, groupBinding.ResourceName)
		}

		for _, userBinding := range policy.UserBindings {
			userBindings = append(userBindings, userBinding.ResourceName)
		}

		for _, roleBinding := range policy.RoleBindings {
			roleBindings = append(roleBindings, fmt.Sprintf("%s%s", RolePrefix, roleBinding.ResourceName))
		}

		if len(groupBindings) == 0 && len(userBindings) == 0 && len(roleBindings) == 0 {
			logger.Info(fmt.Sprintf("Skipping managed policy %s, no user/group/role bindings", policy.Name))
			continue
		}

		var localErr error

		whatItems, incomplete, localErr := CreateWhatFromPolicyDocument(policy.Name, policy.PolicyParsed, configMap)
		if localErr != nil {
			return nil, localErr
		}

		apInput := sync_from_target.AccessProvider{
			ExternalId: policy.Id,
			Name:       policy.Name,
			ActualName: policy.Name,
			Type:       aws.String(string(ManagedPolicy)),
			NamingHint: fmt.Sprintf("%s%s", ManagedPrefix, policy.Name),
			Action:     sync_from_target.Grant,
			Policy:     "",
			Who: &sync_from_target.WhoItem{
				Groups:          groupBindings,
				Users:           userBindings,
				AccessProviders: roleBindings,
			},
			What:       whatItems,
			Incomplete: ptr.Bool(incomplete),
		}

		if isAWSManaged {
			apInput.WhatLocked = aws.Bool(true)
			apInput.WhatLockedReason = aws.String("This policy is managed by AWS")
			apInput.NameLocked = aws.Bool(true)
			apInput.NameLockedReason = aws.String("This policy is managed by AWS")
			apInput.DeleteLocked = aws.Bool(true)
			apInput.DeleteLockedReason = aws.String("This policy is managed by AWS")
		}

		apImportList = append(apImportList, AccessProviderInputExtended{
			ApInput: &apInput})
	}

	logger.Info("Get all inline policies")

	inlinePolicies, err := a.GetAllInlinePolicies(ctx, configMap, repo, roles)
	if err != nil {
		return nil, err
	}

	for ind := range inlinePolicies {
		policy := inlinePolicies[ind]

		var inlinePolicyName string

		userNames := []string{}
		for _, binding := range policy.UserBindings {
			userNames = append(userNames, binding.ResourceName)
			inlinePolicyName = fmt.Sprintf("/inline/user/%s/%s", binding.ResourceName, policy.Name)
		}

		groupNames := []string{}
		for _, binding := range policy.GroupBindings {
			groupNames = append(groupNames, binding.ResourceName)
			inlinePolicyName = fmt.Sprintf("/inline/group/%s/%s", binding.ResourceName, policy.Name)
		}

		roleNames := []string{}

		for _, binding := range policy.RoleBindings {
			roleName := fmt.Sprintf("%s%s", RolePrefix, binding.ResourceName)
			roleNames = append(roleNames, roleName)
			inlinePolicyName = fmt.Sprintf("/inline/role/%s/%s", binding.ResourceName, policy.Name)
		}

		whatItems, incomplete, err := CreateWhatFromPolicyDocument(inlinePolicyName, policy.PolicyParsed, configMap)
		if err != nil {
			logger.Error(fmt.Sprintf("error calculating access from policy document: %s", err.Error()))
			return nil, err
		}

		fullName := *policy.InlineParent + "/" + policy.Name
		logger.Info(fmt.Sprintf("Adding inline policy %q from parent %q with external id %q", policy.Name, *policy.InlineParent, fullName))

		apImportList = append(apImportList, AccessProviderInputExtended{
			InlineParent: policy.InlineParent,
			PolicyType:   policy.PolicyType,
			ApInput: &sync_from_target.AccessProvider{
				// As internal policies don't have an ID we use the policy ARN
				ExternalId: fullName,
				Name:       fullName,
				Type:       aws.String(string(policy.PolicyType)),
				NamingHint: inlinePolicyName,
				ActualName: inlinePolicyName,
				Action:     sync_from_target.Grant,
				Policy:     *policy.PolicyDocument,
				Who: &sync_from_target.WhoItem{
					Groups:          groupNames,
					Users:           userNames,
					AccessProviders: roleNames,
				},
				What:       whatItems,
				Incomplete: ptr.Bool(incomplete),
			}})
	}

	return apImportList, nil
}

func (a *AccessSyncer) GetAllInlinePolicies(ctx context.Context, configMap *config.ConfigMap, repo dataAccessRepository, roles []RoleEntity) ([]PolicyEntity, error) {
	logger.Info("Get inline policies from groups")
	groups, err := repo.GetGroups(ctx, configMap, false)

	if err != nil {
		return nil, err
	}

	groupNames := []string{}
	for _, g := range groups {
		groupNames = append(groupNames, g.Name)
	}

	groupInlinePolicies, err := repo.GetInlinePoliciesForEntities(ctx, configMap, groupNames, "group")
	if err != nil {
		return nil, err
	}

	logger.Info("Get inline policies from users")

	users, err := repo.GetUsers(ctx, configMap, false)
	if err != nil {
		return nil, err
	}

	userNames := []string{}
	for _, u := range users {
		userNames = append(userNames, u.Name)
	}

	userInlinePolicies, err := repo.GetInlinePoliciesForEntities(ctx, configMap, userNames, "user")
	if err != nil {
		return nil, err
	}

	for ind := range userInlinePolicies {
		inlinePolicy := userInlinePolicies[ind]
		logger.Info(fmt.Sprintf("Tags for inline policy %s: %v", inlinePolicy.Name, inlinePolicy.Tags))
	}

	logger.Info("Get inline policies from roles")

	if len(roles) == 0 {
		roles, err = repo.GetRoles(ctx, configMap)
		if err != nil {
			return nil, err
		}
	}

	roleNames := []string{}
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	roleInlinePolicies, err := repo.GetInlinePoliciesForEntities(ctx, configMap, roleNames, "role")
	if err != nil {
		return nil, err
	}

	inlinePolicies := userInlinePolicies
	inlinePolicies = append(inlinePolicies, groupInlinePolicies...)
	inlinePolicies = append(inlinePolicies, roleInlinePolicies...)

	return inlinePolicies, nil
}

func getProperFormatForImport(input []AccessProviderInputExtended) []*sync_from_target.AccessProvider {
	result := []*sync_from_target.AccessProvider{}
	for _, ap := range input {
		result = append(result, ap.ApInput)
	}

	return result
}

func addRoleInlinePolicies(filteredList, fullList []AccessProviderInputExtended) []AccessProviderInputExtended {
	inlineParentMap := map[string]*AccessProviderInputExtended{}

	for ind := range fullList {
		if fullList[ind].ApInput != nil && isInlinePolicy(fullList[ind]) && fullList[ind].InlineParent != nil {
			inlineParentMap[fmt.Sprintf("%s%s", RolePrefix, *fullList[ind].InlineParent)] = &fullList[ind]
		}
	}

	for _, ap := range filteredList {
		if ap.PolicyType == Role {
			logger.Debug(fmt.Sprintf("Checking inline policy for role '%s'", ap.ApInput.Name))

			if _, found := inlineParentMap[ap.ApInput.Name]; found {
				filteredList = append(filteredList, *inlineParentMap[ap.ApInput.Name])
			}
		}
	}

	return filteredList
}

func isInlinePolicy(policy AccessProviderInputExtended) bool {
	if policy.PolicyType == InlinePolicyUser || policy.PolicyType == InlinePolicyGroup || policy.PolicyType == InlinePolicyRole {
		return true
	}

	return false
}

func addChildren(filteredList, fullList []AccessProviderInputExtended) []AccessProviderInputExtended {
	result := []AccessProviderInputExtended{}

	rolesMap := map[string]AccessProviderInputExtended{}

	for ind := range fullList {
		if fullList[ind].ApInput != nil && strings.HasPrefix(fullList[ind].ApInput.NamingHint, RolePrefix) {
			rolesMap[fullList[ind].ApInput.Name] = fullList[ind]
		}
	}

	filteredMap := map[string]bool{}

	for ind := range filteredList {
		if filteredList[ind].ApInput != nil {
			filteredMap[filteredList[ind].ApInput.Name] = true
		}
	}

	for ind := range filteredList {
		result = append(result, filteredList[ind])

		ap := filteredList[ind].ApInput

		if ap.Who == nil || len(ap.Who.AccessProviders) == 0 {
			continue
		}

		for _, descendant := range ap.Who.AccessProviders {
			if _, found := filteredMap[descendant]; found {
				continue
			}

			result = append(result, rolesMap[descendant])
			filteredMap[descendant] = true
		}
	}

	return result
}

func (a *AccessSyncer) SyncAccessAsCodeToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, prefix string, configMap *config.ConfigMap) error {
	return nil
}
