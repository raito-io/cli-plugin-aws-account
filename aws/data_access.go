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
	GetInlinePoliciesForEntities(ctx context.Context, configMap *config.ConfigMap, entityNames []string, entityType string) (map[string][]PolicyEntity, error)
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

	logger.Info(fmt.Sprintf("Keeping %d acces providers after filtering", len(filteredList)))

	err = newRoleEnricher(ctx, configMap).enrich(filteredList)
	if err != nil {
		return err
	}

	err = accessProviderHandler.AddAccessProviders(getProperFormatForImport(filteredList)...)

	return err
}

func filterApImportList(importList []AccessProviderInputExtended) []AccessProviderInputExtended {
	toKeep := map[string]struct{}{}
	logger.Debug("Start filtering for relevant access providers")

	for _, apInput := range importList {
		if apInput.PolicyType == Role || apInput.PolicyType == SSORole {
			// Elements in the WHAT here already means that there are relevant permissions
			if len(apInput.ApInput.What) > 0 {
				logger.Debug(fmt.Sprintf("Keeping role %q", apInput.ApInput.ActualName))

				toKeep[apInput.ApInput.ActualName] = struct{}{}
			} else {
				logger.Debug(fmt.Sprintf("SKipping role %q as it has no WHAT elements", apInput.ApInput.ActualName))
			}

			continue
		} else if apInput.PolicyType == Policy {
			// TODO hard-coded S3 now, but needs to be extended to other services later
			hasS3Actions := false

			if apInput.ApInput.What != nil && len(apInput.ApInput.What) > 0 {
				for _, whatItem := range apInput.ApInput.What {
					for _, permission := range whatItem.Permissions {
						if permission == "*" || strings.HasPrefix(permission, "s3:") {
							hasS3Actions = true
							break
						}
					}

					if hasS3Actions {
						break
					}
				}
			}

			if hasS3Actions {
				logger.Debug(fmt.Sprintf("Keeping policy %q", apInput.ApInput.ActualName))
				toKeep[apInput.ApInput.ActualName] = struct{}{}

				for _, who := range apInput.ApInput.Who.AccessProviders {
					logger.Debug(fmt.Sprintf("Re-adding role %q", who))
					toKeep[who] = struct{}{}
				}
			} else {
				logger.Debug(fmt.Sprintf("Skipping policy %q as it has no relevant permissions/resources", apInput.ApInput.ActualName))
			}
		}
	}

	result := make([]AccessProviderInputExtended, 0, len(toKeep))
	for _, apInput := range importList {
		if _, ok := toKeep[apInput.ApInput.ActualName]; ok {
			result = append(result, apInput)
		}
	}

	return result
}

func (a *AccessSyncer) fetchRoleAccessProviders(ctx context.Context, configMap *config.ConfigMap, repo dataAccessRepository, aps []AccessProviderInputExtended) ([]AccessProviderInputExtended, error) {
	logger.Info("Get all roles")
	roles, err := repo.GetRoles(ctx, configMap)

	if err != nil {
		return nil, err
	}

	for _, role := range roles {
		roleName := fmt.Sprintf("%s%s", RolePrefix, role.Name)

		userNames := []string{}

		aps = append(aps, AccessProviderInputExtended{
			LastUsedDate: role.LastUsedDate,
			PolicyType:   Role,
			ApInput: &sync_from_target.AccessProvider{
				ExternalId: role.Id,
				Name:       role.Name,
				ActualName: roleName,
				NamingHint: roleName,
				Type:       aws.String(string(Role)),
				Action:     sync_from_target.Grant,
				Policy:     "",
				Who: &sync_from_target.WhoItem{
					// Groups:          groupBindings,
					Users: userNames,
				},
				What: []sync_from_target.WhatItem{},
			}})
	}

	return aps, nil
}

func (a *AccessSyncer) fetchManagedPolicyAccessProviders(ctx context.Context, configMap *config.ConfigMap, repo dataAccessRepository, aps []AccessProviderInputExtended) ([]AccessProviderInputExtended, error) {
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

		logger.Info(fmt.Sprintf("Handling managed policy %q", policy.Name))

		isAWSManaged := strings.HasPrefix(policy.ARN, "arn:aws:iam::aws:")

		var groupBindings []string
		var userBindings []string
		var roleBindings []string

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

		whatItems, incomplete := createWhatFromPolicyDocument(policy.PolicyParsed, policy.Name, configMap)

		policyDocument := ""
		if policy.PolicyDocument != nil {
			policyDocument = *policy.PolicyDocument
		}

		apInput := sync_from_target.AccessProvider{
			ExternalId: policy.Id,
			Name:       policy.Name,
			ActualName: policy.Name,
			Type:       aws.String(string(Policy)),
			NamingHint: fmt.Sprintf("%s%s", ManagedPrefix, policy.Name),
			Action:     sync_from_target.Grant,
			Policy:     policyDocument,
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

		aps = append(aps, AccessProviderInputExtended{
			PolicyType: Policy,
			ApInput:    &apInput,
		})
	}

	return aps, nil
}

func convertPoliciesToWhat(policies []PolicyEntity, configMap *config.ConfigMap) ([]sync_from_target.WhatItem, bool, string) {
	var whatItems []sync_from_target.WhatItem
	incomplete := false
	policyDocuments := ""

	for i := range policies {
		policy := policies[i]
		policyWhat, policyIncomplete := createWhatFromPolicyDocument(policy.PolicyParsed, policy.Name, configMap)

		if policy.PolicyDocument != nil {
			policyDocuments += *policy.PolicyDocument + "\n"
		}

		for _, what := range policyWhat {
			if len(what.Permissions) > 0 && what.DataObject != nil {
				whatItems = append(whatItems, what)
			}
		}

		if policyIncomplete {
			incomplete = true
		}
	}

	return whatItems, incomplete, policyDocuments
}

func (a *AccessSyncer) fetchInlinePolicyAccessProviders(ctx context.Context, configMap *config.ConfigMap, repo dataAccessRepository, aps []AccessProviderInputExtended) ([]AccessProviderInputExtended, error) {
	userPolicies, err := a.getInlinePoliciesOnUsers(ctx, configMap, repo)
	if err != nil {
		return nil, err
	}

	for user, policies := range userPolicies {
		whatItems, incomplete, policyDocuments := convertPoliciesToWhat(policies, configMap)

		name := "User " + user + " inline policies"

		aps = append(aps, AccessProviderInputExtended{
			PolicyType: Policy,
			ApInput: &sync_from_target.AccessProvider{
				// As internal policies don't have an ID we use the policy ARN
				ExternalId: name,
				Name:       name,
				Type:       aws.String(string(Policy)),
				NamingHint: "",
				ActualName: name,
				Action:     sync_from_target.Grant,
				Policy:     policyDocuments,
				Who: &sync_from_target.WhoItem{
					Users: []string{user},
				},
				What:       whatItems,
				Incomplete: ptr.Bool(incomplete),
			}})
	}

	groupPolicies, err := a.getInlinePoliciesOnGroups(ctx, configMap, repo)
	if err != nil {
		return nil, err
	}

	for group, policies := range groupPolicies {
		whatItems, incomplete, policyDocuments := convertPoliciesToWhat(policies, configMap)

		name := "Group " + group + " inline policies"

		aps = append(aps, AccessProviderInputExtended{
			PolicyType: Policy,
			ApInput: &sync_from_target.AccessProvider{
				// As internal policies don't have an ID we use the policy ARN
				ExternalId: name,
				Name:       name,
				Type:       aws.String(string(Policy)),
				NamingHint: "",
				ActualName: name,
				Action:     sync_from_target.Grant,
				Policy:     policyDocuments,
				Who: &sync_from_target.WhoItem{
					Groups: []string{group},
				},
				What:       whatItems,
				Incomplete: ptr.Bool(incomplete),
			}})
	}

	rolePolicies, err := a.getInlinePoliciesOnRoles(ctx, configMap, repo)
	if err != nil {
		return nil, err
	}

	for role, policies := range rolePolicies {

		var roleAp *sync_from_target.AccessProvider

		for _, ap := range aps {
			if ap.PolicyType == Role && ap.ApInput.Name == role {
				roleAp = ap.ApInput
			}
		}

		if roleAp == nil {
			logger.Error(fmt.Sprintf("Could not find role %q", role))
			continue
		}

		whatItems, incomplete, policyDocuments := convertPoliciesToWhat(policies, configMap)

		roleAp.Policy = policyDocuments
		roleAp.What = whatItems
		roleAp.Incomplete = ptr.Bool(incomplete || (roleAp.Incomplete != nil && *roleAp.Incomplete))
	}

	return aps, nil
}

func (a *AccessSyncer) fetchAllAccessProviders(ctx context.Context, configMap *config.ConfigMap) ([]AccessProviderInputExtended, error) {
	repo := a.repoProvider()

	var apImportList []AccessProviderInputExtended

	// Adding access providers to the list for the roles
	apImportList, err := a.fetchRoleAccessProviders(ctx, configMap, repo, apImportList)
	if err != nil {
		return nil, err
	}

	// Adding access providers to the list for the managed policies
	apImportList, err = a.fetchManagedPolicyAccessProviders(ctx, configMap, repo, apImportList)
	if err != nil {
		return nil, err
	}

	// Adding access providers to the list for the inline policies (existing role access providers will be enriched with inline policies it may have)
	apImportList, err = a.fetchInlinePolicyAccessProviders(ctx, configMap, repo, apImportList)
	if err != nil {
		return nil, err
	}

	return apImportList, nil
}

func (a *AccessSyncer) getInlinePoliciesOnGroups(ctx context.Context, configMap *config.ConfigMap, repo dataAccessRepository) (map[string][]PolicyEntity, error) {
	logger.Info("Get inline policies from groups")
	groups, err := repo.GetGroups(ctx, configMap, false)

	if err != nil {
		return nil, err
	}

	groupNames := []string{}
	for _, g := range groups {
		groupNames = append(groupNames, g.Name)
	}

	return repo.GetInlinePoliciesForEntities(ctx, configMap, groupNames, "group")
}
func (a *AccessSyncer) getInlinePoliciesOnUsers(ctx context.Context, configMap *config.ConfigMap, repo dataAccessRepository) (map[string][]PolicyEntity, error) {
	logger.Info("Get inline policies from users")

	users, err := repo.GetUsers(ctx, configMap, false)
	if err != nil {
		return nil, err
	}

	userNames := []string{}
	for _, u := range users {
		userNames = append(userNames, u.Name)
	}

	return repo.GetInlinePoliciesForEntities(ctx, configMap, userNames, "user")
}

func (a *AccessSyncer) getInlinePoliciesOnRoles(ctx context.Context, configMap *config.ConfigMap, repo dataAccessRepository) (map[string][]PolicyEntity, error) {
	logger.Info("Get inline policies from roles")

	roles, err := repo.GetRoles(ctx, configMap)
	if err != nil {
		return nil, err
	}

	roleNames := []string{}
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	return repo.GetInlinePoliciesForEntities(ctx, configMap, roleNames, "role")
}

func getProperFormatForImport(input []AccessProviderInputExtended) []*sync_from_target.AccessProvider {
	result := []*sync_from_target.AccessProvider{}

	for _, ap := range input {
		if ap.ApInput == nil {
			logger.Warn(fmt.Sprintf("Access provider input with type %q is nil", ap.PolicyType))
			continue
		}
		result = append(result, ap.ApInput)
	}

	return result
}

func (a *AccessSyncer) SyncAccessAsCodeToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, prefix string, configMap *config.ConfigMap) error {
	return nil
}
