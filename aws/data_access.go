package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/wrappers"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
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
	// CreateWhatFromPolicyDocument(policyName string, policy *awspolicy.Policy) ([]sync_from_target.WhatItem, error)
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
				Policy:     "todo",
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

		whatItems, localErr := CreateWhatFromPolicyDocument(policy.Name, policy.PolicyParsed)
		if localErr != nil {
			return nil, localErr
		}

		apImportList = append(apImportList, AccessProviderInputExtended{
			ApInput: &sync_from_target.AccessProvider{
				ExternalId: policy.Id,
				Name:       policy.Name,
				ActualName: policy.Name,
				Type:       aws.String("policy_managed"),
				NamingHint: fmt.Sprintf("%s%s", ManagedPrefix, policy.Name),
				Action:     sync_from_target.Grant,
				Policy:     "",
				Who: &sync_from_target.WhoItem{
					Groups:          groupBindings,
					Users:           userBindings,
					AccessProviders: roleBindings,
				},
				What: whatItems,
			}})
	}

	logger.Info("Get all in-line policies")

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

		whatItems, err := CreateWhatFromPolicyDocument(inlinePolicyName, policy.PolicyParsed)
		if err != nil {
			logger.Error(fmt.Sprintf("error calculating access from policy document: %s", err.Error()))
			return nil, err
		}

		apImportList = append(apImportList, AccessProviderInputExtended{
			InlineParent: policy.InlineParent,
			PolicyType:   policy.PolicyType,
			ApInput: &sync_from_target.AccessProvider{
				Name:       policy.Name,
				Type:       aws.String("policy_inline"),
				NamingHint: inlinePolicyName,
				ActualName: inlinePolicyName,
				Action:     sync_from_target.Grant,
				Policy:     *policy.PolicyDocument,
				Who: &sync_from_target.WhoItem{
					Groups:          groupNames,
					Users:           userNames,
					AccessProviders: roleNames,
				},
				What: whatItems,
			}})
	}

	return apImportList, nil
}

func (a *AccessSyncer) GetAllInlinePolicies(ctx context.Context, configMap *config.ConfigMap, repo dataAccessRepository, roles []RoleEntity) ([]PolicyEntity, error) {
	logger.Info("Get in-line policies from groups")
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

	logger.Info("Get in-line policies from users")

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

	logger.Info("Get in-line policies from roles")

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
			logger.Info(fmt.Sprintf("Checking inline policy for role '%s'", ap.ApInput.Name))

			if _, found := inlineParentMap[ap.ApInput.Name]; found {
				filteredList = append(filteredList, *inlineParentMap[ap.ApInput.Name])
			}
		}
	}

	return filteredList
}

func isInlinePolicy(policy AccessProviderInputExtended) bool {
	if policy.PolicyType == InlineUser || policy.PolicyType == InlineGroup || policy.PolicyType == InlineRole {
		return true
	}

	return false
}

func addChildren(filteredList, fullList []AccessProviderInputExtended) []AccessProviderInputExtended {
	result := []AccessProviderInputExtended{}

	fullMap := map[string]AccessProviderInputExtended{}

	for ind := range fullList {
		if fullList[ind].ApInput != nil && strings.HasPrefix(fullList[ind].ApInput.NamingHint, RolePrefix) {
			fullMap[fullList[ind].ApInput.Name] = fullList[ind]
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

		if filteredList[ind].ApInput.Who == nil || filteredList[ind].ApInput.Who.AccessProviders == nil || len(filteredList[ind].ApInput.Who.AccessProviders) == 0 {
			continue
		}

		for _, descendant := range filteredList[ind].ApInput.Who.AccessProviders {
			if _, found := filteredMap[descendant]; found {
				continue
			}

			result = append(result, fullMap[descendant])
			filteredMap[descendant] = true
		}
	}

	return result
}

func removeArn(input []PolicyBinding) []PolicyBinding {
	result := []PolicyBinding{}

	for _, val := range input {
		val.ResourceId = ""
		result = append(result, val)
	}

	return result
}

func (a *AccessSyncer) SyncAccessProviderToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler, configMap *config.ConfigMap) error {
	repo := a.repoProvider()

	if accessProviders == nil || len(accessProviders.AccessProviders) == 0 {
		logger.Info("No access providers to sync from Raito to AWS")
		return nil
	}

	logger.Info("Importing to AWS")
	logger.Info(fmt.Sprintf("%d internal access providers to sync", len(accessProviders.AccessProviders)))

	logger.Info("Fetching managed policies")

	managedPolicies, err := repo.GetManagedPolicies(ctx, configMap, true)
	if err != nil {
		return err
	}

	a.managedPolicies = managedPolicies

	logger.Info("Fetching roles")

	roles, err := repo.GetRoles(ctx, configMap)
	if err != nil {
		return err
	}

	policyMap := map[string]string{}
	inlinePolicyMap := map[string]string{}
	inlinePolicyWithEntityMap := map[string]PolicyBinding{}
	roleMap := map[string]string{}
	existingPolicyBindings := map[string]set.Set[PolicyBinding]{}

	for ind := range managedPolicies {
		policy := managedPolicies[ind]

		policyMap[policy.Name] = "managed"

		existingPolicyBindings[policy.Name] = set.Set[PolicyBinding]{}

		existingPolicyBindings[policy.Name].Add(removeArn(policy.UserBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.GroupBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.RoleBindings)...)
	}

	existingRoleAssumptions := map[string]set.Set[PolicyBinding]{}

	for _, role := range roles {
		roleMap[role.Name] = "existing"

		var localErr error

		userBindings, localErr := repo.GetPrincipalsFromAssumeRolePolicyDocument(ctx, configMap, role.AssumeRolePolicyDocument)
		if localErr != nil {
			return localErr
		}

		existingRoleAssumptions[role.Name] = set.Set[PolicyBinding]{}

		for _, userName := range userBindings {
			key := PolicyBinding{
				Type:         "user",
				ResourceName: userName,
			}
			existingRoleAssumptions[role.Name].Add(key)
		}
	}

	managedPoliciesToModify := []AccessWithWho{}
	policyBindingsFromExport := map[string]set.Set[PolicyBinding]{}
	policyInheritanceMap := map[string]set.Set[string]{}

	for _, ap := range accessProviders.AccessProviders {
		if ap == nil {
			logger.Warn("No access provider... provided (bad-dum)")
			continue
		}

		if ap.Type == nil {
			logger.Warn(fmt.Sprintf("No type provided for access provider %s", ap.Name))
			continue
		}

		apMap := &policyMap
		if strings.Contains(*ap.Type, "role") {
			apMap = &roleMap
		} else if strings.Contains(*ap.Type, "inline") {
			apMap = &inlinePolicyMap
		}

		printDebugAp(*ap)

		err = accessProviderFeedbackHandler.AddAccessProviderFeedback(ap.Id, sync_to_target.AccessSyncFeedbackInformation{AccessId: ap.Id, ActualName: ap.Name})
		if err != nil {
			return err
		}

		name := getPolicyName(*ap)

		if _, found := (*apMap)[name]; ap.Delete {
			if found {
				(*apMap)[name] = DeleteAction
			}

			continue
		} else if strings.Contains(*ap.Type, "role") {
			action := UpdateAction
			if !found {
				action = CreateAction
			}
			(*apMap)[name] = action
		} else if strings.Contains(*ap.Type, "policy") { // roles can't have a What, so not needed
			managedPoliciesToModify = append(managedPoliciesToModify, AccessWithWho{
				Name: name,
				What: ap.What,
				// Who:  ap.Who, // irrelevant, is through binding
			})
			action := ""

			if !found {
				logger.Info(fmt.Sprintf("Policy with name %s not found in existing policies, adding to create/update list.", name))
				action = CreateAction
			} else {
				logger.Info(fmt.Sprintf("Policy with name %s found, adding to create/update list.", name))
				action = UpdateAction
			}
			(*apMap)[name] = action
		} else if strings.Contains(*ap.Type, "inline") {
			var localErr error

			// always convert an internal inline policy to a managed policy
			entityName, entityType, localErr := repo.GetAttachedEntity(*ap)
			logger.Info("Processing inline policy %s, for entity %s/%s", ap.Name, entityType, entityName)
			if localErr != nil {
				return localErr
			}
			inlinePolicyWithEntityMap[name] = PolicyBinding{
				ResourceName: entityName,
				Type:         entityType,
			}
			inlinePolicyMap[name] = DeleteAction
			managedPoliciesToModify = append(managedPoliciesToModify, AccessWithWho{
				Name: name,
				What: ap.What,
			})
			policyMap[name] = CreateAction
		}

		apInheritFromNames := getApNames(accessProviders.AccessProviders, ap.Who.InheritFrom...)
		policyInheritanceMap[ap.Name] = set.NewSet(apInheritFromNames...)

		policyBindingsFromExport[name] = set.Set[PolicyBinding]{}

		// Shouldn't use ap.Who.UsersInherited, because this works across non-allowed boundaries (e.g. (User)<-[:WHO]-(Role)<-[:WHO]-(Policy))
		for _, user := range ap.Who.Users {
			key := PolicyBinding{
				Type:         "user",
				ResourceName: user,
			}
			policyBindingsFromExport[name].Add(key)
		}

		for _, group := range ap.Who.Groups {
			key := PolicyBinding{
				Type:         "group",
				ResourceName: group,
				PolicyName:   name,
			}

			policyBindingsFromExport[name].Add(key)
		}
	}

	err = processApInheritance(policyInheritanceMap, policyMap, roleMap, &policyBindingsFromExport, existingPolicyBindings)
	if err != nil {
		return err
	}

	// ============================================================
	// =============== Roles ======================================
	// ============================================================

	assumeRoles := map[string]set.Set[PolicyBinding]{}

	for role, role_state := range roleMap {
		// only touch the access providers that are in the export
		if role_state == UpdateAction || role_state == CreateAction {
			logger.Info(fmt.Sprintf("Existing bindings for %s: %s", role, existingRoleAssumptions[role]))
			logger.Info(fmt.Sprintf("Export bindings for %s: %s", role, policyBindingsFromExport[role]))

			assumeRoles[role] = set.NewSet(policyBindingsFromExport[role].Slice()...)
		}
	}

	for roleName, action := range roleMap {
		if action == "existing" {
			continue
		}

		logger.Info(fmt.Sprintf("Processing role %s with action %s", roleName, action))

		if action == CreateAction {
			logger.Info(fmt.Sprintf("Creating role %s", roleName))

			if len(assumeRoles[roleName]) == 0 {
				return fmt.Errorf("cannot create Role %s, no users are assigned to it", roleName)
			}

			userNames := []string{}
			for _, binding := range assumeRoles[roleName].Slice() {
				userNames = append(userNames, binding.ResourceName)
			}

			err = repo.CreateRole(ctx, configMap, roleName, "", userNames)
			if err != nil {
				return err
			}
		} else if action == DeleteAction {
			logger.Info(fmt.Sprintf("Removing role %s", roleName))

			err = repo.DeleteRole(ctx, configMap, roleName)
			if err != nil {
				return err
			}
		}
	}

	// for now, do a full sync from scratch
	for roleName, v := range assumeRoles {
		userNames := []string{}
		for _, binding := range v.Slice() {
			userNames = append(userNames, binding.ResourceName)
		}

		if len(userNames) == 0 {
			continue
		}

		logger.Info(fmt.Sprintf("Updating users for role %s: %s", roleName, userNames))

		err = repo.UpdateAssumeEntities(ctx, configMap, roleName, userNames)
		if err != nil {
			return err
		}
	}

	// ============================================================
	// =============== Policies ===================================
	// ============================================================

	// create or update policy, overwrite what / policy document
	logger.Info(fmt.Sprintf("policies to add: %v", managedPoliciesToModify))

	for ind := range managedPoliciesToModify {
		policy := managedPoliciesToModify[ind]
		policyInfo := map[string][]string{}

		logger.Info(fmt.Sprintf("Process policy %s, action: %s", policy.Name, policyMap[policy.Name]))

		for _, what := range policy.What {
			if len(what.Permissions) == 0 {
				continue
			}

			if _, found := policyInfo[what.DataObject.FullName]; !found {
				policyInfo[what.DataObject.FullName] = what.Permissions
			}
		}

		var statements []awspolicy.Statement
		for resource, actions := range policyInfo {
			statements = append(statements, awspolicy.Statement{
				Resource: []string{convertFullnameToArn(resource, "s3")},
				Action:   prefixActionsWithService("s3", actions...),
				Effect:   "Allow",
			})
		}

		if strings.Contains(policy.Name, "/") {
			logger.Info(fmt.Sprintf("skipping policy creation for %s", policy.Name))
			continue
		}

		if policyMap[policy.Name] == CreateAction {
			logger.Info(fmt.Sprintf("Creating policy %s", policy.Name))

			_, err = repo.CreateManagedPolicy(ctx, configMap, policy.Name, statements)
			if err != nil {
				return err
			}
		} else if policyMap[policy.Name] == UpdateAction {
			logger.Info(fmt.Sprintf("Updating policy %s", policy.Name))
			err = repo.UpdateManagedPolicy(ctx, configMap, policy.Name, statements)
			if err != nil {
				return err
			}
		}
	}

	for policy, policy_state := range policyMap {
		if policy_state == DeleteAction {
			logger.Info(fmt.Sprintf("Deleting managed policy: %s", policy))

			err = repo.DeleteManagedPolicy(ctx, configMap, policy)
			if err != nil {
				return err
			}
		}
	}

	policyBindingsToAdd := map[string]set.Set[PolicyBinding]{}
	policyBindingsToRemove := map[string]set.Set[PolicyBinding]{}

	for policy, policy_state := range policyMap {
		// only touch the access providers that are in the export
		if policy_state == UpdateAction || policy_state == CreateAction {
			policyBindingsToAdd[policy] = set.NewSet(policyBindingsFromExport[policy].Slice()...)
			policyBindingsToAdd[policy].RemoveAll(existingPolicyBindings[policy].Slice()...)

			policyBindingsToRemove[policy] = set.NewSet(existingPolicyBindings[policy].Slice()...)
			policyBindingsToRemove[policy].RemoveAll(policyBindingsFromExport[policy].Slice()...)
		}
	}

	logger.Info(fmt.Sprintf("%d existing policies with bindings", len(existingPolicyBindings)))
	logger.Info(fmt.Sprintf("%d export policies with bindings", len(policyBindingsFromExport)))
	logger.Info(fmt.Sprintf("%d policies with bindings TO ADD", len(policyBindingsToAdd)))
	logger.Info(fmt.Sprintf("%d policies with bindings TO REMOVE", len(policyBindingsToRemove)))

	for k, v := range policyBindingsToAdd {
		for _, item := range v.Slice() {
			logger.Info(fmt.Sprintf("Bindings to add: %s - %s - %s - %s", item.Type, item.ResourceId, item.ResourceName, k))
		}
	}

	for k, v := range policyBindingsToRemove {
		for _, item := range v.Slice() {
			logger.Info(fmt.Sprintf("Bindings to remove: %s - %s - %s - %s", item.Type, item.ResourceId, item.ResourceName, k))
		}
	}

	for policyName, bindings := range policyBindingsToAdd { //nolint: dupl
		policyArn := repo.GetPolicyArn(policyName, configMap)

		for _, binding := range bindings.Slice() {
			if binding.Type == "user" {
				logger.Info(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = repo.AttachUserToManagedPolicy(ctx, configMap, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == "group" {
				logger.Info(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = repo.AttachGroupToManagedPolicy(ctx, configMap, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == "role" {
				logger.Info(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = repo.AttachRoleToManagedPolicy(ctx, configMap, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			}
		}
	}

	for policyName, bindings := range policyBindingsToRemove { //nolint: dupl
		policyArn := repo.GetPolicyArn(policyName, configMap)

		for _, binding := range bindings.Slice() {
			if binding.Type == "user" {
				logger.Info(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = repo.DetachUserFromManagedPolicy(ctx, configMap, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == "group" {
				logger.Info(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = repo.DetachGroupFromManagedPolicy(ctx, configMap, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == "role" {
				logger.Info(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = repo.DetachRoleFromManagedPolicy(ctx, configMap, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			}
		}
	}

	// ============================================================
	// =============== Inline policies ============================
	// ============================================================
	// inline policies can't be created in the UI, only actions are delete and update the what. Changing the who is done by converting it to a managed policy

	for policy, policy_state := range inlinePolicyMap {
		if binding, found := inlinePolicyWithEntityMap[policy]; policy_state == DeleteAction && found {
			logger.Info(fmt.Sprintf("Deleting inline policy %s for %s/%s", policy, binding.Type, binding.ResourceName))

			err = repo.DeleteInlinePolicy(ctx, configMap, policy, binding.ResourceName, binding.Type)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *AccessSyncer) SyncAccessAsCodeToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, prefix string, configMap *config.ConfigMap) error {
	return nil
}
