package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/raito-io/cli/base/access_provider/sync_to_target/naming_hint"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"
	"github.com/raito-io/golang-set/set"
)

const (
	CreateAction string = "create"
	UpdateAction string = "update"
	DeleteAction string = "delete"
)

func (a *AccessSyncer) SyncAccessProviderToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler, configMap *config.ConfigMap) error {
	a.repo = &AwsIamRepository{
		ConfigMap: configMap,
	}

	return a.doSyncAccessProviderToTarget(ctx, accessProviders, accessProviderFeedbackHandler, configMap)
}

func (a *AccessSyncer) doSyncAccessProviderToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler, configMap *config.ConfigMap) error {
	if accessProviders == nil || len(accessProviders.AccessProviders) == 0 {
		logger.Info("No access providers to sync from Raito to AWS")
		return nil
	}

	logger.Info(fmt.Sprintf("Provisioning %d access providers to AWS", len(accessProviders.AccessProviders)))

	roleActionMap, existingRoleWhoBindings, err := a.fetchExistingRoles(ctx)
	if err != nil {
		return err
	}

	policyActionMap, existingPolicyWhoBindings, err := a.fetchExistingManagedPolicies(ctx)
	if err != nil {
		return err
	}

	// Need to separate roles and policies as they can have the same name
	policyAps := map[string]*sync_to_target.AccessProvider{}
	roleAps := map[string]*sync_to_target.AccessProvider{}
	newRoleWhoBindings := map[string]set.Set[PolicyBinding]{}
	roleInheritanceMap := map[string]set.Set[string]{}
	newPolicyWhoBindings := map[string]set.Set[PolicyBinding]{}
	policyInheritanceMap := map[string]set.Set[string]{}

	inlineUserPoliciesToDelete := map[string][]string{}
	inlineGroupPoliciesToDelete := map[string][]string{}

	for i := range accessProviders.AccessProviders {
		ap := accessProviders.AccessProviders[i]

		if ap == nil {
			continue
		}

		apType := string(Policy)

		if ap.Type == nil {
			logger.Warn(fmt.Sprintf("No type provided for access provider %q. Using Policy as default", ap.Name))
		} else {
			apType = *ap.Type
		}

		var apActionMap map[string]string
		var inheritanceMap map[string]set.Set[string]
		var whoBindings map[string]set.Set[PolicyBinding]
		var aps map[string]*sync_to_target.AccessProvider

		switch apType {
		case string(Role):
			apActionMap = roleActionMap
			inheritanceMap = roleInheritanceMap
			whoBindings = newRoleWhoBindings
			aps = roleAps
		case string(Policy):
			apActionMap = policyActionMap
			inheritanceMap = policyInheritanceMap
			whoBindings = newPolicyWhoBindings
			aps = policyAps
		default:
			return fmt.Errorf("unsupported access provider type: %s", apType)
		}

		printDebugAp(*ap)

		name, err2 := generateName(ap)
		if err2 != nil {
			return errors.Wrap(err2, fmt.Sprintf("failed to generate actual name for access provider %q", ap.Name))
		}

		// Check the incoming external ID to see if there is a list of inline policies defined
		if ap.ExternalId != nil && strings.Contains(*ap.ExternalId, InlinePrefix) {
			eId := *ap.ExternalId

			logger.Info(fmt.Sprintf("Processing externalId %q for access provider %q", eId, ap.Name))

			inlineString := eId[strings.Index(eId, InlinePrefix)+len(InlinePrefix):]
			inlinePolicies := strings.Split(inlineString, "|")

			// Note: for roles we currently don't do this as we simply remove/replace all the inline policies
			if strings.HasPrefix(eId, UserTypePrefix) {
				entityName := eId[len(UserTypePrefix):strings.Index(eId, "|")]

				inlineUserPoliciesToDelete[entityName] = inlinePolicies

				logger.Info(fmt.Sprintf("Handled inline policies for user %q: %v", entityName, inlinePolicies))
			} else if strings.HasPrefix(eId, GroupTypePrefix) {
				entityName := eId[len(GroupTypePrefix):strings.Index(eId, "|")]

				inlineGroupPoliciesToDelete[entityName] = inlinePolicies

				logger.Info(fmt.Sprintf("Handled inline policies for group %q: %v", entityName, inlinePolicies))
			}
		}

		_, found := apActionMap[name]

		if ap.Delete {
			if found {
				apActionMap[name] = DeleteAction
			}

			continue
		} else if apType == string(Role) || apType == string(Policy) {
			externalId := name
			if apType == string(Role) {
				externalId = fmt.Sprintf("%s|%s", RoleTypePrefix, name)
			} else {
				externalId = fmt.Sprintf("%s|%s", PolicyTypePrefix, name)
			}

			err = accessProviderFeedbackHandler.AddAccessProviderFeedback(ap.Id, sync_to_target.AccessSyncFeedbackInformation{AccessId: ap.Id, ActualName: name, ExternalId: &externalId})
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed to add feedback for access provider %q", ap.Name))
			}

			// Map the role/policy name to the AP source
			aps[name] = ap

			// Check the action to perform and store it.
			action := UpdateAction
			if !found {
				action = CreateAction
			}
			apActionMap[name] = action

			// Storing the inheritance information to handle every we covered all APs
			apInheritFromNames := resolveInheritedApNames(accessProviders.AccessProviders, ap.Who.InheritFrom...)
			inheritanceMap[name] = set.NewSet(apInheritFromNames...)

			// Handling the WHO by converting it to policy bindings
			whoBindings[name] = set.Set[PolicyBinding]{}

			// Shouldn't use ap.Who.UsersInherited, because this works across non-allowed boundaries (e.g. (User)<-[:WHO]-(Role)<-[:WHO]-(Policy))
			for _, user := range ap.Who.Users {
				key := PolicyBinding{
					Type:         UserResourceType,
					ResourceName: user,
				}
				whoBindings[name].Add(key)
			}

			if apType == string(Role) {
				// Roles don't support assignment to groups, so we take the users in the groups and add those directly.
				for _, user := range ap.Who.UsersInGroups {
					key := PolicyBinding{
						Type:         UserResourceType,
						ResourceName: user,
					}

					whoBindings[name].Add(key)
				}
			} else {
				for _, group := range ap.Who.Groups {
					key := PolicyBinding{
						Type:         GroupResourceType,
						ResourceName: group,
					}

					whoBindings[name].Add(key)
				}
			}
		}
	}

	logger.Debug(fmt.Sprintf("roleInheritanceMap: %+v", roleInheritanceMap))
	logger.Debug(fmt.Sprintf("policyInheritanceMap: %+v", policyInheritanceMap))
	logger.Debug(fmt.Sprintf("newRoleWhoBindings: %+v", newRoleWhoBindings))
	logger.Debug(fmt.Sprintf("newPolicyWhoBindings: %+v", newPolicyWhoBindings))
	logger.Debug(fmt.Sprintf("existingPolicyWhoBindings: %+v", existingPolicyWhoBindings))
	logger.Debug(fmt.Sprintf("existingRoleWhoBindings: %+v", existingRoleWhoBindings))

	err = processApInheritance(roleInheritanceMap, policyInheritanceMap, newRoleWhoBindings, newPolicyWhoBindings, existingRoleWhoBindings, existingPolicyWhoBindings)
	if err != nil {
		return err
	}

	logger.Debug(fmt.Sprintf("New policy bindings: %+v", newPolicyWhoBindings))
	logger.Debug(fmt.Sprintf("New role bindings: %+v", newRoleWhoBindings))

	// ============================================================
	// ========================== Roles ===========================
	// ============================================================

	assumeRoles := map[string]set.Set[PolicyBinding]{}

	for roleName, roleAction := range roleActionMap {
		logger.Info(fmt.Sprintf("Processing role %s with action %s", roleName, roleAction))

		if roleAction == UpdateAction || roleAction == CreateAction {
			logger.Info(fmt.Sprintf("Existing bindings for %s: %s", roleName, existingRoleWhoBindings[roleName]))
			logger.Info(fmt.Sprintf("Export bindings for %s: %s", roleName, newRoleWhoBindings[roleName]))

			assumeRoles[roleName] = set.NewSet(newRoleWhoBindings[roleName].Slice()...)
		}

		if roleAction == DeleteAction {
			logger.Info(fmt.Sprintf("Removing role %s", roleName))

			err = a.repo.DeleteRole(ctx, roleName)
			if err != nil {
				return err
			}
		} else if roleAction == CreateAction || roleAction == UpdateAction {
			// Getting the who (for roles, this should already contain the list of unpacked users from the groups (as those are not supported for roles)
			userNames := make([]string, 0, len(assumeRoles[roleName]))
			for _, binding := range assumeRoles[roleName].Slice() {
				userNames = append(userNames, binding.ResourceName)
			}

			// TODO Why is this? A role cannot have 0 bindings?
			if len(userNames) == 0 {
				continue
			}

			sort.Strings(userNames)

			// Getting the what
			ap := roleAps[roleName]
			statements := createPolicyStatementsFromWhat(ap.What)

			if roleAction == CreateAction {
				logger.Info(fmt.Sprintf("Creating role %s", roleName))

				// Create the new role with the who
				err = a.repo.CreateRole(ctx, roleName, ap.Description, userNames)
				if err != nil {
					return err
				}
			} else {
				logger.Info(fmt.Sprintf("Updating role %s", roleName))

				// Handle the who
				err = a.repo.UpdateAssumeEntities(ctx, roleName, userNames)
				if err != nil {
					return err
				}

				// For roles, we always delete all the inline policies.
				// If we wouldn't do that, we would be blind on what the role actually looks like.
				// If new permissions are supported later on, we would never see them.
				err = a.repo.DeleteRoleInlinePolicies(ctx, roleName)
				if err != nil {
					return err
				}
			}

			if len(statements) > 0 {
				// Create the inline policy for the what
				err = a.repo.CreateRoleInlinePolicy(ctx, roleName, "Raito_Inline_"+roleName, statements)
				if err != nil {
					return err
				}
			}
		} else {
			logger.Debug(fmt.Sprintf("no action needed for role %q", roleName))
		}
	}

	// ============================================================
	// ====================== Policies ============================
	// ============================================================

	// create or update policy, overwrite what / policy document
	logger.Info(fmt.Sprintf("policies to add or update: %v", policyAps))

	for name, ap := range policyAps {
		action := policyActionMap[name]

		logger.Info(fmt.Sprintf("Process policy %s, action: %s", name, action))

		statements := createPolicyStatementsFromWhat(ap.What)

		if action == CreateAction {
			logger.Info(fmt.Sprintf("Creating policy %s", name))

			_, err = a.repo.CreateManagedPolicy(ctx, name, statements)
			if err != nil {
				return err
			}
		} else if action == UpdateAction {
			logger.Info(fmt.Sprintf("Updating policy %s", name))
			err = a.repo.UpdateManagedPolicy(ctx, name, statements)
			if err != nil {
				return err
			}
		}
	}

	for policy, policyState := range policyActionMap {
		if policyState == DeleteAction {
			logger.Info(fmt.Sprintf("Deleting managed policy: %s", policy))

			err = a.repo.DeleteManagedPolicy(ctx, policy)
			if err != nil {
				return err
			}
		}
	}

	policyBindingsToAdd := map[string]set.Set[PolicyBinding]{}
	policyBindingsToRemove := map[string]set.Set[PolicyBinding]{}

	for policy, policyState := range policyActionMap {
		// only touch the access providers that are in the export
		if policyState == UpdateAction || policyState == CreateAction {
			policyBindingsToAdd[policy] = set.NewSet(newPolicyWhoBindings[policy].Slice()...)
			policyBindingsToAdd[policy].RemoveAll(existingPolicyWhoBindings[policy].Slice()...)

			policyBindingsToRemove[policy] = set.NewSet(existingPolicyWhoBindings[policy].Slice()...)
			policyBindingsToRemove[policy].RemoveAll(newPolicyWhoBindings[policy].Slice()...)
		}
	}

	for policyName, bindings := range policyBindingsToAdd { //nolint: dupl
		policyArn := a.repo.GetPolicyArn(policyName, configMap)

		for _, binding := range bindings.Slice() {
			if binding.Type == UserResourceType {
				logger.Debug(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = a.repo.AttachUserToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == GroupResourceType {
				logger.Debug(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = a.repo.AttachGroupToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == RoleResourceType {
				logger.Debug(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = a.repo.AttachRoleToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			}
		}
	}

	for policyName, bindings := range policyBindingsToRemove { //nolint: dupl
		policyArn := a.repo.GetPolicyArn(policyName, configMap)

		for _, binding := range bindings.Slice() {
			if binding.Type == UserResourceType {
				logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = a.repo.DetachUserFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == GroupResourceType {
				logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = a.repo.DetachGroupFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == RoleResourceType {
				logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = a.repo.DetachRoleFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			}
		}
	}

	// Delete old inline policies on users that are not needed anymore
	for user, inlinePolicies := range inlineUserPoliciesToDelete {
		logger.Info(fmt.Sprintf("Deleting inline polices for user %q: %v", user, inlinePolicies))

		for _, inlinePolicy := range inlinePolicies {
			inlinePolicy = strings.TrimSpace(inlinePolicy)
			if inlinePolicy != "" {
				err2 := a.repo.DeleteInlinePolicy(ctx, inlinePolicy, user, UserResourceType)
				if err2 != nil {
					logger.Warn(fmt.Sprintf("error while deleting inline policy %q for user %q: %s", inlinePolicy, user, err2.Error()))
				}
			}
		}
	}

	// Delete old inline policies on groups that are not needed anymore
	for group, inlinePolicies := range inlineGroupPoliciesToDelete {
		for _, inlinePolicy := range inlinePolicies {
			inlinePolicy = strings.TrimSpace(inlinePolicy)
			if inlinePolicy != "" {
				err2 := a.repo.DeleteInlinePolicy(ctx, inlinePolicy, group, GroupResourceType)
				if err2 != nil {
					logger.Warn(fmt.Sprintf("error while deleting inline policy %q for group %q: %s", inlinePolicy, group, err2.Error()))
				}
			}
		}
	}

	return nil
}

func createPolicyStatementsFromWhat(whatItems []sync_to_target.WhatItem) []awspolicy.Statement {
	policyInfo := map[string][]string{}

	for _, what := range whatItems {
		if len(what.Permissions) == 0 {
			continue
		}

		if _, found := policyInfo[what.DataObject.FullName]; !found {
			policyInfo[what.DataObject.FullName] = what.Permissions
		}
	}

	statements := make([]awspolicy.Statement, 0, len(policyInfo))
	for resource, actions := range policyInfo {
		statements = append(statements, awspolicy.Statement{
			Resource: []string{convertFullnameToArn(resource, "s3")},
			Action:   actions,
			Effect:   "Allow",
		})
	}

	return statements
}

func (a *AccessSyncer) fetchExistingRoles(ctx context.Context) (map[string]string, map[string]set.Set[PolicyBinding], error) {
	logger.Info("Fetching roles")

	roles, err := a.repo.GetRoles(ctx)
	if err != nil {
		return nil, nil, err
	}

	roleMap := map[string]string{}
	existingRoleAssumptions := map[string]set.Set[PolicyBinding]{}

	for _, role := range roles {
		roleMap[role.Name] = "existing"

		var localErr error

		userBindings, localErr := a.repo.GetPrincipalsFromAssumeRolePolicyDocument(role.AssumeRolePolicyDocument)
		if localErr != nil {
			return nil, nil, localErr
		}

		existingRoleAssumptions[role.Name] = set.Set[PolicyBinding]{}

		for _, userName := range userBindings {
			key := PolicyBinding{
				Type:         UserResourceType,
				ResourceName: userName,
			}
			existingRoleAssumptions[role.Name].Add(key)
		}
	}

	return roleMap, existingRoleAssumptions, nil
}

func (a *AccessSyncer) fetchExistingManagedPolicies(ctx context.Context) (map[string]string, map[string]set.Set[PolicyBinding], error) {
	managedPolicies, err := a.repo.GetManagedPolicies(ctx, true)
	if err != nil {
		return nil, nil, err
	}

	a.managedPolicies = managedPolicies

	policyMap := map[string]string{}
	existingPolicyBindings := map[string]set.Set[PolicyBinding]{}

	for ind := range managedPolicies {
		policy := managedPolicies[ind]

		policyMap[policy.Name] = "managed"

		existingPolicyBindings[policy.Name] = set.Set[PolicyBinding]{}

		existingPolicyBindings[policy.Name].Add(removeArn(policy.UserBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.GroupBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.RoleBindings)...)
	}

	return policyMap, existingPolicyBindings, nil
}

func removeArn(input []PolicyBinding) []PolicyBinding {
	result := []PolicyBinding{}

	for _, val := range input {
		val.ResourceId = ""
		result = append(result, val)
	}

	return result
}

func generateName(ap *sync_to_target.AccessProvider) (string, error) {
	uniqueRoleNameGenerator, err := naming_hint.NewUniqueNameGenerator(logger, "", &naming_hint.NamingConstraints{
		UpperCaseLetters:  true,
		LowerCaseLetters:  true,
		Numbers:           true,
		SpecialCharacters: "+_",
		MaxLength:         64,
	})

	if err != nil {
		return "", err
	}

	return uniqueRoleNameGenerator.Generate(ap)
}
