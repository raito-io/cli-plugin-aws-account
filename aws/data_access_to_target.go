package aws

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	ds "github.com/raito-io/cli/base/data_source"

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
	a.repo = iam.NewAwsIamRepository(configMap)

	return a.doSyncAccessProviderToTarget(ctx, accessProviders, accessProviderFeedbackHandler, configMap)
}

func logFeedbackError(apFeedback *sync_to_target.AccessProviderSyncFeedback, msg string) {
	utils.Logger.Error(msg)
	apFeedback.Errors = append(apFeedback.Errors, msg)
}

func (a *AccessSyncer) getUserGroupMap(ctx context.Context, configMap *config.ConfigMap) (map[string][]string, error) {
	if a.userGroupMap != nil {
		return a.userGroupMap, nil
	}

	iamRepo := iam.NewAwsIamRepository(configMap)

	groups, err := iamRepo.GetGroups(ctx)
	if err != nil {
		return nil, err
	}

	a.userGroupMap = make(map[string][]string)

	users, err := iamRepo.GetUsers(ctx, false)
	if err != nil {
		return nil, err
	}

	userMap := make(map[string]string)
	for _, u := range users {
		userMap[u.ExternalId] = u.Name
	}

	for _, g := range groups {
		for _, m := range g.Members {
			if userName, f := userMap[m]; f {
				a.userGroupMap[g.Name] = append(a.userGroupMap[g.Name], userName)
			} else {
				utils.Logger.Warn(fmt.Sprintf("Could not find member %s for group %s", m, g.Name))
			}
		}
	}

	return a.userGroupMap, nil
}

func (a *AccessSyncer) doSyncAccessProviderToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler, configMap *config.ConfigMap) (err error) {
	if accessProviders == nil || len(accessProviders.AccessProviders) == 0 {
		utils.Logger.Info("No access providers to sync from Raito to AWS")
		return nil
	}

	utils.Logger.Info(fmt.Sprintf("Provisioning %d access providers to AWS", len(accessProviders.AccessProviders)))

	roleActionMap, existingRoleWhoBindings, err := a.fetchExistingRoles(ctx, configMap)
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
	newRoleWhoBindings := map[string]set.Set[model.PolicyBinding]{}
	roleInheritanceMap := map[string]set.Set[string]{}
	inverseRoleInheritanceMap := map[string]set.Set[string]{}
	newPolicyWhoBindings := map[string]set.Set[model.PolicyBinding]{}
	policyInheritanceMap := map[string]set.Set[string]{}

	inlineUserPoliciesToDelete := map[string][]string{}
	inlineGroupPoliciesToDelete := map[string][]string{}

	feedbackMap := make(map[string]*sync_to_target.AccessProviderSyncFeedback)

	// Making sure we always send the feedback back
	defer func() {
		for _, feedback := range feedbackMap {
			err2 := accessProviderFeedbackHandler.AddAccessProviderFeedback(*feedback)
			if err2 != nil {
				err = multierror.Append(err, err2)
			}
		}
	}()

	for i := range accessProviders.AccessProviders {
		ap := accessProviders.AccessProviders[i]

		if ap == nil {
			continue
		}

		// Create the initial feedback object
		apFeedback := sync_to_target.AccessProviderSyncFeedback{
			AccessProvider: ap.Id,
		}
		feedbackMap[ap.Id] = &apFeedback

		name, err2 := utils.GenerateName(ap)
		if err2 != nil {
			logFeedbackError(&apFeedback, fmt.Sprintf("failed to generate actual name for access provider %q: %s", ap.Name, err2.Error()))
			continue
		}

		apFeedback.ActualName = name

		if ap.Action != sync_to_target.Grant && ap.Action != sync_to_target.Purpose {
			logFeedbackError(&apFeedback, fmt.Sprintf("unsupported access provider action: %d", ap.Action))
			continue
		}

		apType := string(model.Policy)

		if ap.Action == sync_to_target.Purpose {
			// TODO look at all other APs to see what the incoming WHO links are.
			// How do we handle this with external APs? Do we have this information in the existingRoleWhoBindings and existingPolicyWhoBindings ?
			// If so, do we already know if the role is an SSO role or not?
			// If this is linked to an SSO role (can only be 1): we just add the sso role as actual name and add the WHO from
			//    How to handle Purpose inheritance?
			//    How to handle partial syncs? (can we even support this?) Possibly need a metadata indication that we always need to export the purposes and SSO roles?
			// If this is linked to a role (or multiple?): we handle it the same way as a normal role (or do the same as for SSO roles?)
			// If this is linked to a policy (or multiple?): we need to add the WHO to the policy (= act as normal policy?)
			logFeedbackError(&apFeedback, "currently purposes are not supported yet")
		} else {
			if ap.Type == nil {
				utils.Logger.Warn(fmt.Sprintf("No type provided for access provider %q. Using Policy as default", ap.Name))
			} else {
				apType = *ap.Type
			}
		}

		apFeedback.Type = &apType

		var apActionMap map[string]string
		var inheritanceMap map[string]set.Set[string]
		var whoBindings map[string]set.Set[model.PolicyBinding]
		var aps map[string]*sync_to_target.AccessProvider

		switch apType {
		case string(model.Role):
			apActionMap = roleActionMap
			inheritanceMap = roleInheritanceMap
			whoBindings = newRoleWhoBindings
			aps = roleAps
		case string(model.Policy):
			apActionMap = policyActionMap
			inheritanceMap = policyInheritanceMap
			whoBindings = newPolicyWhoBindings
			aps = policyAps
		default:
			logFeedbackError(&apFeedback, fmt.Sprintf("unsupported access provider type: %s", apType))
			continue
		}

		printDebugAp(*ap)

		// Check the incoming external ID to see if there is a list of inline policies defined
		if ap.ExternalId != nil && strings.Contains(*ap.ExternalId, constants.InlinePrefix) {
			eId := *ap.ExternalId

			utils.Logger.Info(fmt.Sprintf("Processing externalId %q for access provider %q", eId, ap.Name))

			inlineString := eId[strings.Index(eId, constants.InlinePrefix)+len(constants.InlinePrefix):]
			inlinePolicies := strings.Split(inlineString, "|")

			// Note: for roles we currently don't do this as we simply remove/replace all the inline policies
			if strings.HasPrefix(eId, constants.UserTypePrefix) {
				entityName := eId[len(constants.UserTypePrefix):strings.Index(eId, "|")]

				inlineUserPoliciesToDelete[entityName] = inlinePolicies

				utils.Logger.Info(fmt.Sprintf("Handled inline policies for user %q: %v", entityName, inlinePolicies))
			} else if strings.HasPrefix(eId, constants.GroupTypePrefix) {
				entityName := eId[len(constants.GroupTypePrefix):strings.Index(eId, "|")]

				inlineGroupPoliciesToDelete[entityName] = inlinePolicies

				utils.Logger.Info(fmt.Sprintf("Handled inline policies for group %q: %v", entityName, inlinePolicies))
			}
		}

		_, found := apActionMap[name]

		if ap.Delete {
			if found {
				apActionMap[name] = DeleteAction
			}

			continue
		} else {
			externalId := name
			if apType == string(model.Role) {
				externalId = fmt.Sprintf("%s%s", constants.RoleTypePrefix, name)
			} else {
				externalId = fmt.Sprintf("%s%s", constants.PolicyTypePrefix, name)
			}

			apFeedback.ExternalId = &externalId

			// Map the role/policy name to the AP source
			aps[name] = ap

			// Check the action to perform and store it.
			action := UpdateAction
			if !found {
				action = CreateAction
			}
			apActionMap[name] = action

			// Storing the inheritance information to handle every we covered all APs
			apInheritFromNames := iam.ResolveInheritedApNames(accessProviders.AccessProviders, ap.Who.InheritFrom...)
			inheritanceMap[name] = set.NewSet(apInheritFromNames...)

			// Handling the WHO by converting it to policy bindings
			whoBindings[name] = set.Set[model.PolicyBinding]{}

			for _, user := range ap.Who.Users {
				key := model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: user,
				}
				whoBindings[name].Add(key)
			}

			if apType == string(model.Role) {
				if len(ap.Who.Groups) > 0 {
					userGroupMap, err3 := a.getUserGroupMap(ctx, configMap)
					if err3 != nil {
						return err3
					}

					// Roles don't support assignment to groups, so we take the users in the groups and add those directly.
					for _, group := range ap.Who.Groups {
						if users, f := userGroupMap[group]; f {
							for _, user := range users {
								key := model.PolicyBinding{
									Type:         iam.UserResourceType,
									ResourceName: user,
								}
								whoBindings[name].Add(key)
							}
						}
					}
				}

				// For roles we also build the reverse inheritance map
				for _, inheritFrom := range apInheritFromNames {
					if _, f := inverseRoleInheritanceMap[inheritFrom]; !f {
						inverseRoleInheritanceMap[inheritFrom] = set.NewSet[string]()
					}

					inverseRoleInheritanceMap[inheritFrom].Add(name)
				}
			} else {
				for _, group := range ap.Who.Groups {
					key := model.PolicyBinding{
						Type:         iam.GroupResourceType,
						ResourceName: group,
					}

					whoBindings[name].Add(key)
				}
			}
		}
	}

	utils.Logger.Debug(fmt.Sprintf("roleInheritanceMap: %+v", roleInheritanceMap))
	utils.Logger.Debug(fmt.Sprintf("policyInheritanceMap: %+v", policyInheritanceMap))
	utils.Logger.Debug(fmt.Sprintf("newRoleWhoBindings: %+v", newRoleWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("newPolicyWhoBindings: %+v", newPolicyWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("existingPolicyWhoBindings: %+v", existingPolicyWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("existingRoleWhoBindings: %+v", existingRoleWhoBindings))

	iam.ProcessApInheritance(roleInheritanceMap, policyInheritanceMap, newRoleWhoBindings, newPolicyWhoBindings, existingRoleWhoBindings, existingPolicyWhoBindings)

	utils.Logger.Debug(fmt.Sprintf("New policy bindings: %+v", newPolicyWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("New role bindings: %+v", newRoleWhoBindings))

	// ============================================================
	// ========================== Roles ===========================
	// ============================================================

	assumeRoles := map[string]set.Set[model.PolicyBinding]{}

	for roleName, roleAction := range roleActionMap {
		roleAp := roleAps[roleName]

		utils.Logger.Info(fmt.Sprintf("Processing role %s with action %s", roleName, roleAction))

		if roleAction == DeleteAction {
			utils.Logger.Info(fmt.Sprintf("Removing role %s", roleName))

			err = a.repo.DeleteRole(ctx, roleName)
			if err != nil {
				logFeedbackError(feedbackMap[roleAp.Id], fmt.Sprintf("failed to delete role %q: %s", roleName, err.Error()))
				continue
			}
		} else if roleAction == CreateAction || roleAction == UpdateAction {
			utils.Logger.Info(fmt.Sprintf("Existing bindings for %s: %s", roleName, existingRoleWhoBindings[roleName]))
			utils.Logger.Info(fmt.Sprintf("Export bindings for %s: %s", roleName, newRoleWhoBindings[roleName]))

			assumeRoles[roleName] = set.NewSet(newRoleWhoBindings[roleName].Slice()...)

			// Getting the who (for roles, this should already contain the list of unpacked users from the groups (as those are not supported for roles)
			userNames := make([]string, 0, len(assumeRoles[roleName]))
			for _, binding := range assumeRoles[roleName].Slice() {
				userNames = append(userNames, binding.ResourceName)
			}

			sort.Strings(userNames)

			// Getting the what
			ap := roleAps[roleName]
			statements := createPolicyStatementsFromWhat(ap.What)

			// Because we need to flatten the WHAT for roles as well, we gather all role APs from which this role AP inherits its what (following the reverse inheritance chain)
			inheritedAPs := getAllAPsInInheritanceChainForWhat(roleName, inverseRoleInheritanceMap, roleAps)
			for _, inheritedAP := range inheritedAPs {
				statements = append(statements, createPolicyStatementsFromWhat(inheritedAP.What)...)
			}

			if roleAction == CreateAction {
				utils.Logger.Info(fmt.Sprintf("Creating role %s", roleName))

				// Create the new role with the who
				err = a.repo.CreateRole(ctx, roleName, ap.Description, userNames)
				if err != nil {
					logFeedbackError(feedbackMap[roleAp.Id], fmt.Sprintf("failed to create role %q: %s", roleName, err.Error()))
					continue
				}
			} else {
				utils.Logger.Info(fmt.Sprintf("Updating role %s", roleName))

				// Handle the who
				err = a.repo.UpdateAssumeEntities(ctx, roleName, userNames)
				if err != nil {
					logFeedbackError(feedbackMap[roleAp.Id], fmt.Sprintf("failed to update role %q: %s", roleName, err.Error()))
					continue
				}

				// For roles, we always delete all the inline policies.
				// If we wouldn't do that, we would be blind on what the role actually looks like.
				// If new permissions are supported later on, we would never see them.
				err = a.repo.DeleteRoleInlinePolicies(ctx, roleName)
				if err != nil {
					logFeedbackError(feedbackMap[roleAp.Id], fmt.Sprintf("failed to cleanup inline policies for role %q: %s", roleName, err.Error()))
					continue
				}
			}

			if len(statements) > 0 {
				// Create the inline policy for the what
				err = a.repo.CreateRoleInlinePolicy(ctx, roleName, "Raito_Inline_"+roleName, statements)
				if err != nil {
					logFeedbackError(feedbackMap[roleAp.Id], fmt.Sprintf("failed to create inline policies for role %q: %s", roleName, err.Error()))
					continue
				}
			}
		} else {
			utils.Logger.Debug(fmt.Sprintf("no action needed for role %q", roleName))
		}
	}

	// ============================================================
	// ====================== Policies ============================
	// ============================================================

	// create or update policy, overwrite what / policy document
	utils.Logger.Info(fmt.Sprintf("policies to add or update: %v", policyAps))

	managedPolicies := set.NewSet[string]()

	skippedPolicies := set.NewSet[string]()

	for name, ap := range policyAps {
		if ap.WhatLocked != nil && *ap.WhatLocked {
			managedPolicies.Add(name)
		}

		action := policyActionMap[name]

		utils.Logger.Info(fmt.Sprintf("Process policy %s, action: %s", name, action))

		statements := createPolicyStatementsFromWhat(ap.What)

		if action == CreateAction {
			utils.Logger.Info(fmt.Sprintf("Creating policy %s", name))

			p, err2 := a.repo.CreateManagedPolicy(ctx, name, statements)
			if err2 != nil {
				logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to create managed policy %q: %s", name, err2.Error()))
				skippedPolicies.Add(name)

				continue
			}

			if p == nil {
				skippedPolicies.Add(name)
			}
		} else if action == UpdateAction && !managedPolicies.Contains(name) {
			utils.Logger.Info(fmt.Sprintf("Updating policy %s", name))
			err = a.repo.UpdateManagedPolicy(ctx, name, false, statements)

			if err != nil {
				logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to update managed policy %q: %s", name, err.Error()))
				continue
			}
		}
	}

	for policy, policyState := range policyActionMap {
		ap := policyAps[policy]

		if policyState == DeleteAction {
			utils.Logger.Info(fmt.Sprintf("Deleting managed policy: %s", policy))

			err = a.repo.DeleteManagedPolicy(ctx, policy, managedPolicies.Contains(policy))
			if err != nil {
				logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to delete managed policy %q: %s", policy, err.Error()))
				continue
			}
		}
	}

	// Now handle the WHO of the policies
	policyBindingsToAdd := map[string]set.Set[model.PolicyBinding]{}
	policyBindingsToRemove := map[string]set.Set[model.PolicyBinding]{}

	for policy, policyState := range policyActionMap {
		if skippedPolicies.Contains(policy) {
			continue
		}

		// only touch the access providers that are in the export
		if policyState == UpdateAction || policyState == CreateAction {
			policyBindingsToAdd[policy] = set.NewSet(newPolicyWhoBindings[policy].Slice()...)
			policyBindingsToAdd[policy].RemoveAll(existingPolicyWhoBindings[policy].Slice()...)

			policyBindingsToRemove[policy] = set.NewSet(existingPolicyWhoBindings[policy].Slice()...)
			policyBindingsToRemove[policy].RemoveAll(newPolicyWhoBindings[policy].Slice()...)
		}
	}

	for policyName, bindings := range policyBindingsToAdd { //nolint: dupl
		ap := policyAps[policyName]

		policyArn := a.repo.GetPolicyArn(policyName, managedPolicies.Contains(policyName), configMap)

		for _, binding := range bindings.Slice() {
			if binding.Type == iam.UserResourceType {
				utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = a.repo.AttachUserToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to attach user %q to managed policy %q: %s", binding.ResourceName, policyName, err.Error()))
					continue
				}
			} else if binding.Type == iam.GroupResourceType {
				utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to group: %s", policyName, binding.ResourceName))

				err = a.repo.AttachGroupToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to attach group %q to managed policy %q: %s", binding.ResourceName, policyName, err.Error()))
					continue
				}
			} else if binding.Type == iam.RoleResourceType {
				utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to role: %s", policyName, binding.ResourceName))

				err = a.repo.AttachRoleToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to attach role %q to managed policy %q: %s", binding.ResourceName, policyName, err.Error()))
					continue
				}
			}
		}
	}

	// Now handle the WHO bindings to remove for policies
	for policyName, bindings := range policyBindingsToRemove { //nolint: dupl
		ap := policyAps[policyName]

		policyArn := a.repo.GetPolicyArn(policyName, managedPolicies.Contains(policyName), configMap)

		for _, binding := range bindings.Slice() {
			if binding.Type == iam.UserResourceType {
				utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = a.repo.DetachUserFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to deattach user %q from managed policy %q: %s", binding.ResourceName, policyName, err.Error()))
					continue
				}
			} else if binding.Type == iam.GroupResourceType {
				utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from group: %s", policyName, binding.ResourceName))

				err = a.repo.DetachGroupFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to deattach group %q from managed policy %q: %s", binding.ResourceName, policyName, err.Error()))
					continue
				}
			} else if binding.Type == iam.RoleResourceType {
				utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = a.repo.DetachRoleFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(feedbackMap[ap.Id], fmt.Sprintf("failed to deattach role %q from managed policy %q: %s", binding.ResourceName, policyName, err.Error()))
					continue
				}
			}
		}
	}

	// Delete old inline policies on users that are not needed anymore
	for user, inlinePolicies := range inlineUserPoliciesToDelete {
		utils.Logger.Info(fmt.Sprintf("Deleting inline polices for user %q: %v", user, inlinePolicies))

		for _, inlinePolicy := range inlinePolicies {
			inlinePolicy = strings.TrimSpace(inlinePolicy)
			if inlinePolicy != "" {
				err2 := a.repo.DeleteInlinePolicy(ctx, inlinePolicy, user, iam.UserResourceType)
				if err2 != nil {
					utils.Logger.Warn(fmt.Sprintf("error while deleting inline policy %q for user %q: %s", inlinePolicy, user, err2.Error()))
				}
			}
		}
	}

	// Delete old inline policies on groups that are not needed anymore
	for group, inlinePolicies := range inlineGroupPoliciesToDelete {
		for _, inlinePolicy := range inlinePolicies {
			inlinePolicy = strings.TrimSpace(inlinePolicy)
			if inlinePolicy != "" {
				err2 := a.repo.DeleteInlinePolicy(ctx, inlinePolicy, group, iam.GroupResourceType)
				if err2 != nil {
					utils.Logger.Warn(fmt.Sprintf("error while deleting inline policy %q for group %q: %s", inlinePolicy, group, err2.Error()))
				}
			}
		}
	}

	return nil
}

func getAllAPsInInheritanceChainForWhat(start string, inverseRoleInheritanceMap map[string]set.Set[string], roleAps map[string]*sync_to_target.AccessProvider) []*sync_to_target.AccessProvider {
	inherited := set.NewSet[string]()
	getRecursiveInheritedAPs(start, inverseRoleInheritanceMap, inherited)

	aps := make([]*sync_to_target.AccessProvider, 0, len(inherited))

	is := inherited.Slice()
	for _, i := range is {
		aps = append(aps, roleAps[i])
	}

	return aps
}

func getRecursiveInheritedAPs(start string, inverseRoleInheritanceMap map[string]set.Set[string], inherited set.Set[string]) {
	if in, f := inverseRoleInheritanceMap[start]; f {
		for k := range in {
			if !inherited.Contains(k) {
				inherited.Add(k)
				getRecursiveInheritedAPs(k, inverseRoleInheritanceMap, inherited)
			}
		}
	}
}

func createPolicyStatementsFromWhat(whatItems []sync_to_target.WhatItem) []awspolicy.Statement {
	policyInfo := map[string][]string{}

	for _, what := range whatItems {
		if len(what.Permissions) == 0 {
			continue
		}

		if _, found := policyInfo[what.DataObject.FullName]; !found {
			dot := data_source.GetDataObjectType(what.DataObject.Type)
			allPermissions := what.Permissions

			if dot != nil {
				allPermissions = toPermissionList(dot.GetPermissions())
			}

			policyInfo[what.DataObject.FullName] = optimizePermissions(allPermissions, what.Permissions)
		}
	}

	statements := make([]awspolicy.Statement, 0, len(policyInfo))
	for resource, actions := range policyInfo {
		statements = append(statements, awspolicy.Statement{
			Resource: []string{utils.ConvertFullnameToArn(resource, "s3")},
			Action:   actions,
			Effect:   "Allow",
		})
	}

	return statements
}

func toPermissionList(input []*ds.DataObjectTypePermission) []string {
	output := make([]string, 0, len(input))

	for _, permission := range input {
		output = append(output, permission.Permission)
	}

	return output
}

func optimizePermissions(allPermissions, userPermissions []string) []string {
	sort.Strings(allPermissions)
	sort.Strings(userPermissions)

	if slices.Equal(allPermissions, userPermissions) {
		prefix := findCommonPrefix(allPermissions[0], allPermissions[len(allPermissions)-1])
		return []string{prefix + "*"}
	}

	var result []string
	i := 0

	for i < len(userPermissions) {
		if !contains(allPermissions, userPermissions[i]) {
			i++
			continue
		}

		if i == len(userPermissions)-1 {
			result = append(result, userPermissions[i])
			break
		}

		coveredPermissions := set.NewSet[string]()
		untilI := i

		// Find a common prefix with the next permission in the list
		prefixWithNext := findCommonPrefix(userPermissions[i], userPermissions[i+1])

		// If there is a common prefix, we see if the following permissions have that same prefix
		if prefixWithNext != "" {
			coveredPermissions.Add(userPermissions[i], userPermissions[i+1])

			untilI += 2

			for untilI < len(userPermissions) {
				if strings.HasPrefix(userPermissions[untilI], prefixWithNext) {
					coveredPermissions.Add(userPermissions[untilI])

					untilI++
				} else {
					break
				}
			}
		} else {
			result = append(result, userPermissions[i])
			i++

			continue
		}

		// Now that we found the prefix and all user permissions that have it, we check if there are no other permissions possible with this prefix
		match := true

		for _, perm := range allPermissions {
			// When there is a permission in the list that starts with the same prefix, but isn't in the user permission list
			if strings.HasPrefix(perm, prefixWithNext) && !coveredPermissions.Contains(perm) {
				match = false
				break
			}
		}

		if match {
			// If we found a match, we add this prefix + wildcard and skip all the hits we found.
			result = append(result, prefixWithNext+"*")
			i = untilI
		} else {
			result = append(result, userPermissions[i])
			i++
		}
	}

	return result
}

func findCommonPrefix(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}

	return a[:i]
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}

	return false
}

func (a *AccessSyncer) fetchExistingRoles(ctx context.Context, configMap *config.ConfigMap) (map[string]string, map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing roles")

	roles, err := a.repo.GetRoles(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching existing roles: %w", err)
	}

	roleMap := map[string]string{}
	existingRoleAssumptions := map[string]set.Set[model.PolicyBinding]{}

	for _, role := range roles {
		roleMap[role.Name] = "existing"

		who, _ := iam.CreateWhoFromTrustPolicyDocument(role.AssumeRolePolicy, role.Name, configMap)
		existingRoleAssumptions[role.Name] = set.Set[model.PolicyBinding]{}

		if who != nil {
			for _, userName := range who.Users {
				key := model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: userName,
				}
				existingRoleAssumptions[role.Name].Add(key)
			}
		}
	}

	utils.Logger.Info(fmt.Sprintf("Fetched existing %d roles", len(roleMap)))

	return roleMap, existingRoleAssumptions, nil
}

func (a *AccessSyncer) fetchExistingManagedPolicies(ctx context.Context) (map[string]string, map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing managed policies")

	managedPolicies, err := a.repo.GetManagedPolicies(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching existing managed policies: %w", err)
	}

	a.managedPolicies = managedPolicies

	policyMap := map[string]string{}
	existingPolicyBindings := map[string]set.Set[model.PolicyBinding]{}

	for ind := range managedPolicies {
		policy := managedPolicies[ind]

		policyMap[policy.Name] = "managed"

		existingPolicyBindings[policy.Name] = set.Set[model.PolicyBinding]{}

		existingPolicyBindings[policy.Name].Add(removeArn(policy.UserBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.GroupBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.RoleBindings)...)
	}

	utils.Logger.Info(fmt.Sprintf("Fetched existing %d managed policies", len(policyMap)))

	return policyMap, existingPolicyBindings, nil
}

func removeArn(input []model.PolicyBinding) []model.PolicyBinding {
	result := []model.PolicyBinding{}

	for _, val := range input {
		val.ResourceId = ""
		result = append(result, val)
	}

	return result
}
