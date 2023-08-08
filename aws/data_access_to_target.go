package aws

import (
	"context"
	"fmt"
	"strings"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"
	"github.com/raito-io/golang-set/set"
)

func (a *AccessSyncer) SyncAccessProviderToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler, configMap *config.ConfigMap) error {
	a.repo = &AwsIamRepository{
		ConfigMap: configMap,
	}

	if accessProviders == nil || len(accessProviders.AccessProviders) == 0 {
		logger.Info("No access providers to sync from Raito to AWS")
		return nil
	}

	logger.Info(fmt.Sprintf("Provisioning %d access providers to AWS", len(accessProviders.AccessProviders)))

	policyActionMap, existingPolicyBindings, err := a.fetchExistingManagedPolicies(ctx)
	if err != nil {
		return err
	}

	roleActionMap, existingRoleAssumptions, err := a.fetchExistingRoles(ctx)
	if err != nil {
		return err
	}

	inlineActionPolicyMap := map[string]string{}
	inlinePolicyWithEntityMap := map[string]PolicyBinding{}

	managedPoliciesToModify := []AccessWithWho{}
	policyBindingsFromExport := map[string]set.Set[PolicyBinding]{}
	policyInheritanceMap := map[string]set.Set[string]{}

	for i := range accessProviders.AccessProviders {
		ap := accessProviders.AccessProviders[i]

		if ap == nil {
			continue
		}

		if ap.Type == nil {
			logger.Warn(fmt.Sprintf("No type provided for access provider %q", ap.Name))
			continue
		}

		apActionMap := &policyActionMap
		if strings.Contains(*ap.Type, "role") {
			apActionMap = &roleActionMap
		} else if strings.Contains(*ap.Type, "inline") {
			apActionMap = &inlineActionPolicyMap
		}

		printDebugAp(*ap)

		err = accessProviderFeedbackHandler.AddAccessProviderFeedback(ap.Id, sync_to_target.AccessSyncFeedbackInformation{AccessId: ap.Id, ActualName: ap.Name})
		if err != nil {
			return err
		}

		name := getPolicyName(ap)

		_, found := (*apActionMap)[name]

		if ap.Delete {
			if found {
				(*apActionMap)[name] = DeleteAction
			}

			continue
		} else if strings.Contains(*ap.Type, "role") {
			action := UpdateAction
			if !found {
				action = CreateAction
			}
			(*apActionMap)[name] = action
		} else if strings.Contains(*ap.Type, "managed_policy") {
			managedPoliciesToModify = append(managedPoliciesToModify, AccessWithWho{
				Name: name,
				What: ap.What,
				// Who:  ap.Who, // irrelevant, is through binding
			})
			action := ""

			if !found {
				logger.Info(fmt.Sprintf("Policy with name %s not found in existing policies. Adding to create list.", name))
				action = CreateAction
			} else {
				logger.Info(fmt.Sprintf("Policy with name %s found. Adding to update list.", name))
				action = UpdateAction
			}
			(*apActionMap)[name] = action
		} else if strings.Contains(*ap.Type, "inline_policy") {
			var localErr error

			// always convert an internal inline policy to a managed policy
			entityName, entityType, localErr := a.repo.GetAttachedEntity(*ap)
			logger.Info("Processing inline policy %s, for entity %s/%s", ap.Name, entityType, entityName)
			if localErr != nil {
				return localErr
			}

			// Deleting the inline policy
			inlinePolicyWithEntityMap[name] = PolicyBinding{
				ResourceName: entityName,
				Type:         entityType,
			}
			inlineActionPolicyMap[name] = DeleteAction

			// Creating the managed policy instead
			managedPoliciesToModify = append(managedPoliciesToModify, AccessWithWho{
				Name: name,
				What: ap.What,
			})
			policyActionMap[name] = CreateAction
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

	err = processApInheritance(policyInheritanceMap, policyActionMap, roleActionMap, &policyBindingsFromExport, existingPolicyBindings)
	if err != nil {
		return err
	}

	// ============================================================
	// =============== Roles ======================================
	// ============================================================

	assumeRoles := map[string]set.Set[PolicyBinding]{}

	for role, roleAction := range roleActionMap {
		// only touch the access providers that are in the export
		if roleAction == UpdateAction || roleAction == CreateAction {
			logger.Info(fmt.Sprintf("Existing bindings for %s: %s", role, existingRoleAssumptions[role]))
			logger.Info(fmt.Sprintf("Export bindings for %s: %s", role, policyBindingsFromExport[role]))

			assumeRoles[role] = set.NewSet(policyBindingsFromExport[role].Slice()...)
		}
	}

	for roleName, action := range roleActionMap {
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

			err = a.repo.CreateRole(ctx, roleName, "", userNames)
			if err != nil {
				return err
			}
		} else if action == DeleteAction {
			logger.Info(fmt.Sprintf("Removing role %s", roleName))

			err = a.repo.DeleteRole(ctx, roleName)
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

		err = a.repo.UpdateAssumeEntities(ctx, roleName, userNames)
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

		logger.Info(fmt.Sprintf("Process policy %s, action: %s", policy.Name, policyActionMap[policy.Name]))

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

		if policyActionMap[policy.Name] == CreateAction {
			logger.Info(fmt.Sprintf("Creating policy %s", policy.Name))

			_, err = a.repo.CreateManagedPolicy(ctx, policy.Name, statements)
			if err != nil {
				return err
			}
		} else if policyActionMap[policy.Name] == UpdateAction {
			logger.Info(fmt.Sprintf("Updating policy %s", policy.Name))
			err = a.repo.UpdateManagedPolicy(ctx, policy.Name, statements)
			if err != nil {
				return err
			}
		}
	}

	for policy, policy_state := range policyActionMap {
		if policy_state == DeleteAction {
			logger.Info(fmt.Sprintf("Deleting managed policy: %s", policy))

			err = a.repo.DeleteManagedPolicy(ctx, policy)
			if err != nil {
				return err
			}
		}
	}

	policyBindingsToAdd := map[string]set.Set[PolicyBinding]{}
	policyBindingsToRemove := map[string]set.Set[PolicyBinding]{}

	for policy, policy_state := range policyActionMap {
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
		policyArn := a.repo.GetPolicyArn(policyName, configMap)

		for _, binding := range bindings.Slice() {
			if binding.Type == "user" {
				logger.Info(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = a.repo.AttachUserToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == "group" {
				logger.Info(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

				err = a.repo.AttachGroupToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == "role" {
				logger.Info(fmt.Sprintf("Attaching policy %s to user: %s", policyName, binding.ResourceName))

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
			if binding.Type == "user" {
				logger.Info(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = a.repo.DetachUserFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == "group" {
				logger.Info(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = a.repo.DetachGroupFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					return err
				}
			} else if binding.Type == "role" {
				logger.Info(fmt.Sprintf("Detaching policy %s from user: %s", policyName, binding.ResourceName))

				err = a.repo.DetachRoleFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
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

	for policy, policy_state := range inlineActionPolicyMap {
		if binding, found := inlinePolicyWithEntityMap[policy]; policy_state == DeleteAction && found {
			logger.Info(fmt.Sprintf("Deleting inline policy %s for %s/%s", policy, binding.Type, binding.ResourceName))

			err = a.repo.DeleteInlinePolicy(ctx, policy, binding.ResourceName, binding.Type)
			if err != nil {
				return err
			}
		}
	}

	return nil
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
				Type:         "user",
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

func getPolicyName(ap *sync_to_target.AccessProvider) string {
	name := ap.NamingHint
	name = strings.ReplaceAll(name, " ", "_")

	return name
}
