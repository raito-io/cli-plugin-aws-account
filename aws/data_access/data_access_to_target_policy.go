package data_access

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/smithy-go/ptr"
	"github.com/gammazero/workerpool"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/golang-set/set"
)

func (a *AccessToTargetSyncer) handlePolicy(ctx context.Context, policy *sync_to_target.AccessProvider, newName string) []string {
	permissionSetsToProvision := set.NewSet[string]()

	nameToDelete := ""
	if policy.Delete {
		nameToDelete = newName
	}

	if policy.ExternalId != nil && *policy.ExternalId != "" {
		origName := getNameFromExternalId(*policy.ExternalId) // Parsing the name out of the external ID

		if newName != origName {
			nameToDelete = origName
		}
	}

	var existingPolicy *model.PolicyEntity
	var err error

	if nameToDelete != "" {
		utils.Logger.Info(fmt.Sprintf("Deleting policy %s", nameToDelete))

		// We're assuming that an AWS managed policy can't be deleted
		err = a.repo.DeleteManagedPolicy(ctx, nameToDelete, false)
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Error while removing policy %q: %s", nameToDelete, err.Error()))
		}

		if policy.Delete { // If we needed just to delete it, that's all we need to do
			return nil
		}
	} else {
		existingPolicy, err = a.repo.GetManagedPolicyByName(ctx, newName)
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Error while fetching existing policy %q: %s", newName, err.Error()))
			return nil
		}
	}

	existingUserBindings := set.NewSet[string]()
	existingGroupBindings := set.NewSet[string]()
	existingRoleBindings := set.NewSet[string]()

	statements := createPolicyStatementsFromWhat(policy.What, a.cfgMap)
	var policyArn string

	if existingPolicy == nil {
		utils.Logger.Info(fmt.Sprintf("Creating policy %s", newName))

		p, err2 := a.repo.CreateManagedPolicy(ctx, newName, statements)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to create managed policy %q: %s", newName, err2.Error()))
			return nil
		} else if p == nil {
			logFeedbackWarning(a.feedbackMap[policy.Id], fmt.Sprintf("Policy %q not created.", newName))
			return nil
		}

		policyArn = *p.Arn
	} else {
		policyArn = existingPolicy.ARN

		utils.Logger.Info(fmt.Sprintf("Updating policy %s", newName))

		err = a.repo.UpdateManagedPolicy(ctx, newName, false, statements)

		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to update managed policy %q: %s", newName, err.Error()))
			return nil
		}

		existingUserBindings.Add(policyBindingsToNames(existingPolicy.UserBindings)...)
		existingGroupBindings.Add(policyBindingsToNames(existingPolicy.GroupBindings)...)

		// Remove the SSO role bindings as they are handled differently
		for _, roleBinding := range existingPolicy.RoleBindings {
			if !strings.HasPrefix(roleBinding.ResourceName, constants.SsoReservedPrefix) {
				existingRoleBindings.Add(roleBinding.ResourceName)
			}
		}
	}

	parsedArn, err := arn.Parse(policyArn)
	if err != nil {
		logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to parse ARN %q: %s", parsedArn, err.Error()))
		return nil
	}

	isAWSManaged := strings.EqualFold(parsedArn.AccountID, "aws")

	a.lock.Lock()
	a.feedbackMap[policy.Id].ExternalId = ptr.String(constants.PolicyTypePrefix + newName)
	a.feedbackMap[policy.Id].ActualName = newName
	a.idToExternalIdMap[policy.Id] = constants.PolicyTypePrefix + newName
	a.lock.Unlock()

	// Now handling the WHO part of the policy
	a.handlePolicyWho(ctx, policy, newName, policyArn, existingUserBindings, existingGroupBindings, existingRoleBindings, isAWSManaged, permissionSetsToProvision)

	return permissionSetsToProvision.Slice()
}

func (a *AccessToTargetSyncer) handlePolicyWho(ctx context.Context, policy *sync_to_target.AccessProvider, newName string, policyArn string, existingUserBindings set.Set[string], existingGroupBindings set.Set[string], existingRoleBindings set.Set[string], isAWSManaged bool, permissionSetsToProvision set.Set[string]) {
	a.handlePolicyUsers(ctx, policy, newName, existingUserBindings, policyArn)

	a.handlePolicyGroups(ctx, policy, newName, existingGroupBindings, policyArn)

	// Adding and removing roles from the policy
	targetRoleBindings := set.NewSet[string]()
	ssoRoleBindingsToAdd := set.NewSet[string]()
	ssoRoleBindingsToRemove := set.NewSet[string]()

	for _, inherited := range policy.Who.InheritFrom {
		inheritedExternalId := inherited

		if strings.HasPrefix(inherited, "ID:") {
			id := inherited[3:] // Cutting off the 'ID:' prefix
			if externalId, found := a.idToExternalIdMap[id]; found {
				inheritedExternalId = externalId
			} else {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to attach dependency %q to managed policy %q", inherited, newName))
				continue
			}
		}

		if strings.HasPrefix(inheritedExternalId, constants.RoleTypePrefix) {
			targetRoleBindings.Add(getNameFromExternalId(inheritedExternalId))
		} else if strings.HasPrefix(inheritedExternalId, constants.SsoRoleTypePrefix) {
			ssoRoleBindingsToAdd.Add(getNameFromExternalId(inheritedExternalId))
		} else {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Invalid role reference %q in managed policy %q", inherited, newName))
			continue
		}
	}

	if policy.DeletedWho != nil {
		// For SSO roles, we need to work with explicit deletes because the owner of the link between policies and permissions sets is the permission set in this case.
		for _, inherited := range policy.DeletedWho.InheritFrom {
			inheritedExternalId := inherited

			if strings.HasPrefix(inherited, "ID:") {
				id := inherited[3:] // Cutting off the 'ID:' prefix
				if externalId, found := a.idToExternalIdMap[id]; found {
					inheritedExternalId = externalId
				} else {
					logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to detach dependency %q to managed policy %q", inherited, newName))
					continue
				}
			}

			if strings.HasPrefix(inheritedExternalId, constants.SsoRoleTypePrefix) {
				ssoRoleBindingsToRemove.Add(getNameFromExternalId(inheritedExternalId))
			}
		}
	}

	// Adding the IAM roles
	rolesToAdd := utils.SetSubtract(targetRoleBindings, existingRoleBindings)
	for _, role := range rolesToAdd.Slice() {
		utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to role: %s", newName, role))

		err := a.repo.AttachRoleToManagedPolicy(ctx, policyArn, []string{role})
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to attach role %q to managed policy %q: %s", role, newName, err.Error()))
			continue
		}
	}

	// Removing the IAM roles
	rolesToRemove := utils.SetSubtract(existingRoleBindings, targetRoleBindings)
	for _, role := range rolesToRemove.Slice() {
		utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from role: %s", newName, role))

		err := a.repo.DetachRoleFromManagedPolicy(ctx, policyArn, []string{role})
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to detach role %q from managed policy %q: %s", role, newName, err.Error()))
			continue
		}
	}

	// Adding the SSO roles
	for _, ssoRole := range ssoRoleBindingsToAdd.Slice() {
		permSetArn, err2 := a.getPermissionSetArnFromExternalId(ctx, ssoRole)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[policy.Id], err2.Error())
			continue
		}

		// TODO check if not attached yet (or it may fail
		var err error
		if isAWSManaged {
			err = a.ssoRepo.AttachAwsManagedPolicyToPermissionSet(ctx, permSetArn, newName)
		} else {
			err = a.ssoRepo.AttachCustomerManagedPolicyToPermissionSet(ctx, permSetArn, newName, nil)
		}

		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Error while attaching policy %q to permission set %q: %s", newName, permSetArn, err.Error()))
		}

		permissionSetsToProvision.Add(permSetArn)
	}

	// Removing the SSO roles
	for _, ssoRole := range ssoRoleBindingsToRemove.Slice() {
		permSetArn, err2 := a.getPermissionSetArnFromExternalId(ctx, ssoRole)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[policy.Id], err2.Error())
			continue
		}

		// TODO check if actually attached (or it will fail)
		var err error
		if isAWSManaged {
			err = a.ssoRepo.DetachAwsManagedPolicyFromPermissionSet(ctx, permSetArn, newName)
		} else {
			err = a.ssoRepo.DetachCustomerManagedPolicyFromPermissionSet(ctx, permSetArn, newName, nil)
		}

		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Error while detaching policy %q from permission set %q: %s", newName, permSetArn, err.Error()))
		}

		permissionSetsToProvision.Add(permSetArn)
	}
}

func (a *AccessToTargetSyncer) handlePolicyGroups(ctx context.Context, policy *sync_to_target.AccessProvider, newName string, existingGroupBindings set.Set[string], policyArn string) { //nolint:dupl
	// Adding and removing groups from the policy
	targetGroupBindings := set.NewSet[string](policy.Who.Groups...)

	groupsToAdd := utils.SetSubtract(targetGroupBindings, existingGroupBindings)
	for _, group := range groupsToAdd.Slice() {
		utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to group: %s", newName, group))

		err := a.repo.AttachGroupToManagedPolicy(ctx, policyArn, []string{group})
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to attach group %q to managed policy %q: %s", group, newName, err.Error()))
			continue
		}
	}

	groupsToRemove := utils.SetSubtract(existingGroupBindings, targetGroupBindings)
	for _, group := range groupsToRemove.Slice() {
		utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from group: %s", newName, group))

		err := a.repo.DetachGroupFromManagedPolicy(ctx, policyArn, []string{group})
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to detach group %q from managed policy %q: %s", group, newName, err.Error()))
			continue
		}
	}
}

func (a *AccessToTargetSyncer) handlePolicyUsers(ctx context.Context, policy *sync_to_target.AccessProvider, newName string, existingUserBindings set.Set[string], policyArn string) { //nolint:dupl
	// Adding and removing users from the policy
	targetUserBindings := set.NewSet[string](policy.Who.Users...)

	usersToAdd := utils.SetSubtract(targetUserBindings, existingUserBindings)
	for _, user := range usersToAdd.Slice() {
		utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to user: %s", newName, user))

		err := a.repo.AttachUserToManagedPolicy(ctx, policyArn, []string{user})
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to attach user %q to managed policy %q: %s", user, newName, err.Error()))
			continue
		}
	}

	usersToRemove := utils.SetSubtract(existingUserBindings, targetUserBindings)
	for _, user := range usersToRemove.Slice() {
		utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", newName, user))

		err := a.repo.DetachUserFromManagedPolicy(ctx, policyArn, []string{user})
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to detach user %q from managed policy %q: %s", user, newName, err.Error()))
			continue
		}
	}
}

func (a *AccessToTargetSyncer) handlePolicies(ctx context.Context) []string {
	permissionSetsToProvision := set.NewSet[string]()

	wp := workerpool.New(workerPoolSize)
	var lock sync.Mutex

	for _, policy := range a.Policies {
		// Doing this synchronous as it is not thread-safe and fast enough
		name, err := a.nameGenerator.GenerateName(policy, model.Policy)
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Error while generating name for policy %q: %s", policy.Name, err.Error()))
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Generated policy name %q for grant %q", name, policy.Name))

		wp.Submit(func() {
			permSets := a.handlePolicy(ctx, policy, name)

			if len(permSets) > 0 {
				lock.Lock()
				permissionSetsToProvision.Add(permSets...)
				lock.Unlock()
			}
		})
	}

	wp.StopWait()

	return permissionSetsToProvision.Slice()
}

func (a *AccessToTargetSyncer) getPermissionSetArnFromExternalId(ctx context.Context, ssoRole string) (string, error) {
	existingPermissionSets, err := a.fetchExistingPermissionSets(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch existing permission sets to link policies to: %s", err.Error())
	}

	ssoRoleName := getNameFromExternalId(ssoRole) // Parsing the name out of the external ID

	if permSet, f := existingPermissionSets[ssoRoleName]; !f {
		return "", fmt.Errorf("permission set %q not found", ssoRoleName)
	} else {
		return permSet.arn, nil
	}
}

func policyBindingsToNames(bindings []model.PolicyBinding) []string {
	names := make([]string, 0, len(bindings))

	for _, binding := range bindings {
		names = append(names, binding.ResourceName)
	}

	return names
}
