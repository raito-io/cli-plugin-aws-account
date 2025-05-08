package data_access

import (
	"context"
	"fmt"
	"strings"

	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go/ptr"
	"github.com/gammazero/workerpool"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils/bimap"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/golang-set/set"
)

func (a *AccessToTargetSyncer) handleSSORole(ctx context.Context, role *sync_to_target.AccessProvider, name string) string {
	if a.ssoRepo == nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("SSO repository is not initialized. Make sure to configure the parameters %s and %s.", constants.AwsOrganizationIdentityCenterInstanceArn, constants.AwsOrganizationIdentityStore))
		return ""
	}

	if role.ExternalId != nil {
		origName := getNameFromExternalId(*role.ExternalId) // Parsing the name out of the external ID

		if name != origName {
			utils.Logger.Warn(fmt.Sprintf("New name %q does not correspond with current name %q. Renaming is currently not supported, so keeping the old name.", name, origName))
			name = origName
		}
	}

	existingPermissionSets, err := a.fetchExistingPermissionSets(ctx)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while fetching existing permission sets: %s", err.Error()))
		return ""
	}

	existingPermissionSet := existingPermissionSets[name]

	if role.Delete {
		if existingPermissionSet == nil {
			utils.Logger.Info(fmt.Sprintf("No existing permission set found for role %q. Skipping deletion.", name))
			return ""
		}

		utils.Logger.Info(fmt.Sprintf("Deleting permission set %s", role.Name))

		err2 := a.ssoRepo.DeleteSsoRole(ctx, existingPermissionSet.arn)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while removing permission set %q: %s", name, err2.Error()))
		}

		return ""
	}

	permissionSetArn := ""

	if len(role.Description) < 1 {
		logFeedbackError(a.feedbackMap[role.Id], "The description for a Permission Set is mandatory. Please provide a description for the grant.")
		return ""
	}

	tags := a.generateSsoTags(role)

	if existingPermissionSet == nil {
		utils.Logger.Info(fmt.Sprintf("Creating permission set %q", name))

		permissionSetArn, err = a.ssoRepo.CreateSsoRole(ctx, name, role.Description, tags)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to create permission set %q: %s", name, err.Error()))
			return ""
		}

		if permissionSetArn == "" {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to create permission set %q: no ARN returned", name))
			return ""
		}
	} else {
		utils.Logger.Info(fmt.Sprintf("Updating permission set %q with tags %v", name, tags))

		permissionSetArn = existingPermissionSet.arn

		// Update the permission set name
		err = a.ssoRepo.UpdateSsoRole(ctx, existingPermissionSet.arn, role.Description, tags)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to update permission set %q: %s", name, err.Error()))
			return ""
		}
	}

	a.lock.Lock()
	a.feedbackMap[role.Id].ExternalId = ptr.String(constants.SsoRoleTypePrefix + name)
	a.feedbackMap[role.Id].ActualName = name
	a.idToExternalIdMap[role.Id] = constants.SsoRoleTypePrefix + name
	a.lock.Unlock()

	// Update who
	existingBindings := set.NewSet[model.PolicyBinding]()
	if existingPermissionSet != nil {
		existingBindings = existingPermissionSet.bindings
	}

	a.updatePermissionSetWho(ctx, role, existingBindings, permissionSetArn, name)

	// Update What
	a.updatePermissionSetWhat(ctx, role, name, permissionSetArn)

	return permissionSetArn
}

func (a *AccessToTargetSyncer) generateSsoTags(role *sync_to_target.AccessProvider) map[string]string {
	tags := map[string]string{
		"creator": "RAITO", // Always settings this tag to identify Raito created permission sets
	}

	customTagsString := a.cfgMap.GetString(constants.AwsPermissionSetCustomTags)

	if customTagsString != "" {
		for _, tag := range strings.Split(customTagsString, ",") {
			tagSplit := strings.Split(tag, ":")

			if len(tagSplit) == 2 {
				tags[strings.TrimSpace(tagSplit[0])] = strings.TrimSpace(tagSplit[1])
			} else {
				utils.Logger.Warn(fmt.Sprintf("Invalid custom tags value %q, ignoring...", tag))
			}
		}
	}

	accountIdTagString := strings.TrimSpace(a.cfgMap.GetString(constants.AwsPermissionSetAccountIdTag))

	if accountIdTagString != "" {
		for _, tagKey := range strings.Split(accountIdTagString, ",") {
			tagKey = strings.TrimSpace(tagKey)

			if tagKey != "" {
				tags[tagKey] = a.accessSyncer.account
			}
		}
	}

	// Helper function to generate tag values from owners
	generateOwnerTagValue := func(tagKeyString string, owners []sync_to_target.Owner, getValue func(sync_to_target.Owner) (string, bool)) {
		tagValues := set.NewSet[string]()

		for _, owner := range owners {
			if value, ok := getValue(owner); ok {
				tagValues.Add(value)
			}
		}

		tagValueString := strings.Join(tagValues.Slice(), "/") // Using "/" as a separator because many others are not allowed in tags

		for _, tagKey := range strings.Split(tagKeyString, ",") {
			tagKey = strings.TrimSpace(tagKey)

			if tagKey != "" {
				tags[tagKey] = tagValueString
			}
		}
	}

	if emailTag, found := a.cfgMap.Parameters[constants.AwsPermissionSetOwnerEmailTag]; found && emailTag != "" {
		generateOwnerTagValue(emailTag, role.Owners, func(owner sync_to_target.Owner) (string, bool) {
			if owner.Email != nil && *owner.Email != "" {
				return *owner.Email, true
			}

			return "", false
		})
	}

	if nameTag, found := a.cfgMap.Parameters[constants.AwsPermissionSetOwnerNameTag]; found && nameTag != "" {
		generateOwnerTagValue(nameTag, role.Owners, func(owner sync_to_target.Owner) (string, bool) {
			if owner.AccountName != nil && *owner.AccountName != "" {
				return *owner.AccountName, true
			}

			return "", false
		})
	}

	if groupTag, found := a.cfgMap.Parameters[constants.AwsPermissionSetOwnerGroupTag]; found && groupTag != "" {
		generateOwnerTagValue(groupTag, role.Owners, func(owner sync_to_target.Owner) (string, bool) {
			if owner.GroupName != nil && *owner.GroupName != "" {
				return *owner.GroupName, true
			}

			return "", false
		})
	}

	return tags
}

func (a *AccessToTargetSyncer) updatePermissionSetWho(ctx context.Context, role *sync_to_target.AccessProvider, existingBindings set.Set[model.PolicyBinding], permissionSetArn string, name string) {
	targetBindings := set.NewSet[model.PolicyBinding]()

	for _, user := range role.Who.Users {
		targetBindings.Add(model.PolicyBinding{
			Type:         iam.UserResourceType,
			ResourceName: user,
		})
	}

	for _, group := range role.Who.Groups {
		targetBindings.Add(model.PolicyBinding{
			Type:         iam.GroupResourceType,
			ResourceName: group,
		})
	}

	users, err := a.ssoRepo.GetUsers(ctx)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("failed to get users: %s", err.Error()))

		return
	}

	groups, err := a.ssoRepo.GetGroups(ctx)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("failed to get groups: %s", err.Error()))

		return
	}

	bindingsToAdd := utils.SetSubtract(targetBindings, existingBindings)
	for binding := range bindingsToAdd {
		principalType, principalId, err2 := a.handlePermissionSetBindings(binding, users, groups)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[role.Id], err2.Error())
			continue
		}

		err = a.ssoRepo.AssignPermissionSet(ctx, permissionSetArn, principalType, principalId)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to add %s %q to permission set %q: %s", principalType, binding.ResourceName, name, err.Error()))
		}
	}

	bindingsToRemove := utils.SetSubtract(existingBindings, targetBindings)
	for binding := range bindingsToRemove {
		principalType, principalId, err2 := a.handlePermissionSetBindings(binding, users, groups)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[role.Id], err2.Error())
			continue
		}

		err = a.ssoRepo.UnassignPermissionSet(ctx, permissionSetArn, principalType, principalId)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to remove %s %q from permission set %q: %s", principalType, binding.ResourceName, name, err.Error()))
		}
	}
}

func (a *AccessToTargetSyncer) handlePermissionSetBindings(binding model.PolicyBinding, users bimap.Bimap[string, string], groups bimap.Bimap[string, string]) (ssoTypes.PrincipalType, string, error) {
	var principalType ssoTypes.PrincipalType
	var principalId string

	if binding.Type == iam.UserResourceType {
		principalType = ssoTypes.PrincipalTypeUser
		principalId, _ = users.GetBackwards(binding.ResourceName)

		if principalId == "" {
			return "", "", fmt.Errorf("failed to find user to assign %q", binding.ResourceName)
		}

		return principalType, principalId, nil
	} else if binding.Type == iam.GroupResourceType {
		principalType = ssoTypes.PrincipalTypeGroup
		principalId, _ = groups.GetBackwards(binding.ResourceName)

		if principalId == "" {
			return "", "", fmt.Errorf("failed to find group to assign %q", binding.ResourceName)
		}

		return principalType, principalId, nil
	}

	return "", "", fmt.Errorf("unknown binding type %q", binding.Type)
}

func (a *AccessToTargetSyncer) updatePermissionSetWhat(ctx context.Context, role *sync_to_target.AccessProvider, name string, permissionSetArn string) {
	// Note: the WHAT are only the direct data objects now. The other WHAT are handled with the updates in the policies.
	statements := createPolicyStatementsFromWhat(role.What, a.cfgMap)

	err := a.ssoRepo.UpdateInlinePolicyToPermissionSet(ctx, permissionSetArn, statements)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to update inline policy for permission set %q: %s", name, err.Error()))
	}
}

type permissionSetData struct {
	name     string
	arn      string
	bindings set.Set[model.PolicyBinding]
}

func (a *AccessToTargetSyncer) clearPermissionSetsCache() {
	a.cachedPermissionSets = nil
}

func (a *AccessToTargetSyncer) fetchExistingPermissionSets(ctx context.Context) (map[string]*permissionSetData, error) {
	if a.cachedPermissionSets != nil {
		return a.cachedPermissionSets, nil
	}

	utils.Logger.Info("Start loading existing permission sets")

	result := make(map[string]*permissionSetData)

	permissionSetArns, err := a.ssoRepo.ListSsoRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching existing permission sets: %w", err)
	}

	users, err := a.ssoRepo.GetUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("get users: %w", err)
	}

	groups, err := a.ssoRepo.GetGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("get groups: %w", err)
	}

	for _, psArn := range permissionSetArns {
		createdByRaito, err2 := a.ssoRepo.HasRaitoCreatedTag(ctx, psArn)
		if err2 != nil {
			return nil, fmt.Errorf("get raito created tag: %w", err2)
		}

		if !createdByRaito {
			utils.Logger.Info(fmt.Sprintf("Skipping permission set %q as it was not created by Raito", psArn))

			continue
		}

		permissionSetDetails, err2 := a.ssoRepo.GetSsoRole(ctx, psArn)
		if err2 != nil {
			return nil, fmt.Errorf("get permission set details: %w", err2)
		}

		assignments, err2 := a.ssoRepo.ListPermissionSetAssignment(ctx, psArn)
		if err2 != nil {
			return nil, fmt.Errorf("fetching existing permission set assignments: %w", err2)
		}

		bindings := set.NewSet[model.PolicyBinding]()

		for _, assignment := range assignments {
			var assignmentType string
			var principleName string
			var found bool

			if assignment.PrincipalType == ssoTypes.PrincipalTypeUser {
				assignmentType = iam.UserResourceType

				principleName, found = users.GetForward(*assignment.PrincipalId)
				if !found {
					utils.Logger.Warn(fmt.Sprintf("No username found for %q", *assignment.PrincipalId))
					principleName = *assignment.PrincipalId
				}
			} else if assignment.PrincipalType == ssoTypes.PrincipalTypeGroup {
				assignmentType = iam.GroupResourceType

				principleName, found = groups.GetForward(*assignment.PrincipalId)
				if !found {
					utils.Logger.Warn(fmt.Sprintf("No groupname found for %q", *assignment.PrincipalId))
					principleName = *assignment.PrincipalId
				}
			} else {
				continue
			}

			bindings.Add(model.PolicyBinding{
				Type:         assignmentType,
				ResourceName: principleName,
			})
		}

		result[*permissionSetDetails.Name] = &permissionSetData{
			name:     *permissionSetDetails.Name,
			arn:      *permissionSetDetails.PermissionSetArn,
			bindings: bindings,
		}
	}

	a.cachedPermissionSets = result

	return a.cachedPermissionSets, nil
}

func (a *AccessToTargetSyncer) handleSSORoles(ctx context.Context) []string {
	wp := workerpool.New(workerPoolSize)
	permissionSetsDone := set.NewSet[string]()

	for _, ssoRole := range a.PermissionSets {
		// Doing this synchronous as it is not thread-safe and fast enough
		name, err := a.nameGenerator.GenerateName(ssoRole, model.SSORole)
		if err != nil {
			logFeedbackError(a.feedbackMap[ssoRole.Id], fmt.Sprintf("Error while generating name for SSO role %q: %s", ssoRole.Name, err.Error()))
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Generated role name %q for grant %q", name, ssoRole.Name))

		wp.Submit(func() {
			permissionArn := a.handleSSORole(ctx, ssoRole, name)

			if permissionArn != "" {
				a.lock.Lock()
				permissionSetsDone.Add(permissionArn)
				a.lock.Unlock()
			}
		})
	}

	wp.StopWait()

	a.clearPermissionSetsCache() // Clearing the cache to make sure we fetch all the newly created ones.

	return permissionSetsDone.Slice()
}
