package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/golang-set/set"

	"github.com/aws/smithy-go/ptr"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"
)

func (a *AccessSyncer) SyncAccessProvidersFromTarget(ctx context.Context, accessProviderHandler wrappers.AccessProviderHandler, configMap *config.ConfigMap) error {
	a.repo = iam.NewAwsIamRepository(configMap)

	return a.doSyncAccessProvidersFromTarget(ctx, accessProviderHandler, configMap)
}

func (a *AccessSyncer) doSyncAccessProvidersFromTarget(ctx context.Context, accessProviderHandler wrappers.AccessProviderHandler, configMap *config.ConfigMap) error {
	apImportList, err := a.fetchAllAccessProviders(ctx, configMap)
	if err != nil {
		return err
	}

	filteredList := filterApImportList(apImportList)

	utils.Logger.Info(fmt.Sprintf("Keeping %d acces providers after filtering", len(filteredList)))

	err = newRoleEnricher(ctx, configMap).enrich(filteredList)
	if err != nil {
		return err
	}

	err = accessProviderHandler.AddAccessProviders(getProperFormatForImport(filteredList)...)

	return err
}

func filterApImportList(importList []model.AccessProviderInputExtended) []model.AccessProviderInputExtended {
	toKeep := set.NewSet[string]()

	utils.Logger.Debug("Start filtering for relevant access providers")

	for _, apInput := range importList {
		if apInput.PolicyType == model.Role || apInput.PolicyType == model.SSORole {
			// Elements in the WHAT here already means that there are relevant permissions
			if len(apInput.ApInput.What) > 0 {
				utils.Logger.Debug(fmt.Sprintf("Keeping role %q", apInput.ApInput.ActualName))

				toKeep.Add(apInput.ApInput.ActualName)
			} else {
				utils.Logger.Debug(fmt.Sprintf("Skipping role %q as it has no WHAT elements", apInput.ApInput.ActualName))
			}

			continue
		} else if apInput.PolicyType == model.Policy {
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
				utils.Logger.Debug(fmt.Sprintf("Keeping policy %q", apInput.ApInput.ActualName))
				toKeep.Add(apInput.ApInput.ActualName)

				for _, who := range apInput.ApInput.Who.AccessProviders {
					utils.Logger.Debug(fmt.Sprintf("Re-adding role %q", who))
					toKeep.Add(who)
				}
			} else {
				utils.Logger.Debug(fmt.Sprintf("Skipping policy %q as it has no relevant permissions/resources", apInput.ApInput.ActualName))
			}
		}
	}

	result := make([]model.AccessProviderInputExtended, 0, len(toKeep))

	for _, apInput := range importList {
		if toKeep.Contains(apInput.ApInput.ActualName) {
			result = append(result, apInput)
		}
	}

	return result
}

func (a *AccessSyncer) fetchRoleAccessProviders(configMap *config.ConfigMap, roles []model.RoleEntity, aps []model.AccessProviderInputExtended) []model.AccessProviderInputExtended {
	utils.Logger.Info("Get all roles")

	for _, role := range roles {
		isRaito := false

		for _, tag := range role.Tags {
			if tag.Key == "creator" && tag.Value == "raito" {
				isRaito = true
			}
		}

		if isRaito {
			// TODO later, we need to continue as we possibly need to import the (locked) who or what
			utils.Logger.Info(fmt.Sprintf("Ignoring role %q as it is managed by Raito", role.Name))
			continue
		}

		var whoItem *sync_from_target.WhoItem
		incomplete := false

		if role.AssumeRolePolicyDocument != nil {
			whoItem, incomplete = iam.CreateWhoFromTrustPolicyDocument(role.AssumeRolePolicy, role.Name, configMap)
		}

		aps = append(aps, model.AccessProviderInputExtended{
			LastUsedDate: role.LastUsedDate,
			PolicyType:   model.Role,
			ApInput: &sync_from_target.AccessProvider{
				ExternalId: constants.RoleTypePrefix + role.Name,
				Name:       role.Name,
				ActualName: role.Name,
				NamingHint: role.Name,
				Type:       aws.String(string(model.Role)),
				Action:     sync_from_target.Grant,
				Policy:     "",
				Who:        whoItem,
				What:       []sync_from_target.WhatItem{},
				Incomplete: ptr.Bool(incomplete),
			}})
	}

	return aps
}

func (a *AccessSyncer) fetchManagedPolicyAccessProviders(ctx context.Context, configMap *config.ConfigMap, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) {
	utils.Logger.Info("Get all managed policies")
	policies, err := a.repo.GetManagedPolicies(ctx)

	if err != nil {
		return nil, err
	}

	if policies == nil {
		return nil, err
	}

	for ind := range policies {
		policy := policies[ind]

		utils.Logger.Info(fmt.Sprintf("Handling managed policy %q", policy.Name))

		isAWSManaged := strings.HasPrefix(policy.ARN, "arn:aws:iam::aws:")

		var groupBindings []string
		var userBindings []string
		var roleBindings []string

		isRaito := false

		for _, tag := range policy.Tags {
			if tag.Key == "creator" && tag.Value == "raito" {
				isRaito = true
			}
		}

		if isRaito {
			// TODO later, we need to continue as we possibly need to import the (locked) who or what
			utils.Logger.Info(fmt.Sprintf("Ignoring managed policy %q as it is managed by Raito", policy.Name))
			continue
		}

		for _, groupBinding := range policy.GroupBindings {
			groupBindings = append(groupBindings, groupBinding.ResourceName)
		}

		for _, userBinding := range policy.UserBindings {
			userBindings = append(userBindings, userBinding.ResourceName)
		}

		for _, roleBinding := range policy.RoleBindings {
			roleBindings = append(roleBindings, roleBinding.ResourceName)
		}

		if len(groupBindings) == 0 && len(userBindings) == 0 && len(roleBindings) == 0 {
			utils.Logger.Info(fmt.Sprintf("Skipping managed policy %s, no user/group/role bindings", policy.Name))
			continue
		}

		whatItems, incomplete := iam.CreateWhatFromPolicyDocument(policy.PolicyParsed, policy.Name, configMap)

		policyDocument := ""
		if policy.PolicyDocument != nil {
			policyDocument = *policy.PolicyDocument
		}

		prefixedName := fmt.Sprintf("%s%s", constants.PolicyPrefix, policy.Name)

		apInput := sync_from_target.AccessProvider{
			ExternalId: constants.PolicyTypePrefix + policy.Name,
			Name:       policy.Name,
			ActualName: prefixedName,
			Type:       aws.String(string(model.Policy)),
			NamingHint: prefixedName,
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

		aps = append(aps, model.AccessProviderInputExtended{
			PolicyType: model.Policy,
			ApInput:    &apInput,
		})
	}

	return aps, nil
}

func convertPoliciesToWhat(policies []model.PolicyEntity, configMap *config.ConfigMap) ([]sync_from_target.WhatItem, bool, string) {
	var whatItems []sync_from_target.WhatItem
	incomplete := false
	policyDocuments := ""

	for i := range policies {
		policy := policies[i]
		policyWhat, policyIncomplete := iam.CreateWhatFromPolicyDocument(policy.PolicyParsed, policy.Name, configMap)

		if policy.PolicyDocument != nil {
			policyDocuments += *policy.PolicyDocument + "\n"
		}

		for _, what := range policyWhat {
			whatItems = mergeWhatItem(whatItems, what)
		}

		if policyIncomplete {
			incomplete = true
		}
	}

	return whatItems, incomplete, policyDocuments
}

func mergeWhatItem(whatItems []sync_from_target.WhatItem, what sync_from_target.WhatItem) []sync_from_target.WhatItem {
	if len(what.Permissions) > 0 && what.DataObject != nil {
		var existingWhat *sync_from_target.WhatItem
		var existingIndex int

		for i := range whatItems {
			w := whatItems[i]
			if w.DataObject.FullName == what.DataObject.FullName {
				existingWhat = &w
				existingIndex = i

				break
			}
		}

		if existingWhat == nil {
			whatItems = append(whatItems, what)
		} else {
			permissionSet := set.NewSet[string](what.Permissions...)
			permissionSet.Add(existingWhat.Permissions...)
			perms := permissionSet.Slice()
			sort.Strings(perms)
			existingWhat.Permissions = perms
			whatItems[existingIndex] = *existingWhat
		}
	}

	return whatItems
}

func (a *AccessSyncer) fetchInlineUserPolicyAccessProviders(ctx context.Context, configMap *config.ConfigMap, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) { //nolint:dupl
	userPolicies, err := a.getInlinePoliciesOnUsers(ctx)
	if err != nil {
		return nil, err
	}

	for user, policies := range userPolicies {
		whatItems, incomplete, policyDocuments := convertPoliciesToWhat(policies, configMap)

		name := "User " + user + " inline policies"

		var policyIds strings.Builder
		for i := range policies {
			policyIds.WriteString(policies[i].Name)
			policyIds.WriteString("|")
		}

		aps = append(aps, model.AccessProviderInputExtended{
			PolicyType: model.Policy,
			ApInput: &sync_from_target.AccessProvider{
				// As internal policies don't have an ID we use the policy ARN
				ExternalId: constants.UserTypePrefix + user + "|" + constants.InlinePrefix + policyIds.String(),
				Name:       name,
				Type:       aws.String(string(model.Policy)),
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

	return aps, nil
}

func (a *AccessSyncer) fetchInlineGroupPolicyAccessProviders(ctx context.Context, configMap *config.ConfigMap, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) { //nolint:dupl
	groupPolicies, err := a.getInlinePoliciesOnGroups(ctx)
	if err != nil {
		return nil, err
	}

	for group, policies := range groupPolicies {
		whatItems, incomplete, policyDocuments := convertPoliciesToWhat(policies, configMap)

		name := "Group " + group + " inline policies"

		var policyIds strings.Builder
		for i := range policies {
			policyIds.WriteString(policies[i].Name)
			policyIds.WriteString("|")
		}

		aps = append(aps, model.AccessProviderInputExtended{
			PolicyType: model.Policy,
			ApInput: &sync_from_target.AccessProvider{
				// As internal policies don't have an ID we use the policy ARN
				ExternalId: constants.GroupTypePrefix + group + "|" + constants.InlinePrefix + policyIds.String(),
				Name:       name,
				Type:       aws.String(string(model.Policy)),
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

	return aps, nil
}

func (a *AccessSyncer) fetchInlineRolePolicyAccessProviders(ctx context.Context, configMap *config.ConfigMap, roles []model.RoleEntity, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) {
	rolePolicies, err := a.getInlinePoliciesOnRoles(ctx, roles)
	if err != nil {
		return nil, err
	}

	for role, policies := range rolePolicies {
		var roleAp *sync_from_target.AccessProvider

		for _, ap := range aps {
			if ap.PolicyType == model.Role && ap.ApInput.Name == role {
				roleAp = ap.ApInput
			}
		}

		if roleAp == nil {
			utils.Logger.Error(fmt.Sprintf("Could not find role %q", role))
			continue
		}

		whatItems, incomplete, policyDocuments := convertPoliciesToWhat(policies, configMap)

		var policyIds strings.Builder
		for i := range policies {
			policyIds.WriteString(policies[i].Name)
			policyIds.WriteString("|")
		}

		roleAp.ExternalId = constants.RoleTypePrefix + role + "|" + constants.InlinePrefix + policyIds.String()
		roleAp.Policy = policyDocuments
		roleAp.What = whatItems
		roleAp.Incomplete = ptr.Bool(incomplete || (roleAp.Incomplete != nil && *roleAp.Incomplete))
	}

	return aps, nil
}

func (a *AccessSyncer) FetchS3AccessPointAccessProviders(ctx context.Context, configMap *config.ConfigMap, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) {
	accessPoints, err := a.repo.ListAccessPoints(ctx)
	if err != nil {
		return nil, err
	}

	for _, accessPoint := range accessPoints {
		newAp := model.AccessProviderInputExtended{
			PolicyType: model.AccessPoint,
			ApInput: &sync_from_target.AccessProvider{
				// As internal policies don't have an ID we use the policy ARN
				ExternalId: accessPoint.Arn,
				Name:       accessPoint.Name,
				Type:       aws.String(string(model.AccessPoint)),
				NamingHint: "",
				ActualName: accessPoint.Name,
				Action:     sync_from_target.Grant,
			}}

		if accessPoint.PolicyDocument != nil {
			newAp.ApInput.Policy = *accessPoint.PolicyDocument
		}

		incomplete := false
		newAp.ApInput.Who, newAp.ApInput.What, incomplete = iam.CreateWhoAndWhatFromAccessPointPolicy(accessPoint.PolicyParsed, accessPoint.Bucket, accessPoint.Name, configMap)

		if incomplete {
			newAp.ApInput.Incomplete = ptr.Bool(true)
		}

		aps = append(aps, newAp)
	}

	return aps, nil
}

func (a *AccessSyncer) fetchAllAccessProviders(ctx context.Context, configMap *config.ConfigMap) ([]model.AccessProviderInputExtended, error) {
	var apImportList []model.AccessProviderInputExtended

	if !configMap.GetBool(constants.AwsAccessSkipIAM) {
		roles, err := a.repo.GetRoles(ctx)
		if err != nil {
			return nil, err
		}

		// Adding access providers to the list for the roles
		apImportList = a.fetchRoleAccessProviders(configMap, roles, apImportList)

		if !configMap.GetBool(constants.AwsAccessSkipManagedPolicies) {
			// Adding access providers to the list for the managed policies
			apImportList, err = a.fetchManagedPolicyAccessProviders(ctx, configMap, apImportList)
			if err != nil {
				return nil, err
			}
		}

		if !configMap.GetBool(constants.AwsAccessSkipUserInlinePolicies) {
			apImportList, err = a.fetchInlineUserPolicyAccessProviders(ctx, configMap, apImportList)
			if err != nil {
				return nil, err
			}
		}

		if !configMap.GetBool(constants.AwsAccessSkipGroupInlinePolicies) {
			apImportList, err = a.fetchInlineGroupPolicyAccessProviders(ctx, configMap, apImportList)
			if err != nil {
				return nil, err
			}
		}

		// Adding access providers to the list for the inline policies (existing role access providers will be enriched with inline policies it may have)
		apImportList, err = a.fetchInlineRolePolicyAccessProviders(ctx, configMap, roles, apImportList)
		if err != nil {
			return nil, err
		}
	}

	if !configMap.GetBool(constants.AwsAccessSkipS3AccessPoints) {
		var err error

		apImportList, err = a.FetchS3AccessPointAccessProviders(ctx, configMap, apImportList)
		if err != nil {
			return nil, err
		}
	}

	return apImportList, nil
}

func (a *AccessSyncer) getInlinePoliciesOnGroups(ctx context.Context) (map[string][]model.PolicyEntity, error) {
	utils.Logger.Info("Get inline policies from groups")
	groups, err := a.repo.GetGroups(ctx)

	if err != nil {
		return nil, err
	}

	groupNames := []string{}
	for _, g := range groups {
		groupNames = append(groupNames, g.Name)
	}

	return a.repo.GetInlinePoliciesForEntities(ctx, groupNames, iam.GroupResourceType)
}
func (a *AccessSyncer) getInlinePoliciesOnUsers(ctx context.Context) (map[string][]model.PolicyEntity, error) {
	utils.Logger.Info("Get inline policies from users")

	users, err := a.repo.GetUsers(ctx, false)
	if err != nil {
		return nil, err
	}

	userNames := []string{}
	for _, u := range users {
		userNames = append(userNames, u.Name)
	}

	return a.repo.GetInlinePoliciesForEntities(ctx, userNames, iam.UserResourceType)
}

func (a *AccessSyncer) getInlinePoliciesOnRoles(ctx context.Context, roles []model.RoleEntity) (map[string][]model.PolicyEntity, error) {
	utils.Logger.Info("Get inline policies from roles")

	roleNames := []string{}
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	return a.repo.GetInlinePoliciesForEntities(ctx, roleNames, iam.RoleResourceType)
}

func getProperFormatForImport(input []model.AccessProviderInputExtended) []*sync_from_target.AccessProvider {
	result := make([]*sync_from_target.AccessProvider, 0, len(input))

	for _, ap := range input {
		if ap.ApInput == nil {
			utils.Logger.Warn(fmt.Sprintf("Access provider input with type %q is nil", ap.PolicyType))
			continue
		}

		result = append(result, ap.ApInput)
	}

	return result
}
