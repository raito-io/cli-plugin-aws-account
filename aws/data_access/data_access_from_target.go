package data_access

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/raito-io/cli/base/util/match"
	"github.com/raito-io/cli/base/util/slice"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	"github.com/aws/smithy-go/ptr"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"
)

func (a *AccessSyncer) SyncAccessProvidersFromTarget(ctx context.Context, accessProviderHandler wrappers.AccessProviderHandler, configMap *config.ConfigMap) error {
	err := a.initialize(ctx, configMap)
	if err != nil {
		return err
	}

	return a.doSyncAccessProvidersFromTarget(ctx, accessProviderHandler, configMap)
}

func (a *AccessSyncer) doSyncAccessProvidersFromTarget(ctx context.Context, accessProviderHandler wrappers.AccessProviderHandler, configMap *config.ConfigMap) error {
	apImportList, err := a.fetchAllAccessProviders(ctx, configMap)
	if err != nil {
		return err
	}

	filteredList := filterApImportList(apImportList, configMap)

	utils.Logger.Info(fmt.Sprintf("Keeping %d acces providers after filtering", len(filteredList)))

	err = newRoleEnricher(ctx, configMap).enrich(filteredList)
	if err != nil {
		return fmt.Errorf("enrich: %w", err)
	}

	err = accessProviderHandler.AddAccessProviders(getProperFormatForImport(filteredList)...)
	if err != nil {
		return fmt.Errorf("add access provider to handler: %w", err)
	}

	return nil
}

func shouldSkipRole(role string, roleExcludes []string) bool {
	matched, err := match.MatchesAny(role, roleExcludes)
	if err != nil {
		utils.Logger.Error(fmt.Sprintf("invalid value for parameter %q: %s", constants.AwsAccessRoleExcludes, err.Error()))
		return false
	}

	return matched
}

func filterApImportList(importList []model.AccessProviderInputExtended, configMap *config.ConfigMap) []model.AccessProviderInputExtended {
	toKeep := set.NewSet[string]()

	utils.Logger.Debug("Start filtering for relevant access providers")

	// Role excluded get filtered out here, because some may be referenced by policies and so need to get included anyway.
	roleExcludes := slice.ParseCommaSeparatedList(configMap.GetString(constants.AwsAccessRoleExcludes))

	for _, apInput := range importList {
		if apInput.PolicyType == model.Role || apInput.PolicyType == model.SSORole {
			if shouldSkipRole(apInput.ApInput.Name, roleExcludes) {
				utils.Logger.Debug(fmt.Sprintf("Skipping role %q as it was requested to be skipped", apInput.ApInput.ExternalId))
			} else if len(apInput.ApInput.What) > 0 {
				// Elements in the WHAT here already means that there are relevant permissions
				utils.Logger.Debug(fmt.Sprintf("Keeping role %q", apInput.ApInput.ExternalId))

				toKeep.Add(apInput.ApInput.ExternalId)
			} else {
				utils.Logger.Debug(fmt.Sprintf("Skipping role %q as it has no WHAT elements", apInput.ApInput.ExternalId))
			}

			continue
		} else if apInput.PolicyType == model.Policy {
			if len(apInput.ApInput.Who.AccessProviders) > 0 {
				toSkip := set.NewSet[string]()

				// Look for roles that are excluded
				for _, who := range apInput.ApInput.Who.AccessProviders {
					if strings.HasPrefix(who, constants.RoleTypePrefix) {
						roleName, _ := strings.CutPrefix(who, constants.RoleTypePrefix)

						if shouldSkipRole(roleName, roleExcludes) {
							toSkip.Add(who)
						}
					}
				}

				// We have some roles to skip, so remove them and mark the policy as incomplete
				if len(toSkip) > 0 {
					utils.Logger.Debug(fmt.Sprintf("Removing skipped roles %q from policy %q and marking as incomplete", toSkip.Slice(), apInput.ApInput.ExternalId))
					newAps := set.NewSet[string](apInput.ApInput.Who.AccessProviders...)
					newAps.RemoveAll(toSkip.Slice()...)
					apInput.ApInput.Who.AccessProviders = newAps.Slice()
					apInput.ApInput.Incomplete = ptr.Bool(true)
				}
			}

			hasS3Actions := false

			if len(apInput.ApInput.What) > 0 {
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
				toKeep.Add(apInput.ApInput.ExternalId)

				for _, who := range apInput.ApInput.Who.AccessProviders {
					utils.Logger.Debug(fmt.Sprintf("Re-adding role %q", who))
					toKeep.Add(who)
				}
			} else {
				utils.Logger.Debug(fmt.Sprintf("Skipping policy %q as it has no relevant permissions/resources", apInput.ApInput.ExternalId))
			}
		} else if apInput.PolicyType == model.AccessPoint {
			toKeep.Add(apInput.ApInput.ExternalId)
		}
	}

	result := make([]model.AccessProviderInputExtended, 0, len(toKeep))

	for _, apInput := range importList {
		if toKeep.Contains(apInput.ApInput.ExternalId) {
			result = append(result, apInput)
		}
	}

	return result
}

func (a *AccessSyncer) fetchRoleAccessProviders(roles []model.RoleEntity, aps []model.AccessProviderInputExtended) []model.AccessProviderInputExtended {
	utils.Logger.Info("Get all roles")

	for _, role := range roles {
		isRaito := false

		for _, tag := range role.Tags {
			if tag.Key == "creator" && tag.Value == "raito" {
				isRaito = true

				break
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
			whoItem, incomplete = iam.CreateWhoFromTrustPolicyDocument(role.AssumeRolePolicy, role.Name, a.account)
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

func (a *AccessSyncer) fetchManagedPolicyAccessProviders(ctx context.Context, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) {
	utils.Logger.Info("Get all managed policies")

	policies, err := a.repo.GetManagedPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("get managed policies: %w", err)
	}

	if policies == nil {
		return nil, nil
	}

	bucketRegionMap, err := a.getBucketRegionMap()
	if err != nil {
		return nil, fmt.Errorf("get bucket region map: %w", err)
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
			roleBindings = append(roleBindings, constants.RoleTypePrefix+roleBinding.ResourceName)
		}

		if len(groupBindings) == 0 && len(userBindings) == 0 && len(roleBindings) == 0 {
			utils.Logger.Info(fmt.Sprintf("Skipping managed policy %s, no user/group/role bindings", policy.Name))
			continue
		}

		whatItems, incomplete := iam.CreateWhatFromPolicyDocument(policy.PolicyParsed, policy.Name, a.account, bucketRegionMap, a.cfgMap)

		policyDocument := ""
		if policy.PolicyDocument != nil {
			policyDocument = *policy.PolicyDocument
		}

		apInput := sync_from_target.AccessProvider{
			ExternalId: constants.PolicyTypePrefix + policy.Name,
			Name:       policy.Name,
			ActualName: policy.Name,
			Type:       aws.String(string(model.Policy)),
			NamingHint: policy.Name,
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

func (a *AccessSyncer) getBucketRegionMap() (map[string]string, error) {
	if a.bucketRegionMap == nil {
		a.bucketRegionMap = make(map[string]string)

		buckets, err := a.s3Repo.ListBuckets(context.Background())
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}

		for _, bucket := range buckets {
			a.bucketRegionMap[bucket.Key] = bucket.Region
		}
	}

	return a.bucketRegionMap, nil
}

func (a *AccessSyncer) convertPoliciesToWhat(policies []model.PolicyEntity) ([]sync_from_target.WhatItem, bool, string) {
	// Making sure to never return nil
	whatItems := make([]sync_from_target.WhatItem, 0, 10)
	incomplete := false
	policyDocuments := ""

	bucketRegionMap, err := a.getBucketRegionMap()
	if err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to get bucket region map: %s", err.Error()))
		return nil, true, ""
	}

	for i := range policies {
		policy := policies[i]
		policyWhat, policyIncomplete := iam.CreateWhatFromPolicyDocument(policy.PolicyParsed, policy.Name, a.account, bucketRegionMap, a.cfgMap)

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

func (a *AccessSyncer) fetchInlineUserPolicyAccessProviders(ctx context.Context, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) { //nolint:dupl //We may want to optimise this later
	userPolicies, err := a.getInlinePoliciesOnUsers(ctx)
	if err != nil {
		return nil, err
	}

	for user, policies := range userPolicies {
		whatItems, incomplete, policyDocuments := a.convertPoliciesToWhat(policies)

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

func (a *AccessSyncer) fetchInlineGroupPolicyAccessProviders(ctx context.Context, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) { //nolint:dupl //We may want to optimise this later
	groupPolicies, err := a.getInlinePoliciesOnGroups(ctx)
	if err != nil {
		return nil, err
	}

	for group, policies := range groupPolicies {
		whatItems, incomplete, policyDocuments := a.convertPoliciesToWhat(policies)

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

func (a *AccessSyncer) fetchInlineRolePolicyAccessProviders(ctx context.Context, roles []model.RoleEntity, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) {
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

		whatItems, incomplete, policyDocuments := a.convertPoliciesToWhat(policies)

		var policyIds strings.Builder
		for i := range policies {
			policyIds.WriteString(policies[i].Name)
			policyIds.WriteString("|")
		}

		roleAp.Policy = policyDocuments
		roleAp.What = whatItems
		roleAp.Incomplete = ptr.Bool(incomplete || (roleAp.Incomplete != nil && *roleAp.Incomplete))
	}

	return aps, nil
}

func (a *AccessSyncer) FetchS3AccessPointAccessProviders(ctx context.Context, configMap *config.ConfigMap, aps []model.AccessProviderInputExtended) ([]model.AccessProviderInputExtended, error) {
	var err error

	for _, region := range utils.GetRegions(configMap) {
		aps, err = a.fetchS3AccessPointAccessProvidersForRegion(ctx, aps, region)
		if err != nil {
			return nil, fmt.Errorf("fetch s3 access point access provider for region %q: %w", region, err)
		}
	}

	return aps, nil
}

func (a *AccessSyncer) fetchS3AccessPointAccessProvidersForRegion(ctx context.Context, aps []model.AccessProviderInputExtended, region string) ([]model.AccessProviderInputExtended, error) {
	accessPoints, err := a.repo.ListAccessPoints(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("list access points: %w", err)
	}

	bucketRegionMap, err := a.getBucketRegionMap()
	if err != nil {
		return nil, fmt.Errorf("get bucket region map: %w", err)
	}

	for _, accessPoint := range accessPoints {
		if accessPoint.PolicyDocument == nil {
			utils.Logger.Warn(fmt.Sprintf("Skipping access point %q as it has no policy document", accessPoint.Name))
			continue
		}

		newAp := model.AccessProviderInputExtended{
			PolicyType: model.AccessPoint,
			ApInput: &sync_from_target.AccessProvider{
				ExternalId: fmt.Sprintf("%s%s", constants.AccessPointTypePrefix, accessPoint.Arn),
				Name:       accessPoint.Name,
				Type:       aws.String(string(model.AccessPoint)),
				NamingHint: "",
				ActualName: accessPoint.Name,
				Action:     sync_from_target.Grant,
				Policy:     *accessPoint.PolicyDocument,
			}}

		incomplete := false
		newAp.ApInput.Who, newAp.ApInput.What, incomplete = iam.CreateWhoAndWhatFromAccessPointPolicy(accessPoint.PolicyParsed, accessPoint.Bucket, accessPoint.Name, a.account, bucketRegionMap, a.cfgMap)

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
		roleExcludes := slice.ParseCommaSeparatedList(configMap.GetString(constants.AwsAccessRoleExcludes))

		roles, err := a.repo.GetRoles(ctx, roleExcludes)
		if err != nil {
			return nil, fmt.Errorf("get roles: %w", err)
		}

		// Adding access providers to the list for the roles
		apImportList = a.fetchRoleAccessProviders(roles, apImportList)

		if !configMap.GetBool(constants.AwsAccessSkipManagedPolicies) {
			// Adding access providers to the list for the managed policies
			apImportList, err = a.fetchManagedPolicyAccessProviders(ctx, apImportList)
			if err != nil {
				return nil, err
			}
		}

		if !configMap.GetBool(constants.AwsAccessSkipUserInlinePolicies) {
			apImportList, err = a.fetchInlineUserPolicyAccessProviders(ctx, apImportList)
			if err != nil {
				return nil, err
			}
		}

		if !configMap.GetBool(constants.AwsAccessSkipGroupInlinePolicies) {
			apImportList, err = a.fetchInlineGroupPolicyAccessProviders(ctx, apImportList)
			if err != nil {
				return nil, err
			}
		}

		// Adding access providers to the list for the inline policies (existing role access providers will be enriched with inline policies it may have)
		apImportList, err = a.fetchInlineRolePolicyAccessProviders(ctx, roles, apImportList)
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
		return nil, fmt.Errorf("get groups: %w", err)
	}

	groupNames := []string{}
	for _, g := range groups {
		groupNames = append(groupNames, g.Name)
	}

	policies, err := a.repo.GetInlinePoliciesForEntities(ctx, groupNames, iam.GroupResourceType)
	if err != nil {
		return nil, fmt.Errorf("get inline policies for entities: %w", err)
	}

	return policies, nil
}
func (a *AccessSyncer) getInlinePoliciesOnUsers(ctx context.Context) (map[string][]model.PolicyEntity, error) {
	utils.Logger.Info("Get inline policies from users")

	users, err := a.repo.GetUsers(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("get users: %w", err)
	}

	userNames := []string{}
	for _, u := range users {
		userNames = append(userNames, u.Name)
	}

	policies, err := a.repo.GetInlinePoliciesForEntities(ctx, userNames, iam.UserResourceType)
	if err != nil {
		return nil, fmt.Errorf("get inline policies for entities: %w", err)
	}

	return policies, nil
}

func (a *AccessSyncer) getInlinePoliciesOnRoles(ctx context.Context, roles []model.RoleEntity) (map[string][]model.PolicyEntity, error) {
	utils.Logger.Info("Get inline policies from roles")

	roleNames := []string{}
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	policies, err := a.repo.GetInlinePoliciesForEntities(ctx, roleNames, iam.RoleResourceType)
	if err != nil {
		return nil, fmt.Errorf("get inline policies for entities: %w", err)
	}

	return policies, nil
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
