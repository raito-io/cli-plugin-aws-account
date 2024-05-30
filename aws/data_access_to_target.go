package aws

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aws/smithy-go/ptr"
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
	err := a.initialize(ctx, configMap)
	if err != nil {
		return err
	}

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

	roleActionMap, existingRoleWhoBindings, err := a.fetchExistingRoles(ctx)
	if err != nil {
		return err
	}

	policyActionMap, existingPolicyWhoBindings, err := a.fetchExistingManagedPolicies(ctx)
	if err != nil {
		return err
	}

	accessPointActionMap, existingAccessPointWhoBindings, err := a.fetchExistingAccessPoints(ctx, configMap)
	if err != nil {
		return err
	}

	// Need to separate roles and policies as they can have the same name
	policyAps := map[string]*sync_to_target.AccessProvider{}
	roleAps := map[string]*sync_to_target.AccessProvider{}
	accessPointAps := map[string]*sync_to_target.AccessProvider{}
	newRoleWhoBindings := map[string]set.Set[model.PolicyBinding]{}
	roleInheritanceMap := map[string]set.Set[string]{}
	inverseRoleInheritanceMap := map[string]set.Set[string]{}
	inverseAccessPointInheritanceMap := map[string]set.Set[string]{}
	newPolicyWhoBindings := map[string]set.Set[model.PolicyBinding]{}
	policyInheritanceMap := map[string]set.Set[string]{}
	newAccessPointWhoBindings := map[string]set.Set[model.PolicyBinding]{}
	accessPointInheritanceMap := map[string]set.Set[string]{}

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

		// Determine the type
		apType, err2 := resolveApType(ap)
		if err2 != nil {
			logFeedbackError(&apFeedback, err2.Error())
		}

		// Generating the technical name for the access provider complying to the different rules for AWS resources.
		name, err2 := utils.GenerateName(ap, apType)

		if err2 != nil {
			logFeedbackError(&apFeedback, fmt.Sprintf("failed to generate actual name for access provider %q: %s", ap.Name, err2.Error()))
			continue
		}

		apFeedback.ActualName = name

		if ap.Action != sync_to_target.Grant && ap.Action != sync_to_target.Purpose {
			logFeedbackError(&apFeedback, fmt.Sprintf("unsupported access provider action: %d", ap.Action))
			continue
		}

		apFeedback.Type = ptr.String(string(apType))

		var apActionMap map[string]string
		var inheritanceMap map[string]set.Set[string]
		var whoBindings map[string]set.Set[model.PolicyBinding]
		var aps map[string]*sync_to_target.AccessProvider
		var inverseInheritanceMap map[string]set.Set[string]

		switch apType {
		case model.Role, model.SSORole:
			apActionMap = roleActionMap
			inheritanceMap = roleInheritanceMap
			whoBindings = newRoleWhoBindings
			inverseInheritanceMap = inverseRoleInheritanceMap
			aps = roleAps
		case model.Policy:
			apActionMap = policyActionMap
			inheritanceMap = policyInheritanceMap
			whoBindings = newPolicyWhoBindings
			aps = policyAps
		case model.AccessPoint:
			apActionMap = accessPointActionMap
			inheritanceMap = accessPointInheritanceMap
			whoBindings = newAccessPointWhoBindings
			inverseInheritanceMap = inverseAccessPointInheritanceMap
			aps = accessPointAps
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
			if apType == model.Role {
				externalId = fmt.Sprintf("%s%s", constants.RoleTypePrefix, name)
			} else if apType == model.AccessPoint {
				externalId = fmt.Sprintf("%s%s", constants.AccessPointTypePrefix, name)
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
			apInheritFromNames, err3 := iam.ResolveInheritedApNames(resolveApType, accessProviders.AccessProviders, ap.Who.InheritFrom...)
			if err3 != nil {
				logFeedbackError(&apFeedback, fmt.Sprintf("resolving inherited access providers: %s", err3.Error()))
				continue
			}

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

			if apType == model.Role || apType == model.AccessPoint {
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
			} else {
				for _, group := range ap.Who.Groups {
					key := model.PolicyBinding{
						Type:         iam.GroupResourceType,
						ResourceName: group,
					}

					whoBindings[name].Add(key)
				}
			}

			if apType == model.Role || apType == model.AccessPoint {
				// For roles and access points we also build the reverse inheritance map
				for _, inheritFrom := range apInheritFromNames {
					if _, f := inverseInheritanceMap[inheritFrom]; !f {
						inverseInheritanceMap[inheritFrom] = set.NewSet[string]()
					}

					inverseInheritanceMap[inheritFrom].Add(name)
				}
			}
		}
	}

	utils.Logger.Debug(fmt.Sprintf("roleInheritanceMap: %+v", roleInheritanceMap))
	utils.Logger.Debug(fmt.Sprintf("policyInheritanceMap: %+v", policyInheritanceMap))
	utils.Logger.Debug(fmt.Sprintf("accessPointInheritanceMap: %+v", accessPointInheritanceMap))
	utils.Logger.Debug(fmt.Sprintf("newRoleWhoBindings: %+v", newRoleWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("newPolicyWhoBindings: %+v", newPolicyWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("newAccessPointWhoBindings: %+v", newAccessPointWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("existingPolicyWhoBindings: %+v", existingPolicyWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("existingRoleWhoBindings: %+v", existingRoleWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("existingAccessPointWhoBindings: %+v", existingAccessPointWhoBindings))

	iam.ProcessApInheritance(roleInheritanceMap, policyInheritanceMap, accessPointInheritanceMap, newRoleWhoBindings, newPolicyWhoBindings, newAccessPointWhoBindings, existingRoleWhoBindings, existingPolicyWhoBindings, existingAccessPointWhoBindings)

	utils.Logger.Debug(fmt.Sprintf("New policy bindings: %+v", newPolicyWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("New role bindings: %+v", newRoleWhoBindings))
	utils.Logger.Debug(fmt.Sprintf("New access point bindings: %+v", newAccessPointWhoBindings))

	// Now execute the actual update for the roles, policies and access points
	a.handleRoleUpdates(ctx, roleActionMap, roleAps, existingRoleWhoBindings, newRoleWhoBindings, inverseRoleInheritanceMap, feedbackMap)

	a.handlePolicyUpdates(ctx, policyActionMap, policyAps, existingPolicyWhoBindings, newPolicyWhoBindings, inlineUserPoliciesToDelete, inlineGroupPoliciesToDelete, feedbackMap, configMap)

	a.handleAccessPointUpdates(ctx, accessPointActionMap, accessPointAps, existingAccessPointWhoBindings, newAccessPointWhoBindings, inverseAccessPointInheritanceMap, feedbackMap)

	return nil
}

func resolveApType(ap *sync_to_target.AccessProvider) (model.AccessProviderType, error) {
	// Determine the type
	apType := model.Policy

	if ap.Action == sync_to_target.Purpose {
		// TODO look at all other APs to see what the incoming WHO links are.
		// How do we handle this with external APs? Do we have this information in the existingRoleWhoBindings and existingPolicyWhoBindings ?
		// If so, do we already know if the role is an SSO role or not?
		// If this is linked to an SSO role (can only be 1): we just add the sso role as actual name and add the WHO from
		//    How to handle Purpose inheritance?
		//    How to handle partial syncs? (can we even support this?) Possibly need a metadata indication that we always need to export the purposes and SSO roles?
		// If this is linked to a role (or multiple?): we handle it the same way as a normal role (or do the same as for SSO roles?)
		// If this is linked to a policy (or multiple?): we need to add the WHO to the policy (= act as normal policy?)
		return apType, fmt.Errorf("currently purposes are not supported yet")
	} else {
		if ap.Type == nil {
			utils.Logger.Warn(fmt.Sprintf("No type provided for access provider %q. Using Policy as default", ap.Name))
		} else {
			apType = model.AccessProviderType(*ap.Type)
		}
	}

	return apType, nil
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

func (a *AccessSyncer) handleAccessPointUpdates(ctx context.Context, accessPointActionMap map[string]string, accessPointAps map[string]*sync_to_target.AccessProvider, existingAccessPointWhoBindings map[string]set.Set[model.PolicyBinding], newAccessPointWhoBindings map[string]set.Set[model.PolicyBinding], inverseAccessPointInheritanceMap map[string]set.Set[string], feedbackMap map[string]*sync_to_target.AccessProviderSyncFeedback) {
	var err error

	for accessPointName, accessPointAction := range accessPointActionMap {
		accessPointAp := accessPointAps[accessPointName]

		utils.Logger.Info(fmt.Sprintf("Processing access point %s with action %s", accessPointName, accessPointAction))

		if accessPointAction == DeleteAction {
			utils.Logger.Info(fmt.Sprintf("Removing access point %s", accessPointName))

			if accessPointAp.ExternalId == nil {
				logFeedbackError(feedbackMap[accessPointAp.Id], fmt.Sprintf("failed to delete access point %q as no external id is found", accessPointName))
				continue
			}

			// Extract the region from the access point external ID
			extId := *accessPointAp.ExternalId
			extId = extId[len(constants.AccessPointTypePrefix):]

			region := ""
			if strings.Contains(extId, ":") {
				region = extId[:strings.Index(extId, ":")] //nolint:gocritic
			} else {
				logFeedbackError(feedbackMap[accessPointAp.Id], fmt.Sprintf("invalid external id found %q", *accessPointAp.ExternalId))
				continue
			}

			err = a.repo.DeleteAccessPoint(ctx, accessPointName, region)
			if err != nil {
				logFeedbackError(feedbackMap[accessPointAp.Id], fmt.Sprintf("failed to delete access point %q: %s", accessPointName, err.Error()))
				continue
			}
		} else if accessPointAction == CreateAction || accessPointAction == UpdateAction {
			utils.Logger.Info(fmt.Sprintf("Existing bindings for %s: %s", accessPointName, existingAccessPointWhoBindings[accessPointName]))
			utils.Logger.Info(fmt.Sprintf("Export bindings for %s: %s", accessPointName, newAccessPointWhoBindings[accessPointName]))

			who := set.NewSet(newAccessPointWhoBindings[accessPointName].Slice()...)

			// Getting the who (for access points, this should already contain the list of unpacked users from the groups (as those are not supported for roles)
			principals := make([]string, 0, len(who))

			for _, binding := range who.Slice() {
				if binding.Type == iam.UserResourceType || binding.Type == iam.RoleResourceType {
					principals = append(principals, binding.ResourceName)
				}
			}

			sort.Strings(principals)

			// Getting the what
			ap := accessPointAps[accessPointName]
			statements := createPolicyStatementsFromWhat(ap.What)
			whatItems := make([]sync_to_target.WhatItem, 0, len(ap.What))
			whatItems = append(whatItems, ap.What...)

			// Because we need to flatten the WHAT for access points as well, we gather all access point APs from which this access point AP inherits its what (following the reverse inheritance chain)
			inheritedAPs := getAllAPsInInheritanceChainForWhat(accessPointName, inverseAccessPointInheritanceMap, accessPointAps)
			for _, inheritedAP := range inheritedAPs {
				whatItems = append(whatItems, inheritedAP.What...)
				statements = append(statements, createPolicyStatementsFromWhat(inheritedAP.What)...)
			}

			bucketName, region, err2 := extractBucketForAccessPoint(whatItems)
			if err2 != nil {
				logFeedbackError(feedbackMap[accessPointAp.Id], fmt.Sprintf("failed to extract bucket name for access point %q: %s", accessPointName, err2.Error()))
				continue
			}

			statements = mergeStatementsOnPermissions(statements)

			accessPointArn := fmt.Sprintf("arn:aws:s3:%s:%s:accesspoint/%s", region, a.account, accessPointName)
			convertResourceURLsForAccessPoint(statements, accessPointArn)

			for _, statement := range statements {
				statement.Principal = map[string][]string{
					"AWS": principals,
				}
			}

			if accessPointAction == CreateAction {
				utils.Logger.Info(fmt.Sprintf("Creating access point %s", accessPointName))

				// Create the new access point with the who
				err = a.repo.CreateAccessPoint(ctx, accessPointName, bucketName, region, statements)
				if err != nil {
					logFeedbackError(feedbackMap[accessPointAp.Id], fmt.Sprintf("failed to create access point %q: %s", accessPointName, err.Error()))
					continue
				}
			} else {
				utils.Logger.Info(fmt.Sprintf("Updating access point %s", accessPointName))

				// Handle the who
				err = a.repo.UpdateAccessPoint(ctx, accessPointName, region, statements)
				if err != nil {
					logFeedbackError(feedbackMap[accessPointAp.Id], fmt.Sprintf("failed to update access point %q: %s", accessPointName, err.Error()))
					continue
				}
			}
		} else {
			utils.Logger.Debug(fmt.Sprintf("no action needed for access point %q", accessPointName))
		}
	}
}

// convertResourceURLsForAccessPoint converts all the resource ARNs in the policy statements to the corresponding ones for the access point.
// e.g. "arn:aws:s3:::bucket/folder1" would become "arn:aws:s3:eu-central-1:077954824694:accesspoint/operations/object/folder1/*"
func convertResourceURLsForAccessPoint(statements []*awspolicy.Statement, accessPointArn string) {
	for _, statement := range statements {
		for i, resource := range statement.Resource {
			if strings.HasPrefix(resource, "arn:aws:s3:") {
				fullName := strings.Split(resource, ":")[5]
				if strings.Contains(fullName, "/") {
					fullName = fullName[strings.Index(fullName, "/")+1:]
					if !strings.HasPrefix(fullName, "*") {
						fullName += "/*"
					}

					statement.Resource[i] = fmt.Sprintf("%s/object/%s", accessPointArn, fullName)
				} else {
					statement.Resource[i] = accessPointArn
				}
			}
		}
	}
}

// extractBucketForAccessPoint extracts the bucket name and region from the policy statements of an access point.
// When there is non found or multiple buckets, an error is returned.
func extractBucketForAccessPoint(whatItems []sync_to_target.WhatItem) (string, string, error) {
	bucket := ""
	region := ""

	for _, whatItem := range whatItems {
		thisBucket := whatItem.DataObject.FullName
		if strings.Contains(thisBucket, "/") {
			thisBucket = thisBucket[:strings.Index(thisBucket, "/")] //nolint:gocritic
		}

		parts := strings.Split(thisBucket, ":")
		if len(parts) != 3 {
			return "", "", fmt.Errorf("unexpected full name for S3 object: %s", whatItem.DataObject.FullName)
		}

		thisBucketName := parts[2]
		thisBucketRegion := parts[1]

		if bucket != "" && bucket != thisBucketName {
			return "", "", fmt.Errorf("an access point can only have one bucket associated with it")
		}

		bucket = thisBucketName
		region = thisBucketRegion
	}

	if bucket == "" {
		return "", "", fmt.Errorf("unable to determine the bucket for this access point")
	}

	return bucket, region, nil
}

// mergeStatementsOnPermissions merges statements that have the same permissions.
func mergeStatementsOnPermissions(statements []*awspolicy.Statement) []*awspolicy.Statement {
	mergedStatements := make([]*awspolicy.Statement, 0, len(statements))

	permissions := map[string]*awspolicy.Statement{}

	for _, s := range statements {
		actionList := s.Action
		sort.Strings(actionList)
		actions := strings.Join(actionList, ",")

		if existing, f := permissions[actions]; f {
			existing.Resource = append(existing.Resource, s.Resource...)
		} else {
			permissions[actions] = s
		}
	}

	for _, s := range permissions {
		mergedStatements = append(mergedStatements, s)
	}

	return mergedStatements
}

func (a *AccessSyncer) handlePolicyUpdates(ctx context.Context, policyActionMap map[string]string, policyAps map[string]*sync_to_target.AccessProvider, existingPolicyWhoBindings map[string]set.Set[model.PolicyBinding], newPolicyWhoBindings map[string]set.Set[model.PolicyBinding], inlineUserPoliciesToDelete map[string][]string, inlineGroupPoliciesToDelete map[string][]string, feedbackMap map[string]*sync_to_target.AccessProviderSyncFeedback, configMap *config.ConfigMap) {
	var err error
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
}

func (a *AccessSyncer) handleRoleUpdates(ctx context.Context, roleActionMap map[string]string, roleAps map[string]*sync_to_target.AccessProvider, existingRoleWhoBindings map[string]set.Set[model.PolicyBinding], newRoleWhoBindings map[string]set.Set[model.PolicyBinding], inverseRoleInheritanceMap map[string]set.Set[string], feedbackMap map[string]*sync_to_target.AccessProviderSyncFeedback) {
	var err error
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
}

func createPolicyStatementsFromWhat(whatItems []sync_to_target.WhatItem) []*awspolicy.Statement {
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

			fullName := what.DataObject.FullName

			// TODO: later this should only be done for S3 resources?
			if strings.Contains(fullName, ":") {
				fullName = fullName[strings.Index(fullName, ":")+1:]
				if strings.Contains(fullName, ":") {
					fullName = fullName[strings.Index(fullName, ":")+1:]
				}
			}

			policyInfo[fullName] = optimizePermissions(allPermissions, what.Permissions)
		}
	}

	statements := make([]*awspolicy.Statement, 0, len(policyInfo))
	for resource, actions := range policyInfo {
		statements = append(statements, &awspolicy.Statement{
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

func (a *AccessSyncer) fetchExistingRoles(ctx context.Context) (map[string]string, map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing roles")

	roles, err := a.repo.GetRoles(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching existing roles: %w", err)
	}

	roleMap := map[string]string{}
	existingRoleAssumptions := map[string]set.Set[model.PolicyBinding]{}

	for _, role := range roles {
		roleMap[role.Name] = "existing"

		who, _ := iam.CreateWhoFromTrustPolicyDocument(role.AssumeRolePolicy, role.Name, a.account)
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

func (a *AccessSyncer) fetchExistingAccessPoints(ctx context.Context, configMap *config.ConfigMap) (map[string]string, map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing access points")

	accessPointMap := map[string]string{}
	existingPolicyBindings := map[string]set.Set[model.PolicyBinding]{}

	for _, region := range utils.GetRegions(configMap) {
		err := a.fetchExistingAccessPointsForRegion(ctx, region, accessPointMap, existingPolicyBindings)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching existing access points for region %s: %w", region, err)
		}
	}

	return accessPointMap, existingPolicyBindings, nil
}

func (a *AccessSyncer) fetchExistingAccessPointsForRegion(ctx context.Context, region string, accessPointMap map[string]string, existingPolicyBindings map[string]set.Set[model.PolicyBinding]) error {
	accessPoints, err := a.repo.ListAccessPoints(ctx, region)
	if err != nil {
		return fmt.Errorf("error fetching existing access points: %w", err)
	}

	for ind := range accessPoints {
		accessPoint := accessPoints[ind]

		accessPointMap[accessPoint.Name] = "existing"

		existingPolicyBindings[accessPoint.Name] = set.Set[model.PolicyBinding]{}

		who, _, _ := iam.CreateWhoAndWhatFromAccessPointPolicy(accessPoint.PolicyParsed, accessPoint.Bucket, accessPoint.Name, a.account)
		if who != nil {
			// Note: Groups are not supported here in AWS.
			for _, userName := range who.Users {
				key := model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: userName,
				}
				existingPolicyBindings[accessPoint.Name].Add(key)
			}

			for _, ap := range who.AccessProviders {
				key := model.PolicyBinding{
					Type:         iam.RoleResourceType,
					ResourceName: ap,
				}
				existingPolicyBindings[accessPoint.Name].Add(key)
			}
		}
	}

	utils.Logger.Info(fmt.Sprintf("Fetched existing %d access points", len(accessPointMap)))

	return nil
}

func removeArn(input []model.PolicyBinding) []model.PolicyBinding {
	result := []model.PolicyBinding{}

	for _, val := range input {
		val.ResourceId = ""
		result = append(result, val)
	}

	return result
}
