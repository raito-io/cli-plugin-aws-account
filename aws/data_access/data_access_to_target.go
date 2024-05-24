package data_access

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	ds "github.com/raito-io/cli/base/data_source"

	"github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"
	"github.com/raito-io/golang-set/set"
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

func logFeedbackWarning(apFeedback *sync_to_target.AccessProviderSyncFeedback, msg string) {
	utils.Logger.Warn(msg)
	apFeedback.Warnings = append(apFeedback.Warnings, msg)
}

func (a *AccessSyncer) getUserGroupMap(ctx context.Context, configMap *config.ConfigMap) (map[string][]string, error) {
	if a.userGroupMap != nil {
		return a.userGroupMap, nil
	}

	iamRepo := iam.NewAwsIamRepository(configMap)

	groups, err := iamRepo.GetGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("get groups: %w", err)
	}

	a.userGroupMap = make(map[string][]string)

	users, err := iamRepo.GetUsers(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("get users: %w", err)
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

	inheritanceResolver := func(aps ...string) ([]string, error) {
		return iam.ResolveInheritedApNames(resolveApType, accessProviders.AccessProviders, aps...)
	}

	roleHandler := NewRoleAccessHandler(a.repo, a.getUserGroupMap, roleActionMap, existingRoleWhoBindings, inheritanceResolver)
	policyHandler := NewPolicyAccessHandler(a.repo, policyActionMap, existingPolicyWhoBindings, inheritanceResolver)
	accessPointHandler := NewAccessProviderHandler(a.account, a.repo, a.getUserGroupMap, accessPointActionMap, existingAccessPointWhoBindings, inheritanceResolver)

	for i := range accessProviders.AccessProviders {
		ap := accessProviders.AccessProviders[i]

		if ap == nil {
			continue
		}

		// Create the initial feedback object
		apFeedback := &sync_to_target.AccessProviderSyncFeedback{
			AccessProvider: ap.Id,
		}
		feedbackMap[ap.Id] = apFeedback

		// Determine the type
		apType, err2 := resolveApType(ap)
		if err2 != nil {
			logFeedbackError(apFeedback, err2.Error())
		}

		switch apType {
		case model.Role, model.SSORole:
			roleHandler.AddAccessProvider(ap, apType, apFeedback, configMap)
		case model.Policy:
			policyHandler.AddAccessProvider(ap, apType, apFeedback, configMap)
		case model.AccessPoint:
			accessPointHandler.AddAccessProvider(ap, apType, apFeedback, configMap)
		default:
			logFeedbackError(apFeedback, fmt.Sprintf("unknown access provider type %q", apType))
		}
	}

	// Handle inheritance
	roleDetailsMap := roleHandler.ProcessInheritance(nil)
	_ = policyHandler.ProcessInheritance(roleDetailsMap)
	_ = accessPointHandler.ProcessInheritance(roleDetailsMap)

	roleHandler.HandleUpdates(ctx, configMap)
	policyHandler.HandleUpdates(ctx, configMap)
	accessPointHandler.HandleUpdates(ctx, configMap)

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

func getAllAPsInInheritanceChainForWhatDetails(start string, detailsMap map[string]*AccessProviderDetails) []*sync_to_target.AccessProvider {
	inherited := set.NewSet[string]()
	getRecursiveInheritedAPsDetails(start, detailsMap, inherited)

	aps := make([]*sync_to_target.AccessProvider, 0, len(inherited))

	for i := range inherited {
		aps = append(aps, detailsMap[i].ap)
	}

	return aps
}

func getRecursiveInheritedAPsDetails(start string, detailsMap map[string]*AccessProviderDetails, inherited set.Set[string]) {
	if in, f := detailsMap[start]; f {
		for k := range in.inverseInheritance {
			if !inherited.Contains(k) {
				inherited.Add(k)
				getRecursiveInheritedAPsDetails(k, detailsMap, inherited)
			}
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

func (a *AccessSyncer) fetchExistingRoles(ctx context.Context) (map[string]AccessProviderAction, map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing roles")

	roles, err := a.repo.GetRoles(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching existing roles: %w", err)
	}

	roleMap := map[string]AccessProviderAction{}
	existingRoleAssumptions := map[string]set.Set[model.PolicyBinding]{}

	for _, role := range roles {
		roleMap[role.Name] = ActionExisting

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

func (a *AccessSyncer) fetchExistingManagedPolicies(ctx context.Context) (map[string]AccessProviderAction, map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing managed policies")

	managedPolicies, err := a.repo.GetManagedPolicies(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching existing managed policies: %w", err)
	}

	a.managedPolicies = managedPolicies

	policyMap := map[string]AccessProviderAction{}
	existingPolicyBindings := map[string]set.Set[model.PolicyBinding]{}

	for ind := range managedPolicies {
		policy := managedPolicies[ind]

		policyMap[policy.Name] = ActionExisting

		existingPolicyBindings[policy.Name] = set.Set[model.PolicyBinding]{}

		existingPolicyBindings[policy.Name].Add(removeArn(policy.UserBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.GroupBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.RoleBindings)...)
	}

	utils.Logger.Info(fmt.Sprintf("Fetched existing %d managed policies", len(policyMap)))

	return policyMap, existingPolicyBindings, nil
}

func (a *AccessSyncer) fetchExistingAccessPoints(ctx context.Context, configMap *config.ConfigMap) (map[string]AccessProviderAction, map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing access points")

	accessPointMap := map[string]AccessProviderAction{}
	existingPolicyBindings := map[string]set.Set[model.PolicyBinding]{}

	for _, region := range utils.GetRegions(configMap) {
		err := a.fetchExistingAccessPointsForRegion(ctx, region, accessPointMap, existingPolicyBindings)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching existing access points for region %s: %w", region, err)
		}
	}

	return accessPointMap, existingPolicyBindings, nil
}

func (a *AccessSyncer) fetchExistingAccessPointsForRegion(ctx context.Context, region string, accessPointMap map[string]AccessProviderAction, existingPolicyBindings map[string]set.Set[model.PolicyBinding]) error {
	accessPoints, err := a.repo.ListAccessPoints(ctx, region)
	if err != nil {
		return fmt.Errorf("error fetching existing access points: %w", err)
	}

	for ind := range accessPoints {
		accessPoint := accessPoints[ind]

		accessPointMap[accessPoint.Name] = ActionExisting

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
