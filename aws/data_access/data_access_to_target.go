package data_access

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aws/smithy-go/ptr"
	"github.com/hashicorp/go-multierror"
	ds "github.com/raito-io/cli/base/data_source"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source"
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

	return a.doSyncAccessProviderToTarget(ctx, accessProviders, accessProviderFeedbackHandler)
}

func logFeedbackError(apFeedback *sync_to_target.AccessProviderSyncFeedback, msg string) {
	utils.Logger.Error(msg)
	apFeedback.Errors = append(apFeedback.Errors, msg)
}

func logFeedbackWarning(apFeedback *sync_to_target.AccessProviderSyncFeedback, msg string) {
	utils.Logger.Warn(msg)
	apFeedback.Warnings = append(apFeedback.Warnings, msg)
}

func (a *AccessSyncer) getUserGroupMap(ctx context.Context) (map[string][]string, error) {
	if a.userGroupMap != nil {
		return a.userGroupMap, nil
	}

	groups, err := a.iamRepo.GetGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("get groups: %w", err)
	}

	a.userGroupMap = make(map[string][]string)

	users, err := a.iamRepo.GetUsers(ctx, false)
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

func (a *AccessSyncer) doSyncAccessProviderToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler) (err error) {
	if accessProviders == nil || len(accessProviders.AccessProviders) == 0 {
		utils.Logger.Info("No access providers to sync from Raito to AWS")
		return nil
	}

	utils.Logger.Info(fmt.Sprintf("Provisioning %d access providers to AWS", len(accessProviders.AccessProviders)))

	bucketRegionMap, err := a.getBucketRegionMap()
	if err != nil {
		return fmt.Errorf("get bucket region map: %w", err)
	}

	feedbackMap := make(map[string]*sync_to_target.AccessProviderSyncFeedback)

	// Sort access providers on type
	typeSortedAccessProviders := NewAccessProvidersByType()

	typeCount := make(map[model.AccessProviderType]int)

	for i := range accessProviders.AccessProviders {
		accessProvider := accessProviders.AccessProviders[i]

		if accessProvider == nil {
			continue
		}

		// Create the initial feedback object
		apFeedback := &sync_to_target.AccessProviderSyncFeedback{
			AccessProvider: accessProvider.Id,
		}
		feedbackMap[accessProvider.Id] = apFeedback

		apType := resolveApType(accessProvider, a.cfgMap)
		apFeedback.Type = ptr.String(string(apType))

		t := typeSortedAccessProviders.AddAccessProvider(apType, accessProvider, apFeedback, a.nameGenerator)
		if t == nil {
			continue
		}

		if _, found := typeCount[*t]; !found {
			typeCount[*t] = 0
		}

		typeCount[*t]++
	}

	// Based on AWS dependencies we handle the access providers in the following order:
	// 1. Roles
	// 2. Policies
	// 3. Permission Sets (if organization is enabled)
	// 4. Access Points

	handlers := make([]*AccessHandler, 0, 4)

	if c, found := typeCount[model.Role]; found && c > 0 {
		roleHandler := NewRoleAccessHandler(&typeSortedAccessProviders, a.repo, a.getUserGroupMap, a.account)
		handlers = append(handlers, &roleHandler)
	}

	if c, found := typeCount[model.Policy]; found && c > 0 {
		policyHandler := NewPolicyAccessHandler(&typeSortedAccessProviders, a.repo, a.account)
		handlers = append(handlers, &policyHandler)
	}

	if c, found := typeCount[model.SSORole]; !utils.CheckNilInterface(a.ssoRepo) && found && c > 0 {
		ssoRoleHandler := NewSSORoleAccessHandler(&typeSortedAccessProviders, a.repo, a.ssoRepo, a.getUserGroupMap, a.account)
		handlers = append(handlers, &ssoRoleHandler)
	}

	if c, found := typeCount[model.AccessPoint]; found && c > 0 {
		s3AccessPointHandler := NewAccessProviderHandler(&typeSortedAccessProviders, a.repo, a.getUserGroupMap, a.account)
		handlers = append(handlers, &s3AccessPointHandler)
	}

	// Initialize handlers
	for _, handler := range handlers {
		err = handler.Initialize(ctx, a.cfgMap, bucketRegionMap)
		if err != nil {
			return fmt.Errorf("initialize handler %T: %w", handler, err)
		}
	}

	// Making sure we always send the feedback back
	defer func() {
		for _, feedback := range feedbackMap {
			err2 := accessProviderFeedbackHandler.AddAccessProviderFeedback(*feedback)
			if err2 != nil {
				err = multierror.Append(err, err2)
			}
		}
	}()

	// Start processing access providers
	for _, handler := range handlers {
		handler.PrepareAccessProviders(ctx)
	}

	// Process Inheritance
	for _, handler := range handlers {
		handler.ProcessInheritance()
	}

	// Update access providers
	for _, handler := range handlers {
		utils.Logger.Info(fmt.Sprintf("Handling update and creation of access providers with type %s", handler.handlerType))
		handler.HandleUpdates(ctx)
	}

	// Delete old access providers
	for i := range handlers {
		handler := handlers[len(handlers)-1-i]
		utils.Logger.Info(fmt.Sprintf("Handling deletion of access providers with type %s", handler.handlerType))
		handler.HandleDeletes(ctx)
	}

	return nil
}

func resolveApType(ap *sync_to_target.AccessProvider, configmap *config.ConfigMap) model.AccessProviderType {
	if ap.Type != nil {
		return model.AccessProviderType(*ap.Type)
	}

	if ap.Action == sync_to_target.Purpose {
		if configmap.GetStringWithDefault(constants.AwsOrganizationProfile, "") != "" {
			return model.SSORole
		} else {
			return model.Role
		}
	}

	utils.Logger.Warn(fmt.Sprintf("No type provided for access provider %q. Using Policy as default", ap.Name))

	return model.Policy
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

func createPolicyStatementsFromWhat(whatItems []sync_to_target.WhatItem, cfg *config.ConfigMap) []*awspolicy.Statement {
	policyInfo := map[string][]string{}

	for _, what := range whatItems {
		if len(what.Permissions) == 0 {
			continue
		}

		if _, found := policyInfo[what.DataObject.FullName]; !found {
			dot := data_source.GetDataObjectType(what.DataObject.Type, cfg)
			allPermissions := what.Permissions

			if dot != nil {
				allPermissions = toPermissionList(dot.GetPermissions())
			}

			fullName := what.DataObject.FullName

			// TODO: later this should only be done for S3 resources?
			if strings.Contains(fullName, ":") { // Cutting off the 'accountID:region:' prefix
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

func removeArn(input []model.PolicyBinding) []model.PolicyBinding {
	result := []model.PolicyBinding{}

	for _, val := range input {
		val.ResourceId = ""
		result = append(result, val)
	}

	return result
}
