package data_access

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

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

const roleDelay = 10
const workerPoolSize = 5

type AccessToTargetSyncer struct {
	accessSyncer *AccessSyncer

	feedbackMap   map[string]*sync_to_target.AccessProviderSyncFeedback
	nameGenerator *NameGenerator

	Roles          []*sync_to_target.AccessProvider
	Policies       []*sync_to_target.AccessProvider
	AccessPoints   []*sync_to_target.AccessProvider
	PermissionSets []*sync_to_target.AccessProvider

	cachedPermissionSets map[string]*permissionSetData

	accessProviderById map[string]*sync_to_target.AccessProvider
	idToExternalIdMap  map[string]string

	userGroupMap map[string][]string

	repo    dataAccessRepository
	ssoRepo dataAccessSsoRepository
	iamRepo dataAccessIamRepository
	cfgMap  *config.ConfigMap

	lock sync.Mutex
}

func NewAccessToTargetSyncer(a *AccessSyncer) *AccessToTargetSyncer {
	return &AccessToTargetSyncer{
		accessSyncer: a,
		repo:         a.repo,
		ssoRepo:      a.ssoRepo,
		iamRepo:      a.iamRepo,
		cfgMap:       a.cfgMap,
	}
}

func (a *AccessSyncer) SyncAccessProviderToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler, configMap *config.ConfigMap) error {
	err := a.initialize(ctx, configMap)
	if err != nil {
		return err
	}

	toTargetSyncer := NewAccessToTargetSyncer(a)

	return toTargetSyncer.doSyncAccessProviderToTarget(ctx, accessProviders, accessProviderFeedbackHandler)
}

func (a *AccessToTargetSyncer) initialize() error {
	nameGenerator, err := NewNameGenerator(a.accessSyncer.account)
	if err != nil {
		return fmt.Errorf("new name generator: %w", err)
	}

	a.nameGenerator = nameGenerator

	_, err = a.accessSyncer.getBucketRegionMap() // Making sure to initialize the bucket region map
	if err != nil {
		return fmt.Errorf("get bucket region map: %w", err)
	}

	a.feedbackMap = make(map[string]*sync_to_target.AccessProviderSyncFeedback)
	a.idToExternalIdMap = make(map[string]string)
	a.accessProviderById = make(map[string]*sync_to_target.AccessProvider)

	return nil
}

// loadAccessProviders loads the access providers into the syncer by putting them into the correct maps.
func (a *AccessToTargetSyncer) loadAccessProviders(accessProviders []*sync_to_target.AccessProvider) {
	for i := range accessProviders {
		accessProvider := accessProviders[i]

		if accessProvider == nil {
			continue
		}

		apType := resolveApType(accessProvider, a.accessSyncer.cfgMap)

		t := a.addAccessProvider(apType, accessProvider)
		if t == nil {
			continue
		}
	}
}

func (a *AccessToTargetSyncer) addAccessProvider(t model.AccessProviderType, ap *sync_to_target.AccessProvider) *model.AccessProviderType {
	// Create the initial feedback object
	apFeedback := &sync_to_target.AccessProviderSyncFeedback{
		AccessProvider: ap.Id,
		Type:           ptr.String(string(t)),
	}
	a.feedbackMap[ap.Id] = apFeedback

	a.accessProviderById[ap.Id] = ap

	if ap.ExternalId != nil {
		a.idToExternalIdMap[ap.Id] = *ap.ExternalId
	}

	switch t {
	case model.Role:
		a.Roles = append(a.Roles, ap)
	case model.SSORole:
		a.PermissionSets = append(a.PermissionSets, ap)
	case model.Policy:
		a.Policies = append(a.Policies, ap)
	case model.AccessPoint:
		a.AccessPoints = append(a.AccessPoints, ap)
	}

	return &t
}

func (a *AccessToTargetSyncer) doSyncAccessProviderToTarget(ctx context.Context, accessProviders *sync_to_target.AccessProviderImport, accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler) (err error) {
	if accessProviders == nil || len(accessProviders.AccessProviders) == 0 {
		utils.Logger.Info("No access providers to sync from Raito to AWS")
		return nil
	}

	utils.Logger.Info(fmt.Sprintf("Provisioning %d access providers to AWS", len(accessProviders.AccessProviders)))

	err = a.initialize() // some initialization stuff we need to do
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}

	a.loadAccessProviders(accessProviders.AccessProviders)

	// Making sure we always send the feedback back
	defer func() {
		err = a.sendFeedback(accessProviderFeedbackHandler)
	}()

	// The possible hierarchy links are these:
	// access point -> role
	// access point -> sso role
	// policy -> role
	// policy -> sso role
	//
	// We'll start with handling from the top to make sure these are created when trying to link to them.

	a.handleRoles(ctx)
	a.handleSSORoles(ctx)
	a.handleAccessPoints(ctx)
	a.handlePolicies(ctx)

	return nil
}

func (a *AccessToTargetSyncer) sendFeedback(accessProviderFeedbackHandler wrappers.AccessProviderFeedbackHandler) error {
	var err error

	for _, feedback := range a.feedbackMap {
		err2 := accessProviderFeedbackHandler.AddAccessProviderFeedback(*feedback)
		if err2 != nil {
			err = multierror.Append(err, err2)
		}
	}

	return err
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

		if !slices.Contains(allPermissions, userPermissions[i]) {
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

// getUserGroupMap returns a map of group names to users they contain
func (a *AccessToTargetSyncer) getUserGroupMap(ctx context.Context) (map[string][]string, error) {
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

func logFeedbackError(apFeedback *sync_to_target.AccessProviderSyncFeedback, msg string) {
	utils.Logger.Error(msg)
	apFeedback.Errors = append(apFeedback.Errors, msg)
}

func logFeedbackWarning(apFeedback *sync_to_target.AccessProviderSyncFeedback, msg string) {
	utils.Logger.Warn(msg)
	apFeedback.Warnings = append(apFeedback.Warnings, msg)
}

func (a *AccessToTargetSyncer) unpackGroups(ctx context.Context, groups []string, result set.Set[string]) error {
	if len(groups) == 0 {
		return nil
	}

	userGroupMap, err := a.getUserGroupMap(ctx)
	if err != nil {
		return fmt.Errorf("get user group map: %w", err)
	}

	for _, group := range groups {
		if users, f := userGroupMap[group]; f {
			for _, user := range users {
				result.Add(user)
			}
		}
	}

	return nil
}

func getNameFromExternalId(externalId string) string {
	return externalId[strings.Index(externalId, ":")+1:]
}
