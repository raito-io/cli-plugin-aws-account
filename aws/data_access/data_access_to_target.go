package data_access

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go/ptr"
	"github.com/gammazero/workerpool"
	"github.com/hashicorp/go-multierror"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source/permissions"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
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
	lock    sync.Mutex
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

		t := a.addAccessProvider(apType, accessProvider, a.nameGenerator)
		if t == nil {
			continue
		}
	}
}

func (a *AccessToTargetSyncer) addAccessProvider(t model.AccessProviderType, ap *sync_to_target.AccessProvider, nameGenerator *NameGenerator) *model.AccessProviderType {
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

func (a *AccessToTargetSyncer) handleRole(ctx context.Context, role *sync_to_target.AccessProvider, name string) {
	if role.ExternalId != nil {
		origName := getNameFromExternalId(*role.ExternalId) // Parsing the name out of the external ID

		if name != origName {
			utils.Logger.Warn(fmt.Sprintf("New name %q does not correspond with current name %q. Renaming is currently not supported, so keeping the old name.", name, origName))
			name = origName
		}
	}

	if role.Delete {
		utils.Logger.Info(fmt.Sprintf("Deleting role %s", role.Name))

		err := a.repo.DeleteRole(ctx, name)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while removing role %q: %s", name, err.Error()))
		}
		return
	}

	existingRole, err := a.repo.GetRoleByName(ctx, name)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while fetching existing role %q: %s", name, err.Error()))
		return
	}

	targetUsers := set.NewSet[string]()

	for _, user := range role.Who.Users {
		targetUsers.Add(user)
	}

	err = a.unpackGroups(ctx, role.Who.Groups, targetUsers)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while unpacking groups for role %q: %s", name, err.Error()))
		return
	}

	userNames := targetUsers.Slice()
	sort.Strings(userNames)

	// Getting the what
	statements := createPolicyStatementsFromWhat(role.What, a.cfgMap)

	if existingRole == nil {
		utils.Logger.Info(fmt.Sprintf("Creating role %s", name))

		created, err2 := a.repo.CreateRole(ctx, name, role.Description, userNames)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to create role %q: %s", name, err2.Error()))
			return
		} else if !created {
			logFeedbackWarning(a.feedbackMap[role.Id], fmt.Sprintf("Role %q not created.", name))
			return
		}
	} else {
		utils.Logger.Info(fmt.Sprintf("Updating role %s", name))

		// Handle the who
		err = a.repo.UpdateAssumeEntities(ctx, name, userNames)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to update role %q: %s", name, err.Error()))
			return
		}

		// For roles, we always delete all the inline policies.
		// If we wouldn't do that, we would be blind on what the role actually looks like.
		// If new permissions are supported later on, we would never see them.
		err = a.repo.DeleteRoleInlinePolicies(ctx, name)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to cleanup inline policies for role %q: %s", name, err.Error()))
			return
		}
	}

	a.feedbackMap[role.Id].ExternalId = ptr.String(constants.RoleTypePrefix + name)
	a.feedbackMap[role.Id].ActualName = name
	a.idToExternalIdMap[role.Id] = constants.RoleTypePrefix + name

	// Handling the what of the role
	if len(statements) > 0 {
		// Create the inline policy for the what
		err = a.repo.CreateRoleInlinePolicy(ctx, name, "Raito_Inline_"+name, statements)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("failed to create inline policies for role %q: %s", name, err.Error()))
			return
		}
	}
}

func (a *AccessToTargetSyncer) handleRoles(ctx context.Context) {
	wp := workerpool.New(workerPoolSize)

	for _, role := range a.Roles {
		// Doing this synchronous as it is not thread-safe and fast enough
		name, err := a.nameGenerator.GenerateName(role, model.Role)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while generating name for role %q: %s", role.Name, err.Error()))
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Generated role name %q for grant %q", name, role.Name))

		wp.Submit(func() {
			a.handleRole(ctx, role, name)
		})
	}

	wp.StopWait()
}

func (a *AccessToTargetSyncer) handleSSORole(ctx context.Context, role *sync_to_target.AccessProvider, name string) {
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
		return
	}

	existingPermissionSet := existingPermissionSets[name]

	if role.Delete {
		if existingPermissionSet == nil {
			utils.Logger.Info(fmt.Sprintf("No existing permission set found for role %q. Skipping deletion.", name))
			return
		}

		utils.Logger.Info(fmt.Sprintf("Deleting role %s", role.Name))

		err2 := a.ssoRepo.DeleteSsoRole(ctx, existingPermissionSet.arn)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while removing role %q: %s", name, err2.Error()))
		}
		return
	}

	permissionSetArn := ""

	if existingPermissionSet == nil {
		utils.Logger.Info(fmt.Sprintf("Creating permission set %q", name))

		permissionSetArn, err = a.ssoRepo.CreateSsoRole(ctx, name, role.Description)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to create permission set %q: %s", name, err.Error()))
			return
		}

		if permissionSetArn == "" {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to create permission set %q: no ARN returned", name))
			return
		}
	} else {
		utils.Logger.Info(fmt.Sprintf("Updating permission set %q", name))

		permissionSetArn = existingPermissionSet.arn

		// Update the permission set name
		err = a.ssoRepo.UpdateSsoRole(ctx, existingPermissionSet.arn, role.Description)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to update permission set %q: %s", name, err.Error()))
			return
		}
	}

	a.feedbackMap[role.Id].ExternalId = ptr.String(constants.SsoRoleTypePrefix + name)
	a.feedbackMap[role.Id].ActualName = name
	a.idToExternalIdMap[role.Id] = constants.SsoRoleTypePrefix + name

	// Update who
	existingBindings := set.NewSet[model.PolicyBinding]()
	if existingPermissionSet != nil {
		existingBindings = existingPermissionSet.bindings
	}

	a.updatePermissionSetWho(ctx, role, existingBindings, permissionSetArn, name)

	// Update What
	a.updatePermissionSetWhat(ctx, role, name, permissionSetArn)

	_, err = a.ssoRepo.ProvisionPermissionSet(ctx, permissionSetArn)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to provision permission set %q: %s", name, err.Error()))
	}
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

	bindingsToRemove := utils.SetSubtract(existingBindings, targetBindings)

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

	for binding := range bindingsToRemove {
		var principalType ssoTypes.PrincipalType
		var principalId string

		if binding.Type == iam.UserResourceType {
			principalType = ssoTypes.PrincipalTypeUser
			principalId, _ = users.GetBackwards(binding.ResourceName)

			if principalId == "" {
				logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to find user to unassign %q", binding.ResourceName))

				continue
			}
		} else if binding.Type == iam.GroupResourceType {
			principalType = ssoTypes.PrincipalTypeGroup
			principalId, _ = groups.GetBackwards(binding.ResourceName)

			if principalId == "" {
				logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to find group to unassign %q", binding.ResourceName))

				continue
			}
		} else {
			continue
		}

		err = a.ssoRepo.UnassignPermissionSet(ctx, permissionSetArn, principalType, principalId)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to remove %s %q from permission set %q: %s", principalType, binding.ResourceName, name, err.Error()))
		}
	}

	bindingsToAdd := utils.SetSubtract(targetBindings, existingBindings)

	for binding := range bindingsToAdd {
		var principalType ssoTypes.PrincipalType
		var principalId string

		if binding.Type == iam.UserResourceType {
			principalType = ssoTypes.PrincipalTypeUser
			principalId, _ = users.GetBackwards(binding.ResourceName)

			if principalId == "" {
				logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to find user to assign %q", binding.ResourceName))

				continue
			}
		} else if binding.Type == iam.GroupResourceType {
			principalType = ssoTypes.PrincipalTypeGroup
			principalId, _ = groups.GetBackwards(binding.ResourceName)

			if principalId == "" {
				logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to find group to assign %q", binding.ResourceName))

				continue
			}
		} else {
			continue
		}

		err = a.ssoRepo.AssignPermissionSet(ctx, permissionSetArn, principalType, principalId)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to add %s %q to permission set %q: %s", principalType, binding.ResourceName, name, err.Error()))
		}
	}
}

func (a *AccessToTargetSyncer) updatePermissionSetWhat(ctx context.Context, role *sync_to_target.AccessProvider, name string, permissionSetArn string) {
	a.updatePermissionSetWhatDataObjects(ctx, role, name, permissionSetArn)

	err := a.updatePermissionSetWhatPolicies(ctx, role, name, permissionSetArn)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Gailed to update roles for permission set %q: %s", name, err.Error()))
	}
}

func (a *AccessToTargetSyncer) updatePermissionSetWhatPolicies(ctx context.Context, role *sync_to_target.AccessProvider, name string, permissionSetArn string) error {
	// TODO
	return nil
}

func (a *AccessToTargetSyncer) updatePermissionSetWhatDataObjects(ctx context.Context, role *sync_to_target.AccessProvider, name string, permissionSetArn string) {
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

func (a *AccessToTargetSyncer) fetchExistingPermissionSets(ctx context.Context) (map[string]*permissionSetData, error) {
	if a.cachedPermissionSets != nil {
		return a.cachedPermissionSets, nil
	}

	utils.Logger.Info("Loading existing permission sets")

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

func (a *AccessToTargetSyncer) handleSSORoles(ctx context.Context) {
	wp := workerpool.New(workerPoolSize)

	for _, ssoRole := range a.PermissionSets {
		// Doing this synchronous as it is not thread-safe and fast enough
		name, err := a.nameGenerator.GenerateName(ssoRole, model.SSORole)
		if err != nil {
			logFeedbackError(a.feedbackMap[ssoRole.Id], fmt.Sprintf("Error while generating name for SSO role %q: %s", ssoRole.Name, err.Error()))
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Generated role name %q for grant %q", name, ssoRole.Name))

		wp.Submit(func() {
			a.handleSSORole(ctx, ssoRole, name)
		})
	}

	wp.StopWait()
}

func (a *AccessToTargetSyncer) handleAccessPoints(ctx context.Context) {
	for _, accessPoint := range a.AccessPoints {
		newName, err := a.nameGenerator.GenerateName(accessPoint, model.AccessPoint)
		if err != nil {
			logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Error while generating name for access point %q: %s", accessPoint.Name, err.Error()))
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Generated access point name %q for grant %q", newName, accessPoint.Name))

		var origName, region string

		var existingAccessPoint *model.AwsS3AccessPoint

		if accessPoint.ExternalId != nil {
			origName, region, err = extractAccessPointNameAndRegionFromArn(getNameFromExternalId(*accessPoint.ExternalId))
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to extract access point name and region from external id %q: %s", *accessPoint.ExternalId, err.Error()))
				continue
			}

			if newName != origName {
				utils.Logger.Warn(fmt.Sprintf("New name %q does not correspond with current name %q. Renaming is currently not supported, so keeping the old name.", newName, origName))
				newName = origName
			}

			existingAccessPoint, err = a.repo.GetAccessPointByNameAndRegion(ctx, origName, region)
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Error while fetching existing access point %q: %s", origName, err.Error()))
				continue
			}
		}

		if accessPoint.Delete {
			utils.Logger.Info(fmt.Sprintf("Deleting access point %s", accessPoint.Name))

			if accessPoint.ExternalId == nil {
				utils.Logger.Info(fmt.Sprintf("No external id found for access point %s. Will consider it as already deleted.", accessPoint.Name))
				continue
			}

			err = a.repo.DeleteAccessPoint(ctx, origName, region)
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to delete access point %q: %s", accessPoint.Name, err.Error()))
			}

			continue
		}

		targetPrincipals := set.NewSet[string]()

		for _, user := range accessPoint.Who.Users {
			targetPrincipals.Add(utils.GetTrustUserPolicyArn("user", user, a.accessSyncer.account).String())
		}

		groupUsers := set.NewSet[string]()
		err = a.unpackGroups(ctx, accessPoint.Who.Groups, groupUsers)
		if err != nil {
			logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Error while unpacking groups for access point %q: %s", newName, err.Error()))
			continue
		}

		for _, user := range groupUsers.Slice() {
			targetPrincipals.Add(utils.GetTrustUserPolicyArn("user", user, a.accessSyncer.account).String())
		}

		shouldSleep := false

		for _, inherited := range accessPoint.Who.InheritFrom {
			inheritedExternalId := inherited

			if strings.HasPrefix(inherited, "ID:") {
				shouldSleep = true // sleeping because this is a newly created role. See later.

				id := inherited[3:] // Cutting off the 'ID:' prefix
				if externalId, found := a.idToExternalIdMap[id]; found {
					inheritedExternalId = externalId
				} else {
					logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to attach dependency %q to access point %q", inherited, newName))
					continue
				}
			}

			if roleName, hasCut := strings.CutPrefix(inheritedExternalId, constants.RoleTypePrefix); hasCut {
				targetPrincipals.Add(utils.GetTrustUserPolicyArn("role", roleName, a.accessSyncer.account).String())
			} else if roleName, hasCut = strings.CutPrefix(inheritedExternalId, constants.SsoRoleTypePrefix); hasCut {
				role, err2 := a.repo.GetSsoRoleWithPrefix(ctx, roleName, []string{})
				if err2 != nil {
					logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to get SSO role %q to link to access point %q: %s", roleName, newName, err2.Error()))
					continue
				}

				targetPrincipals.Add(role.ARN)
			} else {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Invalid inheritFrom value %q for access point %q", inheritedExternalId, newName))
				continue
			}
		}

		// For some reason, new roles are not immediately available to link to and cause an error when creating/updating the access point.
		// So when linking to a new role, we'll sleep for a bit to make sure it's available.
		if shouldSleep {
			time.Sleep(roleDelay * time.Second)
		}

		principals := targetPrincipals.Slice()
		sort.Strings(principals)

		// Getting the what
		statements := createPolicyStatementsFromWhat(accessPoint.What, a.cfgMap)
		whatItems := make([]sync_to_target.WhatItem, 0, len(accessPoint.What))
		whatItems = append(whatItems, accessPoint.What...)

		statements = mergeStatementsOnPermissions(statements)
		filterAccessPointPermissions(statements)

		bucketName, region, err2 := extractBucketForAccessPoint(whatItems)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("failed to extract bucket name for access point %q: %s", newName, err2.Error()))
			continue
		}

		accessPointArn := fmt.Sprintf("arn:aws:s3:%s:%s:accesspoint/%s", region, a.accessSyncer.account, newName)
		convertResourceURLsForAccessPoint(statements, accessPointArn)

		if len(principals) > 0 {
			for _, statement := range statements {
				statement.Principal = map[string][]string{
					"AWS": principals,
				}
			}
		}

		var s3ApArn string

		if existingAccessPoint == nil {
			utils.Logger.Info(fmt.Sprintf("Creating access point %s", newName))

			// Create the new access point with the who
			s3ApArn, err = a.repo.CreateAccessPoint(ctx, newName, bucketName, region, statements)
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to create access point %q: %s", newName, err.Error()))
				continue
			}
		} else {
			utils.Logger.Info(fmt.Sprintf("Updating access point %s", newName))

			// Handle the who
			err = a.repo.UpdateAccessPoint(ctx, newName, region, statements)
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to update access point %q: %s", newName, err.Error()))
				continue
			}
		}

		a.feedbackMap[accessPoint.Id].ExternalId = ptr.String(constants.AccessPointTypePrefix + s3ApArn)
		a.feedbackMap[accessPoint.Id].ActualName = newName
		a.idToExternalIdMap[accessPoint.Id] = constants.AccessPointTypePrefix + s3ApArn
	}
}

func extractAccessPointNameAndRegionFromArn(acArn string) (string, string, error) {
	// arn:aws:s3:us-west-2:123456789012:accesspoint/mybucket
	s3apArn, err2 := arn.Parse(acArn)
	if err2 != nil {
		return "", "", fmt.Errorf("parsing access point ARN %q: %w", acArn, err2)
	}

	return s3apArn.Resource[12:], s3apArn.Region, nil
}

func filterAccessPointPermissions(statements []*awspolicy.Statement) {
	applicableActions := permissions.ApplicableS3AccessPointActions()

	for _, statement := range statements {
		actions := make([]string, 0, len(statement.Action))

		for _, action := range statement.Action {
			if applicableActions.Contains(action) {
				actions = append(actions, action)
			}
		}

		statement.Action = actions
	}
}

func (a *AccessToTargetSyncer) handlePolicies(ctx context.Context) {
	for _, policy := range a.Policies {
		newName, err := a.nameGenerator.GenerateName(policy, model.Policy)
		if err != nil {
			logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Error while generating name for policy %q: %s", policy.Name, err.Error()))
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Generated policy name %q for grant %q", newName, policy.Name))

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

		if nameToDelete != "" {
			utils.Logger.Info(fmt.Sprintf("Deleting policy %s", nameToDelete))

			// We're assuming that an AWS managed policy can't be deleted
			err = a.repo.DeleteManagedPolicy(ctx, nameToDelete, false)
			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Error while removing policy %q: %s", nameToDelete, err.Error()))
			}

			if policy.Delete { // If we needed just to delete it, that's all we need to do
				continue
			}
		} else {
			existingPolicy, err = a.repo.GetManagedPolicyByName(ctx, newName)
			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Error while fetching existing policy %q: %s", newName, err.Error()))
				continue
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
				continue
			} else if p == nil {
				logFeedbackWarning(a.feedbackMap[policy.Id], fmt.Sprintf("Policy %q not created.", newName))
				continue
			}

			policyArn = *p.Arn
		} else {
			policyArn = existingPolicy.ARN
			utils.Logger.Info(fmt.Sprintf("Updating policy %s", newName))

			err = a.repo.UpdateManagedPolicy(ctx, newName, false, statements)

			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to update managed policy %q: %s", newName, err.Error()))
				continue
			}

			existingUserBindings.Add(policyBindingsToNames(existingPolicy.UserBindings)...)
			existingGroupBindings.Add(policyBindingsToNames(existingPolicy.GroupBindings)...)
			existingRoleBindings.Add(policyBindingsToNames(existingPolicy.RoleBindings)...)
		}

		a.feedbackMap[policy.Id].ExternalId = ptr.String(constants.PolicyTypePrefix + newName)
		a.feedbackMap[policy.Id].ActualName = newName
		a.idToExternalIdMap[policy.Id] = constants.PolicyTypePrefix + newName

		// Now handling the WHO part of the policy

		// Adding and removing users from the policy
		targetUserBindings := set.NewSet[string](policy.Who.Users...)

		usersToAdd := utils.SetSubtract(targetUserBindings, existingUserBindings)
		for _, user := range usersToAdd.Slice() {
			utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to user: %s", newName, user))

			err = a.repo.AttachUserToManagedPolicy(ctx, policyArn, []string{user})
			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to attach user %q to managed policy %q: %s", user, newName, err.Error()))
				continue
			}
		}

		usersToRemove := utils.SetSubtract(existingUserBindings, targetUserBindings)
		for _, user := range usersToRemove.Slice() {
			utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", newName, user))

			err = a.repo.DetachUserFromManagedPolicy(ctx, policyArn, []string{user})
			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to detach user %q from managed policy %q: %s", user, newName, err.Error()))
				continue
			}
		}

		// Adding and removing groups from the policy
		targetGroupBindings := set.NewSet[string](policy.Who.Groups...)

		groupsToAdd := utils.SetSubtract(targetGroupBindings, existingGroupBindings)
		for _, group := range groupsToAdd.Slice() {
			utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to group: %s", newName, group))

			err = a.repo.AttachGroupToManagedPolicy(ctx, policyArn, []string{group})
			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to attach group %q to managed policy %q: %s", group, newName, err.Error()))
				continue
			}
		}

		groupsToRemove := utils.SetSubtract(existingGroupBindings, targetGroupBindings)
		for _, group := range groupsToRemove.Slice() {
			utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from group: %s", newName, group))

			err = a.repo.DetachGroupFromManagedPolicy(ctx, policyArn, []string{group})
			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to detach group %q from managed policy %q: %s", group, newName, err.Error()))
				continue
			}
		}

		// Adding and removing roles from the policy
		targetRoleBindings := set.NewSet[string]()

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

			if !strings.HasPrefix(inheritedExternalId, constants.RoleTypePrefix) {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Invalid role reference %q in managed policy %q", inherited, newName))
				continue
			}

			targetRoleBindings.Add(getNameFromExternalId(inheritedExternalId))
		}

		rolesToAdd := utils.SetSubtract(targetRoleBindings, existingRoleBindings)
		for _, role := range rolesToAdd.Slice() {
			utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to role: %s", newName, role))

			err = a.repo.AttachRoleToManagedPolicy(ctx, policyArn, []string{role})
			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to attach role %q to managed policy %q: %s", role, newName, err.Error()))
				continue
			}
		}

		rolesToRemove := utils.SetSubtract(existingRoleBindings, targetRoleBindings)
		for _, role := range rolesToRemove.Slice() {
			utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from role: %s", newName, role))

			err = a.repo.DetachRoleFromManagedPolicy(ctx, policyArn, []string{role})
			if err != nil {
				logFeedbackError(a.feedbackMap[policy.Id], fmt.Sprintf("Failed to detach role %q from managed policy %q: %s", role, newName, err.Error()))
				continue
			}
		}
	}
}

func policyBindingsToNames(bindings []model.PolicyBinding) []string {
	names := make([]string, 0, len(bindings))

	for _, binding := range bindings {
		names = append(names, binding.ResourceName)
	}

	return names
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
