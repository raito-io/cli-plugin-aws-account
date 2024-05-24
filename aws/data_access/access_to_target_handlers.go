package data_access

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/smithy-go/ptr"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
)

type UserGroupMapFunc func(ctx context.Context, configMap *config.ConfigMap) (map[string][]string, error)
type InheritanceResolverFunc func(aps ...string) ([]string, error)

type AccessProviderDetails struct {
	ap                 *sync_to_target.AccessProvider
	name               string
	apType             model.AccessProviderType
	action             AccessProviderAction
	inheritance        set.Set[string]
	inverseInheritance set.Set[string]
	newBindings        set.Set[model.PolicyBinding]
	existingBindings   set.Set[model.PolicyBinding]
	apFeedback         *sync_to_target.AccessProviderSyncFeedback
}

func (a *AccessProviderDetails) GetExistingOrNewBindings() set.Set[model.PolicyBinding] {
	if a.IsExternal() {
		return a.existingBindings
	}

	return a.newBindings
}

func (a *AccessProviderDetails) IsExternal() bool {
	return a.newBindings == nil
}

func NewAccessProviderDetails(ap *sync_to_target.AccessProvider, t model.AccessProviderType, apFeedback *sync_to_target.AccessProviderSyncFeedback) *AccessProviderDetails {
	return &AccessProviderDetails{
		ap:                 ap,
		apType:             t,
		action:             ActionUnknown,
		inheritance:        set.NewSet[string](),
		inverseInheritance: set.NewSet[string](),
		apFeedback:         apFeedback,
	}
}

type accessHandlerExecutor interface {
	HookInlinePolicies(ap *sync_to_target.AccessProvider)
	ExternalId(name string, t model.AccessProviderType) string
	HandleGroupBindings(ctx context.Context, configMap *config.ConfigMap, groups []string) (set.Set[model.PolicyBinding], error)
	HandleInheritance(detailsMap map[string]*AccessProviderDetails, otherAccessDetails map[string]*AccessProviderDetails)
	ExecuteUpdates(ctx context.Context, details map[string]*AccessProviderDetails, configMap *config.ConfigMap)
}

func NewAccessHandler(executor accessHandlerExecutor, actionMap map[string]AccessProviderAction, whoBindings map[string]set.Set[model.PolicyBinding], inheritanceResolver InheritanceResolverFunc) *AccessHandler {
	return &AccessHandler{
		accessProviderDetails: map[string]*AccessProviderDetails{},
		executor:              executor,
		inheritanceResolver:   inheritanceResolver,
		actionMap:             actionMap,
		whoBindings:           whoBindings,
	}
}

type AccessHandler struct {
	accessProviderDetails map[string]*AccessProviderDetails

	actionMap   map[string]AccessProviderAction
	whoBindings map[string]set.Set[model.PolicyBinding]

	inheritanceResolver InheritanceResolverFunc
	executor            accessHandlerExecutor
}

func (a *AccessHandler) AddAccessProvider(ap *sync_to_target.AccessProvider, t model.AccessProviderType, apFeedback *sync_to_target.AccessProviderSyncFeedback, configMap *config.ConfigMap) {
	printDebugAp(ap)

	details := NewAccessProviderDetails(ap, t, apFeedback)

	apFeedback.Type = ptr.String(string(t))

	// Generate nane
	name, err := utils.GenerateName(ap, t)
	if err != nil {
		logFeedbackError(apFeedback, fmt.Sprintf("failed to generate actual name for access provider %q: %s", ap.Name, err.Error()))

		return
	}

	if existingBindings, found := a.whoBindings[name]; found {
		details.existingBindings = existingBindings
	}

	apFeedback.ActualName = name
	details.name = name

	if ap.Action != sync_to_target.Grant && ap.Action != sync_to_target.Purpose {
		logFeedbackError(apFeedback, fmt.Sprintf("unsupported access provider action: %d", ap.Action))

		return
	}

	a.executor.HookInlinePolicies(ap)

	_, found := a.actionMap[name]

	if ap.Delete {
		if found {
			details.action = ActionDelete
			a.accessProviderDetails[name] = details
		}

		return
	}

	// Create or update
	externalId := a.executor.ExternalId(name, t)
	apFeedback.ExternalId = &externalId

	details.action = ActionCreate
	if found {
		details.action = ActionUpdate
	}

	// Storing the inheritance information to handle every we covered all APs
	apInheritFromNames, err := a.inheritanceResolver(ap.Who.InheritFrom...)
	if err != nil {
		logFeedbackError(apFeedback, fmt.Sprintf("resolving inherited access providers: %s", err.Error()))

		return
	}

	details.inheritance.Add(apInheritFromNames...)

	// Handling the WHO by converting it to policy bindings
	details.newBindings = set.NewSet[model.PolicyBinding]()

	for _, user := range ap.Who.Users {
		key := model.PolicyBinding{
			Type:         iam.UserResourceType,
			ResourceName: user,
		}
		details.newBindings.Add(key)
	}

	groupBindings, err := a.executor.HandleGroupBindings(context.Background(), configMap, ap.Who.Groups)
	if err != nil {
		logFeedbackError(apFeedback, fmt.Sprintf("handling group bindings: %s", err.Error()))

		return
	}

	details.newBindings.AddSet(groupBindings)

	a.accessProviderDetails[name] = details
}

func (a *AccessHandler) ProcessInheritance(otherDetailMaps map[string]*AccessProviderDetails) map[string]*AccessProviderDetails {
	a.executor.HandleInheritance(a.accessProviderDetails, otherDetailMaps)

	return a.accessProviderDetails
}

func (a *AccessHandler) HandleUpdates(ctx context.Context, configMap *config.ConfigMap) {
	// Build inverse inheritance map
	for name, details := range a.accessProviderDetails {
		for inheritedFrom := range details.inheritance {
			if _, f := a.accessProviderDetails[inheritedFrom]; f {
				a.accessProviderDetails[inheritedFrom].inverseInheritance.Add(name)
			}
		}
	}

	a.executor.ExecuteUpdates(ctx, a.accessProviderDetails, configMap)
}

var _ accessHandlerExecutor = (*roleAccessHandler)(nil)

func NewRoleAccessHandler(repo dataAccessRepository, getUserGroupMap UserGroupMapFunc, actionMap map[string]AccessProviderAction, whoBindings map[string]set.Set[model.PolicyBinding], inheritanceResolver InheritanceResolverFunc) *AccessHandler {
	executor := &roleAccessHandler{
		repo:            repo,
		getUserGroupMap: getUserGroupMap,
	}

	return NewAccessHandler(executor, actionMap, whoBindings, inheritanceResolver)
}

type roleAccessHandler struct {
	repo            dataAccessRepository
	getUserGroupMap UserGroupMapFunc
}

func (r *roleAccessHandler) HookInlinePolicies(_ *sync_to_target.AccessProvider) {
	// No-op
}

func (r *roleAccessHandler) ExternalId(name string, t model.AccessProviderType) string {
	if t == model.Role {
		return fmt.Sprintf("%s%s", constants.RoleTypePrefix, name)
	}

	return name
}

func (r *roleAccessHandler) HandleGroupBindings(ctx context.Context, configMap *config.ConfigMap, groups []string) (set.Set[model.PolicyBinding], error) {
	return unpackGroups(ctx, configMap, groups, r.getUserGroupMap)
}

func (r *roleAccessHandler) HandleInheritance(detailsMap map[string]*AccessProviderDetails, _ map[string]*AccessProviderDetails) {
	for name, details := range detailsMap {
		descendants := getDescendants(detailsMap, name)
		for descendant := range descendants {
			details.newBindings.AddSet(detailsMap[descendant].GetExistingOrNewBindings())
		}
	}
}

func (r *roleAccessHandler) ExecuteUpdates(ctx context.Context, detailsMap map[string]*AccessProviderDetails, _ *config.ConfigMap) {
	for name, details := range detailsMap {
		utils.Logger.Info(fmt.Sprintf("Processing role %s with action %s", name, details.action))

		switch details.action {
		case ActionDelete:
			utils.Logger.Info(fmt.Sprintf("Removing role %s", name))

			err := r.repo.DeleteRole(ctx, name)
			if err != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to delete role %q: %s", name, err.Error()))
			}
		case ActionCreate, ActionUpdate:
			utils.Logger.Info(fmt.Sprintf("Existing bindings for %s: %s", name, details.existingBindings))
			utils.Logger.Info(fmt.Sprintf("Export bindings for %s: %s", name, details.newBindings))

			// Getting the who (for roles, this should already contain the list of unpacked users from the groups (as those are not supported for roles)
			userNames := make([]string, 0, len(details.newBindings))
			for binding := range details.newBindings {
				userNames = append(userNames, binding.ResourceName)
			}

			sort.Strings(userNames)

			// Getting the what
			ap := details.ap
			statements := createPolicyStatementsFromWhat(ap.What)

			// Because we need to flatten the WHAT for roles as well, we gather all role APs from which this role AP inherits its what (following the reverse inheritance chain)
			inheritedAPs := getAllAPsInInheritanceChainForWhatDetails(name, detailsMap)
			for _, inheritedAP := range inheritedAPs {
				statements = append(statements, createPolicyStatementsFromWhat(inheritedAP.What)...)
			}

			if details.action == ActionCreate {
				utils.Logger.Info(fmt.Sprintf("Creating role %s", name))

				// Create the new role with the who
				created, err2 := r.repo.CreateRole(ctx, name, ap.Description, userNames)
				if err2 != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to create role %q: %s", name, err2.Error()))
					continue
				} else if !created {
					logFeedbackWarning(details.apFeedback, fmt.Sprintf("role %q not created.", name))
					continue
				}
			} else {
				utils.Logger.Info(fmt.Sprintf("Updating role %s", name))

				// Handle the who
				err := r.repo.UpdateAssumeEntities(ctx, name, userNames)
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update role %q: %s", name, err.Error()))
					continue
				}

				// For roles, we always delete all the inline policies.
				// If we wouldn't do that, we would be blind on what the role actually looks like.
				// If new permissions are supported later on, we would never see them.
				err = r.repo.DeleteRoleInlinePolicies(ctx, name)
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to cleanup inline policies for role %q: %s", name, err.Error()))
					continue
				}
			}

			if len(statements) > 0 {
				// Create the inline policy for the what
				err := r.repo.CreateRoleInlinePolicy(ctx, name, "Raito_Inline_"+name, statements)
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to create inline policies for role %q: %s", name, err.Error()))
					continue
				}
			}
		default:
			utils.Logger.Debug(fmt.Sprintf("no action needed for role %q", name))
		}
	}
}

var _ accessHandlerExecutor = (*policyAccessHandler)(nil)

func NewPolicyAccessHandler(repo dataAccessRepository, actionMap map[string]AccessProviderAction, whoBindings map[string]set.Set[model.PolicyBinding], inheritanceResolver InheritanceResolverFunc) *AccessHandler {
	executor := &policyAccessHandler{
		repo: repo,

		inlineUserPoliciesToDelete:  map[string][]string{},
		inlineGroupPoliciesToDelete: map[string][]string{},
	}

	return NewAccessHandler(executor, actionMap, whoBindings, inheritanceResolver)
}

type policyAccessHandler struct {
	repo dataAccessRepository

	inlineUserPoliciesToDelete  map[string][]string
	inlineGroupPoliciesToDelete map[string][]string
}

func (p *policyAccessHandler) HookInlinePolicies(ap *sync_to_target.AccessProvider) {
	if ap.ExternalId != nil && strings.Contains(*ap.ExternalId, constants.InlinePrefix) {
		eId := *ap.ExternalId

		utils.Logger.Info(fmt.Sprintf("Processing externalId %q for access provider %q", eId, ap.Name))

		inlineString := eId[strings.Index(eId, constants.InlinePrefix)+len(constants.InlinePrefix):]
		inlinePolicies := strings.Split(inlineString, "|")

		// Note: for roles we currently don't do this as we simply remove/replace all the inline policies
		if strings.HasPrefix(eId, constants.UserTypePrefix) {
			entityName := eId[len(constants.UserTypePrefix):strings.Index(eId, "|")]

			p.inlineUserPoliciesToDelete[entityName] = inlinePolicies

			utils.Logger.Info(fmt.Sprintf("Handled inline policies for user %q: %v", entityName, inlinePolicies))
		} else if strings.HasPrefix(eId, constants.GroupTypePrefix) {
			entityName := eId[len(constants.GroupTypePrefix):strings.Index(eId, "|")]

			p.inlineGroupPoliciesToDelete[entityName] = inlinePolicies

			utils.Logger.Info(fmt.Sprintf("Handled inline policies for group %q: %v", entityName, inlinePolicies))
		}
	}
}

func (p *policyAccessHandler) ExternalId(name string, _ model.AccessProviderType) string {
	return fmt.Sprintf("%s%s", constants.PolicyTypePrefix, name)
}

func (p *policyAccessHandler) HandleGroupBindings(_ context.Context, _ *config.ConfigMap, groups []string) (set.Set[model.PolicyBinding], error) {
	result := set.Set[model.PolicyBinding]{}

	for _, group := range groups {
		key := model.PolicyBinding{
			Type:         iam.GroupResourceType,
			ResourceName: group,
		}

		result.Add(key)
	}

	return result, nil
}

func (p *policyAccessHandler) HandleInheritance(detailsMap map[string]*AccessProviderDetails, otherAccessDetails map[string]*AccessProviderDetails) {
	processPolicyInheritance(detailsMap, otherAccessDetails)
}

func (p *policyAccessHandler) ExecuteUpdates(ctx context.Context, detailMap map[string]*AccessProviderDetails, configMap *config.ConfigMap) {
	managedPolicies, skippedPolicies := p.createAndUpdateRaitoPolicies(ctx, detailMap)

	p.deleteOldPolicies(ctx, detailMap, managedPolicies)

	p.updatePolicyBindings(ctx, detailMap, configMap, skippedPolicies, managedPolicies)

	// Delete old inline policies on users that are not needed anymore
	p.deleteInlinePolicies(ctx, p.inlineUserPoliciesToDelete, iam.UserResourceType)

	// Delete old inline policies on groups that are not needed anymore
	p.deleteInlinePolicies(ctx, p.inlineGroupPoliciesToDelete, iam.GroupResourceType)
}

func (p *policyAccessHandler) updatePolicyBindings(ctx context.Context, detailMap map[string]*AccessProviderDetails, configMap *config.ConfigMap, skippedPolicies set.Set[string], managedPolicies set.Set[string]) {
	// Now handle the WHO of the policies
	policyBindingsToAdd := map[string]set.Set[model.PolicyBinding]{}
	policyBindingsToRemove := map[string]set.Set[model.PolicyBinding]{}

	for name, details := range detailMap {
		if skippedPolicies.Contains(name) {
			continue
		}

		// only touch the access providers that are in the export
		if details.action == ActionUpdate || details.action == ActionCreate {
			policyBindingsToAdd[name] = set.NewSet(details.newBindings.Slice()...)
			policyBindingsToAdd[name].RemoveAll(details.existingBindings.Slice()...)

			policyBindingsToRemove[name] = set.NewSet(details.existingBindings.Slice()...)
			policyBindingsToRemove[name].RemoveAll(details.newBindings.Slice()...)
		}
	}

	for name, bindings := range policyBindingsToAdd { //nolint:dupl // false positive
		details := detailMap[name]

		policyArn := p.repo.GetPolicyArn(name, managedPolicies.Contains(name), configMap)

		for binding := range bindings {
			switch binding.Type {
			case iam.UserResourceType:
				utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to user: %s", name, binding.ResourceName))

				err := p.repo.AttachUserToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to attach user %q to managed policy %q: %s", binding.ResourceName, name, err.Error()))
					continue
				}
			case iam.GroupResourceType:
				utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to group: %s", name, binding.ResourceName))

				err := p.repo.AttachGroupToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to attach group %q to managed policy %q: %s", binding.ResourceName, name, err.Error()))
					continue
				}
			case iam.RoleResourceType:
				utils.Logger.Debug(fmt.Sprintf("Attaching policy %s to role: %s", name, binding.ResourceName))

				err := p.repo.AttachRoleToManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to attach role %q to managed policy %q: %s", binding.ResourceName, name, err.Error()))
					continue
				}
			}
		}
	}

	// Now handle the WHO bindings to remove for policies
	for name, bindings := range policyBindingsToRemove { //nolint:dupl // false positive
		details := detailMap[name]

		policyArn := p.repo.GetPolicyArn(name, managedPolicies.Contains(name), configMap)

		for binding := range bindings {
			switch binding.Type {
			case iam.UserResourceType:
				utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", name, binding.ResourceName))

				err := p.repo.DetachUserFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to deattach user %q from managed policy %q: %s", binding.ResourceName, name, err.Error()))
					continue
				}
			case iam.GroupResourceType:
				utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from group: %s", name, binding.ResourceName))

				err := p.repo.DetachGroupFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to deattach group %q from managed policy %q: %s", binding.ResourceName, name, err.Error()))
					continue
				}
			case iam.RoleResourceType:
				utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from user: %s", name, binding.ResourceName))

				err := p.repo.DetachRoleFromManagedPolicy(ctx, policyArn, []string{binding.ResourceName})
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to deattach role %q from managed policy %q: %s", binding.ResourceName, name, err.Error()))
					continue
				}
			}
		}
	}
}

func (p *policyAccessHandler) deleteOldPolicies(ctx context.Context, detailMap map[string]*AccessProviderDetails, managedPolicies set.Set[string]) {
	for name, details := range detailMap {
		if details.action == ActionDelete {
			utils.Logger.Info(fmt.Sprintf("Deleting policy %s", name))

			err := p.repo.DeleteManagedPolicy(ctx, name, managedPolicies.Contains(name))
			if err != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to delete managed policy %q: %s", name, err.Error()))
				continue
			}
		}
	}
}

func (p *policyAccessHandler) createAndUpdateRaitoPolicies(ctx context.Context, detailMap map[string]*AccessProviderDetails) (set.Set[string], set.Set[string]) {
	managedPolicies := set.NewSet[string]()
	skippedPolicies := set.NewSet[string]()

	for name, details := range detailMap {
		if details.ap.WhatLocked != nil && *details.ap.WhatLocked {
			managedPolicies.Add(name)
		}

		action := details.action

		utils.Logger.Info(fmt.Sprintf("Process policy %s, action: %s", name, action))

		statements := createPolicyStatementsFromWhat(details.ap.What)

		if action == ActionCreate {
			utils.Logger.Info(fmt.Sprintf("Creating policy %s", name))

			p, err2 := p.repo.CreateManagedPolicy(ctx, name, statements)
			if err2 != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to create managed policy %q: %s", name, err2.Error()))
				skippedPolicies.Add(name)

				continue
			}

			if p == nil {
				skippedPolicies.Add(name)
			}
		} else if action == ActionUpdate && !managedPolicies.Contains(name) {
			utils.Logger.Info(fmt.Sprintf("Updating policy %s", name))
			err := p.repo.UpdateManagedPolicy(ctx, name, false, statements)

			if err != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update managed policy %q: %s", name, err.Error()))
				continue
			}
		}
	}

	return managedPolicies, skippedPolicies
}

func (p *policyAccessHandler) deleteInlinePolicies(ctx context.Context, policies map[string][]string, resourceType string) {
	for resource, inlinePolicies := range policies {
		for _, inlinePolicy := range inlinePolicies {
			inlinePolicy = strings.TrimSpace(inlinePolicy)
			if inlinePolicy != "" {
				err := p.repo.DeleteInlinePolicy(ctx, inlinePolicy, resource, resourceType)
				if err != nil {
					utils.Logger.Warn(fmt.Sprintf("error while deleting inline policy %q for %q: %s", inlinePolicy, resource, err.Error()))
				}
			}
		}
	}
}

var _ accessHandlerExecutor = (*accessPointAccessHandler)(nil)

func NewAccessProviderHandler(account string, repo dataAccessRepository, getUserGroupMap UserGroupMapFunc, actionMap map[string]AccessProviderAction, whoBindings map[string]set.Set[model.PolicyBinding], inheritanceResolver InheritanceResolverFunc) *AccessHandler {
	executor := &accessPointAccessHandler{
		account:         account,
		repo:            repo,
		getUserGroupMap: getUserGroupMap,
	}

	return NewAccessHandler(executor, actionMap, whoBindings, inheritanceResolver)
}

type accessPointAccessHandler struct {
	account         string
	repo            dataAccessRepository
	getUserGroupMap UserGroupMapFunc
}

func (a *accessPointAccessHandler) HookInlinePolicies(_ *sync_to_target.AccessProvider) {
	// no-op
}

func (a *accessPointAccessHandler) ExternalId(name string, _ model.AccessProviderType) string {
	return fmt.Sprintf("%s%s", constants.AccessPointTypePrefix, name)
}

func (a *accessPointAccessHandler) HandleGroupBindings(ctx context.Context, configMap *config.ConfigMap, groups []string) (set.Set[model.PolicyBinding], error) {
	return unpackGroups(ctx, configMap, groups, a.getUserGroupMap)
}

func (a *accessPointAccessHandler) HandleInheritance(detailsMap map[string]*AccessProviderDetails, otherAccessDetails map[string]*AccessProviderDetails) {
	processPolicyInheritance(detailsMap, otherAccessDetails)
}

func (a *accessPointAccessHandler) ExecuteUpdates(ctx context.Context, detailsMap map[string]*AccessProviderDetails, configMap *config.ConfigMap) {
	for accessPointName, details := range detailsMap {
		accessPointAp := details.ap

		utils.Logger.Info(fmt.Sprintf("Processing access point %s with action %s", accessPointName, details.action))

		switch details.action {
		case ActionDelete:
			utils.Logger.Info(fmt.Sprintf("Removing access point %s", accessPointName))

			if accessPointAp.ExternalId == nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to delete access point %q as no external id is found", accessPointName))
				continue
			}

			// Extract the region from the access point external ID
			extId := *accessPointAp.ExternalId
			extId = extId[len(constants.AccessPointTypePrefix):]

			region := ""
			if strings.Contains(extId, ":") {
				region = extId[:strings.Index(extId, ":")] //nolint:gocritic
			} else {
				logFeedbackError(details.apFeedback, fmt.Sprintf("invalid external id found %q", *accessPointAp.ExternalId))
				continue
			}

			err := a.repo.DeleteAccessPoint(ctx, accessPointName, region)
			if err != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to delete access point %q: %s", accessPointName, err.Error()))
				continue
			}
		case ActionCreate, ActionUpdate:
			utils.Logger.Info(fmt.Sprintf("Existing bindings for %s: %s", accessPointName, details.existingBindings))
			utils.Logger.Info(fmt.Sprintf("Export bindings for %s: %s", accessPointName, details.newBindings))

			who := set.NewSet(details.newBindings.Slice()...)

			// Getting the who (for access points, this should already contain the list of unpacked users from the groups (as those are not supported for roles)
			principals := make([]string, 0, len(who))

			for _, binding := range who.Slice() {
				if binding.Type == iam.UserResourceType || binding.Type == iam.RoleResourceType {
					principals = append(principals, utils.GetTrustPolicyArn(binding.ResourceName, a.account))
				}
			}

			sort.Strings(principals)

			// Getting the what
			statements := createPolicyStatementsFromWhat(accessPointAp.What)
			whatItems := make([]sync_to_target.WhatItem, 0, len(accessPointAp.What))
			whatItems = append(whatItems, accessPointAp.What...)

			// Because we need to flatten the WHAT for access points as well, we gather all access point APs from which this access point AP inherits its what (following the reverse inheritance chain)
			inheritedAPs := getAllAPsInInheritanceChainForWhatDetails(accessPointName, detailsMap)
			for _, inheritedAP := range inheritedAPs {
				whatItems = append(whatItems, inheritedAP.What...)
				statements = append(statements, createPolicyStatementsFromWhat(inheritedAP.What)...)
			}

			bucketName, region, err2 := extractBucketForAccessPoint(whatItems)
			if err2 != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to extract bucket name for access point %q: %s", accessPointName, err2.Error()))
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

			if details.action == ActionCreate {
				utils.Logger.Info(fmt.Sprintf("Creating access point %s", accessPointName))

				// Create the new access point with the who
				err := a.repo.CreateAccessPoint(ctx, accessPointName, bucketName, region, statements)
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to create access point %q: %s", accessPointName, err.Error()))
					continue
				}
			} else {
				utils.Logger.Info(fmt.Sprintf("Updating access point %s", accessPointName))

				// Handle the who
				err := a.repo.UpdateAccessPoint(ctx, accessPointName, region, statements)
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update access point %q: %s", accessPointName, err.Error()))
					continue
				}
			}
		default:
			utils.Logger.Debug(fmt.Sprintf("no action needed for access point %q", accessPointName))
		}
	}
}

func unpackGroups(ctx context.Context, configMap *config.ConfigMap, groups []string, getUserGroupMap func(ctx context.Context, configMap *config.ConfigMap) (map[string][]string, error)) (set.Set[model.PolicyBinding], error) {
	result := set.NewSet[model.PolicyBinding]()

	if len(groups) == 0 {
		return result, nil
	}

	userGroupMap, err := getUserGroupMap(ctx, configMap)
	if err != nil {
		return nil, err
	}

	// Roles don't support assignment to groups, so we take the users in the groups and add those directly.
	for _, group := range groups {
		if users, f := userGroupMap[group]; f {
			for _, user := range users {
				key := model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: user,
				}
				result.Add(key)
			}
		}
	}

	return result, nil
}

func processPolicyInheritance(policyDetails map[string]*AccessProviderDetails, roleDetails map[string]*AccessProviderDetails) {
	for name, details := range policyDetails {
		if details.IsExternal() {
			// External policy so we skip it
			continue
		}

		policyDescendants := getDescendants(policyDetails, name)
		roleDescendants := set.NewSet[string]()

		for descendant := range policyDescendants {

			if _, f := roleDetails[descendant]; f {
				// If the dependency is a role, we register it as a role descendant
				roleDescendants.Add(descendant)
				roleDescendants.AddSet(getDescendants(roleDetails, descendant))
			} else if policy, f := policyDetails[descendant]; f {
				// In this case the descendant is not an internal access provider. Let's see if it is an external one to get those dependencies
				if !policy.IsExternal() {
					// The case where the internal AP depends on an external AP (of type policy). In that case we have to look at the bindings to see if there are roles in there.
					for binding := range policy.newBindings {
						if binding.Type == iam.RoleResourceType {
							if _, f := roleDetails[binding.ResourceName]; f {
								roleDescendants.Add(binding.ResourceName)
								roleDescendants.AddSet(getDescendants(roleDetails, binding.ResourceName))
							}
						}
					}
				}
			}
		}

		// For descendants that are roles, we need to add that role as a binding for this policy
		for descendant := range roleDescendants {
			roleBinding := model.PolicyBinding{
				Type:         iam.RoleResourceType,
				ResourceName: descendant,
			}

			details.newBindings.Add(roleBinding)
		}
	}

	for name, details := range policyDetails {
		policyDescendants := getDescendants(policyDetails, name)

		// For descendants that are policies
		for descendant := range policyDescendants {
			if policy, f := policyDetails[descendant]; f {
				details.newBindings.AddSet(policy.GetExistingOrNewBindings())
			}
		}
	}
}

func getDescendants(accessDetailsChilds map[string]*AccessProviderDetails, name string) set.Set[string] {
	descendants := set.NewSet[string]()

	if v, found := accessDetailsChilds[name]; found {
		for child := range v.inheritance {
			descendants.Add(child)
			descendants.AddSet(getDescendants(accessDetailsChilds, child))
		}
	}

	return descendants
}
