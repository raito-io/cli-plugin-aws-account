package data_access

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go/ptr"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source/permissions"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
)

type UserGroupMapFunc func(ctx context.Context, configMap *config.ConfigMap) (map[string][]string, error)

type AccessProvidersByType struct {
	Roles          map[string]*AccessProviderDetails
	Policies       map[string]*AccessProviderDetails
	AccessPoints   map[string]*AccessProviderDetails
	PermissionSets map[string]*AccessProviderDetails

	AccessProviderById map[string]*AccessProviderDetails
}

func NewAccessProvidersByType() AccessProvidersByType {
	return AccessProvidersByType{
		Roles:          map[string]*AccessProviderDetails{},
		Policies:       map[string]*AccessProviderDetails{},
		AccessPoints:   map[string]*AccessProviderDetails{},
		PermissionSets: map[string]*AccessProviderDetails{},

		AccessProviderById: map[string]*AccessProviderDetails{},
	}
}

func (a *AccessProvidersByType) AddAccessProvider(t model.AccessProviderType, ap *sync_to_target.AccessProvider, apFeedback *sync_to_target.AccessProviderSyncFeedback, nameGenerator *NameGenerator) {
	details := NewAccessProviderDetails(ap, t, apFeedback)

	apFeedback.Type = ptr.String(string(t))

	a.AccessProviderById[ap.Id] = details

	// Generate nane
	name, err := nameGenerator.GenerateName(ap, t)
	if err != nil {
		logFeedbackError(apFeedback, fmt.Sprintf("failed to generate actual name for access provider %q: %s", ap.Name, err.Error()))

		return
	}

	apFeedback.ActualName = name
	details.name = name

	switch t {
	case model.Role:
		a.Roles[name] = details
	case model.SSORole:
		a.PermissionSets[name] = details
	case model.Policy:
		a.Policies[name] = details
	case model.AccessPoint:
		a.AccessPoints[name] = details
	}
}

func (a *AccessProvidersByType) GetAccessProvider(t model.AccessProviderType, name string) *AccessProviderDetails {
	switch t {
	case model.Role:
		return a.Roles[name]
	case model.SSORole:
		return a.PermissionSets[name]
	case model.Policy:
		return a.Policies[name]
	case model.AccessPoint:
		return a.AccessPoints[name]
	}

	return nil
}

func (a *AccessProvidersByType) GetDescendants(t model.AccessProviderType, name string, allowedTypes ...model.AccessProviderType) set.Set[*AccessProviderDetails] {
	allowedTypesSet := set.NewSet(allowedTypes...)
	if len(allowedTypes) == 0 {
		allowedTypesSet = set.NewSet(model.Role, model.SSORole, model.AccessPoint, model.Policy)
	}

	result := set.NewSet[*AccessProviderDetails]()

	details := a.GetAccessProvider(t, name)
	if details == nil {
		return result
	}

	for childType, childNames := range details.inheritance {
		if !allowedTypesSet.Contains(childType) {
			continue
		}

		for _, childName := range childNames {
			childDetails := a.GetAccessProvider(childType, childName)
			if childDetails != nil {
				result.Add(childDetails)
				result.AddSet(a.GetDescendants(childType, childName, allowedTypesSet.Slice()...))
			}
		}
	}

	return result
}

func (a *AccessProvidersByType) GetAllAccessProvidersInInheritanceChainForWhat(t model.AccessProviderType, start string, allowedTypes ...model.AccessProviderType) set.Set[*AccessProviderDetails] {
	allowedTypesSet := set.NewSet(allowedTypes...)
	if len(allowedTypes) == 0 {
		allowedTypesSet = set.NewSet(model.Role, model.SSORole, model.AccessPoint, model.Policy)
	}

	result := set.NewSet[*AccessProviderDetails]()

	details := a.GetAccessProvider(t, start)
	for parentType, parents := range details.inverseInheritance {
		if !allowedTypesSet.Contains(parentType) {
			continue
		}

		for _, parent := range parents {
			result.Add(a.GetAccessProvider(parentType, parent))
			result.AddSet(a.GetAllAccessProvidersInInheritanceChainForWhat(parentType, parent, allowedTypes...))
		}
	}

	return result
}

type AccessHandlerExecutor interface {
	Initialize(configmap *config.ConfigMap)
	FetchExistingBindings(ctx context.Context) (map[string]set.Set[model.PolicyBinding], error)
	HookInlinePolicies(ap *sync_to_target.AccessProvider)
	ExternalId(details *AccessProviderDetails) *string
	HandleGroupBindings(ctx context.Context, groups []string) (set.Set[model.PolicyBinding], error)
	HandleInheritance()
	ExecuteUpdates(ctx context.Context)
}

func NewAccessHandler(executor AccessHandlerExecutor, handlerType model.AccessProviderType,
	accessProviderDetails map[string]*AccessProviderDetails, accessProvidersByType *AccessProvidersByType) AccessHandler {
	return AccessHandler{
		accessProviderDetails: accessProviderDetails,
		accessProvidersByType: accessProvidersByType,
		handlerType:           handlerType,
		executor:              executor,
	}
}

type AccessHandler struct {
	accessProviderDetails map[string]*AccessProviderDetails
	accessProvidersByType *AccessProvidersByType
	handlerType           model.AccessProviderType

	// cache
	existingBindings map[string]set.Set[model.PolicyBinding]

	executor AccessHandlerExecutor
}

func (a *AccessHandler) Initialize(ctx context.Context, configmap *config.ConfigMap) error {
	a.executor.Initialize(configmap)

	bindings, err := a.executor.FetchExistingBindings(ctx)
	if err != nil {
		return fmt.Errorf("fetch existing bindings: %w", err)
	}

	a.existingBindings = bindings

	return nil
}

func (a *AccessHandler) PrepareAccessProviders() {
	for name, details := range a.accessProviderDetails {
		a.preparationForAccessProvider(name, details)
	}
}

func (a *AccessHandler) preparationForAccessProvider(name string, details *AccessProviderDetails) {
	existingBindings, found := a.existingBindings[name]

	if found {
		details.existingBindings = existingBindings
	}

	ap := details.ap
	apFeedback := details.apFeedback

	if ap.Action != sync_to_target.Grant && ap.Action != sync_to_target.Purpose {
		logFeedbackError(apFeedback, fmt.Sprintf("unsupported access provider action: %d", ap.Action))

		return
	}

	a.executor.HookInlinePolicies(ap)

	if ap.Delete {
		if found {
			details.action = ActionDelete
			a.accessProviderDetails[name] = details
		}

		return
	}

	// Create or update
	details.action = ActionCreate
	if found {
		details.action = ActionUpdate
	}

	apFeedback.ExternalId = a.executor.ExternalId(details)

	// Storing the inheritance information to handle every we covered all APs
	apInheritFromNames := a.resolveInheritance(ap.Who.InheritFrom...)

	details.inheritance = apInheritFromNames

	// Handling the WHO by converting it to policy bindings
	details.newBindings = set.NewSet[model.PolicyBinding]()

	for _, user := range ap.Who.Users {
		key := model.PolicyBinding{
			Type:         iam.UserResourceType,
			ResourceName: user,
		}
		details.newBindings.Add(key)
	}

	apGroupBindings, err := a.executor.HandleGroupBindings(context.Background(), ap.Who.Groups)
	if err != nil {
		logFeedbackError(apFeedback, fmt.Sprintf("handling group bindings: %s", err.Error()))

		return
	}

	details.newBindings.AddSet(apGroupBindings)
}

func (a *AccessHandler) resolveInheritance(names ...string) map[model.AccessProviderType][]string {
	result := map[model.AccessProviderType][]string{}

	for _, name := range names {
		if !strings.HasPrefix(name, "ID:") {
			// No id is set so we assume the name is the name of the access provider with the same type
			result[a.handlerType] = append(result[a.handlerType], name)
		}

		parts := strings.Split(name, "ID:")
		if len(parts) != 2 {
			continue
		}

		apID := parts[1]
		if details, found := a.accessProvidersByType.AccessProviderById[apID]; found {
			result[details.apType] = append(result[details.apType], details.name)
		}
	}

	return result
}

func (a *AccessHandler) ProcessInheritance() map[string]*AccessProviderDetails {
	a.executor.HandleInheritance()

	// Build inverse inheritance map
	for name, details := range a.accessProviderDetails {
		for apType, inheritedSet := range details.inheritance {
			var inheritedAccessProviderMap map[string]*AccessProviderDetails

			switch apType {
			case model.Role:
				inheritedAccessProviderMap = a.accessProvidersByType.Roles
			case model.SSORole:
				inheritedAccessProviderMap = a.accessProvidersByType.PermissionSets
			case model.Policy:
				inheritedAccessProviderMap = a.accessProvidersByType.Policies
			case model.AccessPoint:
				inheritedAccessProviderMap = a.accessProvidersByType.AccessPoints
			}

			for _, inheritedFrom := range inheritedSet {
				if _, f := inheritedAccessProviderMap[inheritedFrom]; f {
					utils.Logger.Info(fmt.Sprintf("Add %q to inversed inheritance of %q", name, inheritedFrom))
					inheritedAccessProviderMap[inheritedFrom].inverseInheritance[a.handlerType] = append(inheritedAccessProviderMap[inheritedFrom].inverseInheritance[a.handlerType], name)
				} else {
					utils.Logger.Warn(fmt.Sprintf("Didn't found %q to in access providers of expected type %s", inheritedFrom, apType))
				}
			}
		}
	}

	return a.accessProviderDetails
}

func (a *AccessHandler) HandleUpdates(ctx context.Context) {
	a.executor.ExecuteUpdates(ctx)
}

func NewRoleAccessHandler(allAccessProviders *AccessProvidersByType, repo dataAccessRepository, getUserGroupMap UserGroupMapFunc, account string) AccessHandler {
	executor := &roleAccessHandler{
		accessProviders: allAccessProviders,
		repo:            repo,
		getUserGroupMap: getUserGroupMap,
		account:         account,
	}

	return NewAccessHandler(executor, model.Role, allAccessProviders.Roles, allAccessProviders)
}

type roleAccessHandler struct {
	accessProviders *AccessProvidersByType
	repo            dataAccessRepository
	getUserGroupMap UserGroupMapFunc
	account         string

	configMap *config.ConfigMap
}

func (r *roleAccessHandler) Initialize(configmap *config.ConfigMap) {
	r.configMap = configmap
}

func (r *roleAccessHandler) FetchExistingBindings(ctx context.Context) (map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing roles")

	roles, err := r.repo.GetRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching existing roles: %w", err)
	}

	existingRoleAssumptions := map[string]set.Set[model.PolicyBinding]{}

	for _, role := range roles {
		who, _ := iam.CreateWhoFromTrustPolicyDocument(role.AssumeRolePolicy, role.Name, r.account)
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

	utils.Logger.Info(fmt.Sprintf("Fetched existing %d roles", len(existingRoleAssumptions)))

	return existingRoleAssumptions, nil
}

func (r *roleAccessHandler) HookInlinePolicies(ap *sync_to_target.AccessProvider) {
	// No-op
}

func (r *roleAccessHandler) ExternalId(details *AccessProviderDetails) *string {
	return ptr.String(fmt.Sprintf("%s%s", constants.RoleTypePrefix, details.name))
}
func (r *roleAccessHandler) HandleGroupBindings(ctx context.Context, groups []string) (set.Set[model.PolicyBinding], error) {
	return unpackGroups(ctx, r.configMap, groups, r.getUserGroupMap)
}

func (r *roleAccessHandler) HandleInheritance() {
	for name, details := range r.accessProviders.Roles {
		descendants := r.accessProviders.GetDescendants(model.Role, name, model.Role)
		for descendant := range descendants {
			details.newBindings.AddSet(descendant.GetExistingOrNewBindings())
		}
	}
}

func (r *roleAccessHandler) ExecuteUpdates(ctx context.Context) {
	for name, details := range r.accessProviders.Roles {
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
			inheritedAPs := r.accessProviders.GetAllAccessProvidersInInheritanceChainForWhat(model.Role, name, model.Role)
			for inheritedAP := range inheritedAPs {
				statements = append(statements, createPolicyStatementsFromWhat(inheritedAP.ap.What)...)
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

func NewPolicyAccessHandler(allAccessProviders *AccessProvidersByType, repo dataAccessRepository, account string) AccessHandler {
	executor := &policyAccessHandler{
		account:         account,
		accessProviders: allAccessProviders,
		repo:            repo,

		inlineUserPoliciesToDelete:  map[string][]string{},
		inlineGroupPoliciesToDelete: map[string][]string{},
	}

	return NewAccessHandler(executor, model.Policy, allAccessProviders.Policies, allAccessProviders)
}

type policyAccessHandler struct {
	account         string
	accessProviders *AccessProvidersByType
	repo            dataAccessRepository

	inlineUserPoliciesToDelete  map[string][]string
	inlineGroupPoliciesToDelete map[string][]string

	configMap *config.ConfigMap
}

func (p *policyAccessHandler) Initialize(configmap *config.ConfigMap) {
	p.configMap = configmap
}

func (p *policyAccessHandler) FetchExistingBindings(ctx context.Context) (map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing managed policies")

	managedPolicies, err := p.repo.GetManagedPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching existing managed policies: %w", err)
	}

	existingPolicyBindings := map[string]set.Set[model.PolicyBinding]{}

	for ind := range managedPolicies {
		policy := managedPolicies[ind]

		existingPolicyBindings[policy.Name] = set.Set[model.PolicyBinding]{}

		existingPolicyBindings[policy.Name].Add(removeArn(policy.UserBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.GroupBindings)...)
		existingPolicyBindings[policy.Name].Add(removeArn(policy.RoleBindings)...)
	}

	utils.Logger.Info(fmt.Sprintf("Fetched existing %d managed policies", len(existingPolicyBindings)))

	return existingPolicyBindings, nil
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

func (p *policyAccessHandler) ExternalId(details *AccessProviderDetails) *string {
	return ptr.String(fmt.Sprintf("%s%s", constants.PolicyTypePrefix, details.name))
}

func (p *policyAccessHandler) HandleGroupBindings(_ context.Context, groups []string) (set.Set[model.PolicyBinding], error) {
	return groupBindings(groups)
}

func (p *policyAccessHandler) HandleInheritance() {
	processPolicyInheritance(p.accessProviders.Policies, p.accessProviders)
}

func (p *policyAccessHandler) ExecuteUpdates(ctx context.Context) {
	managedPolicies, skippedPolicies := p.createAndUpdateRaitoPolicies(ctx, p.accessProviders.Policies)

	p.deleteOldPolicies(ctx, p.accessProviders.Policies, managedPolicies)

	p.updatePolicyBindings(ctx, p.accessProviders.Policies, skippedPolicies, managedPolicies)

	// Delete old inline policies on users that are not needed anymore
	p.deleteInlinePolicies(ctx, p.inlineUserPoliciesToDelete, iam.UserResourceType)

	// Delete old inline policies on groups that are not needed anymore
	p.deleteInlinePolicies(ctx, p.inlineGroupPoliciesToDelete, iam.GroupResourceType)
}

func (p *policyAccessHandler) updatePolicyBindings(ctx context.Context, detailMap map[string]*AccessProviderDetails, skippedPolicies set.Set[string], managedPolicies set.Set[string]) {
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

		policyArn := p.repo.GetPolicyArn(name, managedPolicies.Contains(name), p.configMap)

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

		policyArn := p.repo.GetPolicyArn(name, managedPolicies.Contains(name), p.configMap)

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

func NewAccessProviderHandler(allAccessProviders *AccessProvidersByType, repo dataAccessRepository, getUserGroupMap UserGroupMapFunc, account string) AccessHandler {
	executor := &accessPointHandler{
		accessProviders: allAccessProviders,
		repo:            repo,
		getUserGroupMap: getUserGroupMap,
		account:         account,
	}

	return NewAccessHandler(executor, model.AccessPoint, allAccessProviders.AccessPoints, allAccessProviders)
}

type accessPointHandler struct {
	accessProviders *AccessProvidersByType
	account         string
	repo            dataAccessRepository
	getUserGroupMap UserGroupMapFunc

	configMap *config.ConfigMap
}

func (a *accessPointHandler) Initialize(configmap *config.ConfigMap) {
	a.configMap = configmap
}

func (a *accessPointHandler) FetchExistingBindings(ctx context.Context) (map[string]set.Set[model.PolicyBinding], error) {
	utils.Logger.Info("Fetching existing access points")

	existingPolicyBindings := map[string]set.Set[model.PolicyBinding]{}

	for _, region := range utils.GetRegions(a.configMap) {
		err := a.fetchExistingAccessPointsForRegion(ctx, region, existingPolicyBindings)
		if err != nil {
			return nil, fmt.Errorf("fetching existing access points for region %s: %w", region, err)
		}
	}

	return existingPolicyBindings, nil
}

func (a *accessPointHandler) fetchExistingAccessPointsForRegion(ctx context.Context, region string, existingPolicyBindings map[string]set.Set[model.PolicyBinding]) error {
	accessPoints, err := a.repo.ListAccessPoints(ctx, region)
	if err != nil {
		return fmt.Errorf("error fetching existing access points: %w", err)
	}

	for ind := range accessPoints {
		accessPoint := accessPoints[ind]

		who, _, _ := iam.CreateWhoAndWhatFromAccessPointPolicy(accessPoint.PolicyParsed, accessPoint.Bucket, accessPoint.Name, a.account)
		if who != nil {
			existingPolicyBindings[accessPoint.Name] = set.Set[model.PolicyBinding]{}

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

	utils.Logger.Info(fmt.Sprintf("Fetched existing %d access points", len(existingPolicyBindings)))

	return nil
}

func (a *accessPointHandler) HookInlinePolicies(ap *sync_to_target.AccessProvider) {
	// no-op
}

func (a *accessPointHandler) ExternalId(details *AccessProviderDetails) *string {
	return ptr.String(fmt.Sprintf("%s%s", constants.AccessPointTypePrefix, details.name))
}

func (a *accessPointHandler) HandleGroupBindings(ctx context.Context, groups []string) (set.Set[model.PolicyBinding], error) {
	return unpackGroups(ctx, a.configMap, groups, a.getUserGroupMap)
}

func (a *accessPointHandler) HandleInheritance() {
	processPolicyInheritance(a.accessProviders.AccessPoints, a.accessProviders)
}

func (a *accessPointHandler) ExecuteUpdates(ctx context.Context) {
	for accessPointName, details := range a.accessProviders.AccessPoints {
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
					principals = append(principals, utils.GetTrustPolicyArn(binding.ResourceName, a.account)) // TODO this is not correct for roles
				}
			}

			sort.Strings(principals)

			// Getting the what
			statements := createPolicyStatementsFromWhat(accessPointAp.What)
			whatItems := make([]sync_to_target.WhatItem, 0, len(accessPointAp.What))
			whatItems = append(whatItems, accessPointAp.What...)

			// Because we need to flatten the WHAT for access points as well, we gather all access point APs from which this access point AP inherits its what (following the reverse inheritance chain)
			inheritedAPs := a.accessProviders.GetAllAccessProvidersInInheritanceChainForWhat(model.AccessPoint, accessPointName, model.AccessPoint)
			for inheritedAP := range inheritedAPs {
				whatItems = append(whatItems, inheritedAP.ap.What...)
				statements = append(statements, createPolicyStatementsFromWhat(inheritedAP.ap.What)...)
			}

			bucketName, region, err2 := extractBucketForAccessPoint(whatItems)
			if err2 != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to extract bucket name for access point %q: %s", accessPointName, err2.Error()))
				continue
			}

			statements = mergeStatementsOnPermissions(statements)
			filterAccessPointPermissions(statements)

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

func NewSSORoleAccessHandler(allAccessProviders *AccessProvidersByType, repo dataAccessRepository, ssoAdmin dataAccessSsoRepository, getUserGroupMap UserGroupMapFunc, account string) AccessHandler {
	executor := &ssoRoleAccessHandler{
		accessProviders: allAccessProviders,
		repo:            repo,
		ssoAdmin:        ssoAdmin,
		getUserGroupMap: getUserGroupMap,
		account:         account,
	}

	return NewAccessHandler(executor, model.SSORole, allAccessProviders.PermissionSets, allAccessProviders)
}

type ssoRoleAccessHandler struct {
	accessProviders *AccessProvidersByType
	account         string
	repo            dataAccessRepository
	ssoAdmin        dataAccessSsoRepository
	getUserGroupMap UserGroupMapFunc

	config *config.ConfigMap
}

func (s *ssoRoleAccessHandler) Initialize(configmap *config.ConfigMap) {
	s.config = configmap
}

func (s *ssoRoleAccessHandler) FetchExistingBindings(ctx context.Context) (map[string]set.Set[model.PolicyBinding], error) {
	result := make(map[string]set.Set[model.PolicyBinding])

	permissionSetArns, err := s.ssoAdmin.ListSsoRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching existing permission sets: %w", err)
	}

	users, err := s.ssoAdmin.GetUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("get users: %w", err)
	}

	groups, err := s.ssoAdmin.GetGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("get groups: %w", err)
	}

	for _, arn := range permissionSetArns {
		permissionSetDetails, err := s.ssoAdmin.GetSsoRole(ctx, arn)
		if err != nil {
			return nil, fmt.Errorf("get permission set details: %w", err)
		}

		assignments, err := s.ssoAdmin.ListPermissionSetAssignment(ctx, arn)
		if err != nil {
			return nil, fmt.Errorf("error fetching existing permission set assignments: %w", err)
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

		result[*permissionSetDetails.Name] = bindings
	}

	return result, nil
}

func (s *ssoRoleAccessHandler) HookInlinePolicies(ap *sync_to_target.AccessProvider) {
	// no-op
}

func (s *ssoRoleAccessHandler) ExternalId(details *AccessProviderDetails) *string {
	return details.ap.ExternalId // The external ID should contain the permission set ARN. If external id is nil an external ID would be created during creation
}

func (s *ssoRoleAccessHandler) HandleGroupBindings(ctx context.Context, groups []string) (set.Set[model.PolicyBinding], error) {
	return groupBindings(groups)
}

func (s *ssoRoleAccessHandler) HandleInheritance() {
	for name, details := range s.accessProviders.PermissionSets {
		descendants := s.accessProviders.GetDescendants(model.SSORole, name)
		for descendant := range descendants {
			details.newBindings.AddSet(descendant.GetExistingOrNewBindings())
		}
	}
}

func (s *ssoRoleAccessHandler) ExecuteUpdates(ctx context.Context) {
	permissionSetArnFromExternalId := func(externalId *string) (string, bool) {
		if externalId == nil || !strings.HasPrefix(*externalId, constants.SsoRoleTypePrefix) {
			return "", false
		}

		return (*externalId)[len(constants.SsoRoleTypePrefix):], true
	}

	for name, details := range s.accessProviders.PermissionSets {
		utils.Logger.Info(fmt.Sprintf("Processing sso role %s with action %s", name, details.action))

		switch details.action {
		case ActionDelete:
			s.deletePermissionSet(ctx, name, permissionSetArnFromExternalId, details)
		case ActionCreate, ActionUpdate:
			utils.Logger.Info(fmt.Sprintf("Existing bindings for %s: %s", name, details.existingBindings))
			utils.Logger.Info(fmt.Sprintf("Export bindings for %s: %s", name, details.newBindings))

			permissionSetArn, err := s.updateOrCreatePermissionSet(ctx, details, permissionSetArnFromExternalId)
			if err != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update or create permission set %q: %s", name, err.Error()))

				continue
			}

			// Update who
			s.updateWho(ctx, details, permissionSetArn, name)

			// Update What
			s.updateWhat(ctx, details, name, permissionSetArn)

			_, err = s.ssoAdmin.ProvisionPermissionSet(ctx, permissionSetArn)
			if err != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to provision permission set %q: %s", name, err.Error()))
			}
		default:
			continue
		}
	}
}

func (s *ssoRoleAccessHandler) updateWhat(ctx context.Context, details *AccessProviderDetails, name string, permissionSetArn string) {
	s.updateWhatDataObjects(ctx, details, name, permissionSetArn)

	err := s.updateWhatPolicies(ctx, name, permissionSetArn, details)
	if err != nil {
		logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update roles for permission set %q: %s", name, err.Error()))
	}
}

func (s *ssoRoleAccessHandler) updateWhatPolicies(ctx context.Context, name string, permissionSetArn string, details *AccessProviderDetails) error {
	inheritedPolicies := s.accessProviders.GetAllAccessProvidersInInheritanceChainForWhat(model.SSORole, name, model.Policy)

	managedPolicies, err := s.repo.GetManagedPolicies(ctx)
	if err != nil {
		return fmt.Errorf("fetching existing managed policies: %w", err)
	}

	managedPolicyMap := make(map[string]*model.PolicyEntity)

	for i := range managedPolicies {
		managedPolicyMap[managedPolicies[i].Name] = &managedPolicies[i]
	}

	existingAwsManagedPolicies, err := s.ssoAdmin.ListAwsManagedPolicyFromPermissionSet(ctx, permissionSetArn)
	if err != nil {
		return fmt.Errorf("fetching existing aws managed policies: %w", err)
	}

	existingCustomerPolicies, err := s.ssoAdmin.ListCustomerManagedPolicyFromPermissionSet(ctx, permissionSetArn)
	if err != nil {
		return fmt.Errorf("fetching existing customer managed policies: %w", err)
	}

	utils.Logger.Info(fmt.Sprintf("Existing aws managed policies for %s: %v", name, existingAwsManagedPolicies.Slice()))
	utils.Logger.Info(fmt.Sprintf("Existing customer managed policies for %s: %v", name, existingCustomerPolicies.Slice()))

	newAwsManagedPolicies := set.NewSet[string]()
	newCustomerManagedPolicies := set.NewSet[string]()

	for inheritedPolicy := range inheritedPolicies {
		if managedPolicy, ok := managedPolicyMap[inheritedPolicy.name]; ok {
			if managedPolicy.AwsManaged {
				newAwsManagedPolicies.Add(inheritedPolicy.name)
			} else {
				newCustomerManagedPolicies.Add(inheritedPolicy.name)
			}
		} else {
			logFeedbackError(details.apFeedback, fmt.Sprintf("policy %q not found in managed policies", inheritedPolicy.name))
		}
	}

	awsPoliciesToRemove := utils.SetSubtract(existingAwsManagedPolicies, newAwsManagedPolicies)
	awsPoliciesToAdd := utils.SetSubtract(newAwsManagedPolicies, existingAwsManagedPolicies)

	for policyName := range awsPoliciesToRemove {
		policy := managedPolicyMap[policyName]

		err = s.ssoAdmin.DetachAwsManagedPolicyFromPermissionSet(ctx, permissionSetArn, policy.ARN)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("removing aws managed policy %q from permission set: %s", policy.Name, err.Error()))
		}
	}

	for policyName := range awsPoliciesToAdd {
		policy := managedPolicyMap[policyName]

		err = s.ssoAdmin.AttachAwsManagedPolicyToPermissionSet(ctx, permissionSetArn, policy.ARN)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("adding customer managed policy %q from permission set: %s", policy.Name, err.Error()))
		}
	}

	customerPoliciesToRemove := utils.SetSubtract(existingCustomerPolicies, newCustomerManagedPolicies)
	customerPoliciesToAdd := utils.SetSubtract(newCustomerManagedPolicies, existingCustomerPolicies)

	for policyName := range customerPoliciesToRemove {
		policy := managedPolicyMap[policyName]

		err = s.ssoAdmin.DetachCustomerManagedPolicyFromPermissionSet(ctx, permissionSetArn, policy.Name, nil)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("removing customer managed policy %q from permission set: %s", policy.Name, err.Error()))
		}
	}

	for policyName := range customerPoliciesToAdd {
		policy := managedPolicyMap[policyName]

		err = s.ssoAdmin.AttachCustomerManagedPolicyToPermissionSet(ctx, permissionSetArn, policy.Name, nil)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("adding customer managed policy %q from permission set: %s", policy.Name, err.Error()))
		}
	}

	return nil
}

func (s *ssoRoleAccessHandler) updateWhatDataObjects(ctx context.Context, details *AccessProviderDetails, name string, permissionSetArn string) {
	statements := createPolicyStatementsFromWhat(details.ap.What) // this should be empty as it is purpose

	// Because we need to flatten the WHAT for roles as well, we gather all role APs from which this role AP inherits its what (following the reverse inheritance chain)
	inheritedWhatToFlatten := s.accessProviders.GetAllAccessProvidersInInheritanceChainForWhat(model.SSORole, name, model.Role, model.SSORole, model.AccessPoint)

	for inheritedAP := range inheritedWhatToFlatten {
		statements = append(statements, createPolicyStatementsFromWhat(inheritedAP.ap.What)...)
	}

	err := s.ssoAdmin.UpdateInlinePolicyToPermissionSet(ctx, permissionSetArn, statements)
	if err != nil {
		logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update inline policy for permission set %q: %s", name, err.Error()))
	}
}

func (s *ssoRoleAccessHandler) updateWho(ctx context.Context, details *AccessProviderDetails, permissionSetArn string, name string) {
	bindings := utils.SetSubtract(details.existingBindings, details.newBindings)

	users, err := s.ssoAdmin.GetUsers(ctx)
	if err != nil {
		logFeedbackError(details.apFeedback, fmt.Sprintf("failed to get users: %s", err.Error()))

		return
	}

	groups, err := s.ssoAdmin.GetGroups(ctx)
	if err != nil {
		logFeedbackError(details.apFeedback, fmt.Sprintf("failed to get groups: %s", err.Error()))

		return
	}

	for binding := range bindings {
		var principalType ssoTypes.PrincipalType
		var principalId string

		if binding.Type == iam.UserResourceType {
			principalType = ssoTypes.PrincipalTypeUser
			principalId, _ = users.GetBackwards(binding.ResourceName)

			if principalId == "" {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to find user to unassign %q", binding.ResourceName))

				continue
			}
		} else if binding.Type == iam.GroupResourceType {
			principalType = ssoTypes.PrincipalTypeGroup
			principalId, _ = groups.GetBackwards(binding.ResourceName)

			if principalId == "" {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to find group to unassign %q", binding.ResourceName))

				continue
			}
		} else {
			continue
		}

		err := s.ssoAdmin.UnassignPermissionSet(ctx, permissionSetArn, principalType, principalId)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to remove %s %q from permission set %q: %s", principalType, binding.ResourceName, name, err.Error()))
		}
	}

	bindings = utils.SetSubtract(details.newBindings, details.existingBindings)

	for binding := range bindings {
		var principalType ssoTypes.PrincipalType
		var principalId string

		if binding.Type == iam.UserResourceType {
			principalType = ssoTypes.PrincipalTypeUser
			principalId, _ = users.GetBackwards(binding.ResourceName)

			if principalId == "" {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to find user to assign %q", binding.ResourceName))

				continue
			}
		} else if binding.Type == iam.GroupResourceType {
			principalType = ssoTypes.PrincipalTypeGroup
			principalId, _ = groups.GetBackwards(binding.ResourceName)

			if principalId == "" {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to find group to assign %q", binding.ResourceName))

				continue
			}
		} else {
			continue
		}

		err := s.ssoAdmin.AssignPermissionSet(ctx, permissionSetArn, principalType, principalId)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to add %s %q from permission set %q: %s", principalType, binding.ResourceName, name, err.Error()))
		}
	}
}

func (s *ssoRoleAccessHandler) updateOrCreatePermissionSet(ctx context.Context, details *AccessProviderDetails, permissionSetArnFn func(externalId *string) (string, bool)) (string, error) {
	permissionSetArn, _ := permissionSetArnFn(details.ap.ExternalId)

	shouldBeCreated := details.action == ActionCreate

	if details.action == ActionUpdate {
		originalPermissionSet, err := s.ssoAdmin.GetSsoRole(ctx, permissionSetArn)
		if err != nil {
			return permissionSetArn, fmt.Errorf("get sso role: %w", err)
		}

		if originalPermissionSet.Name == nil || *originalPermissionSet.Name != details.name {
			shouldBeCreated = true

			err = s.ssoAdmin.DeleteSsoRole(ctx, permissionSetArn)
			if err != nil {
				return permissionSetArn, fmt.Errorf("delete sso role: %w", err)
			}

			permissionSetArn = ""
		} else {
			// Update the permission set name
			err = s.ssoAdmin.UpdateSsoRole(ctx, permissionSetArn, details.ap.Description)
			if err != nil {
				return permissionSetArn, fmt.Errorf("update sso role: %w", err)
			}
		}
	}

	if shouldBeCreated {
		var err error

		permissionSetArn, err = s.ssoAdmin.CreateSsoRole(ctx, details.name, details.ap.Description)
		if err != nil {
			return permissionSetArn, fmt.Errorf("create sso role: %w", err)
		}

		if permissionSetArn == "" {
			return "", errors.New("create sso role: empty permission set arn")
		}

		details.apFeedback.ExternalId = ptr.String(fmt.Sprintf("%s%s", constants.SsoRoleTypePrefix, permissionSetArn))
	}

	return permissionSetArn, nil
}

func (s *ssoRoleAccessHandler) deletePermissionSet(ctx context.Context, name string, permissionSetArnFromExternalId func(externalId *string) (string, bool), details *AccessProviderDetails) {
	utils.Logger.Info(fmt.Sprintf("Removing sso role %s", name))

	if permissionSetArn, f := permissionSetArnFromExternalId(details.ap.ExternalId); f {
		err := s.ssoAdmin.DeleteSsoRole(ctx, permissionSetArn)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to delete sso role %q: %s", name, err.Error()))
		}
	}
}

func groupBindings(groups []string) (set.Set[model.PolicyBinding], error) {
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

func processPolicyInheritance(policyDetails map[string]*AccessProviderDetails, accessProviders *AccessProvidersByType) {
	for _, details := range policyDetails {
		if details.IsExternal() {
			// External policy so we skip it
			continue
		}

		policyDescendants := accessProviders.GetDescendants(details.apType, details.name)
		roleDescendants := set.NewSet[*AccessProviderDetails]()

		for descendant := range policyDescendants {
			if descendant.apType == model.Role {
				roleDescendants.Add(descendant)
				roleDescendants.AddSet(accessProviders.GetDescendants(descendant.apType, descendant.name))
			} else if policy, f := policyDetails[descendant.name]; f {
				if !policy.IsExternal() {
					// The case where the internal AP depends on an external AP (of type policy). In that case we have to look at the bindings to see if there are roles in there.
					for binding := range policy.newBindings {
						if binding.Type == iam.RoleResourceType {
							if role, f := accessProviders.Roles[binding.ResourceName]; f {
								roleDescendants.Add(role)
								roleDescendants.AddSet(accessProviders.GetDescendants(role.apType, binding.ResourceName))
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
				ResourceName: descendant.name,
			}

			details.newBindings.Add(roleBinding)
		}
	}

	for _, details := range policyDetails {
		policyDescendants := accessProviders.GetDescendants(details.apType, details.name)

		// For descendants that are policies
		for descendant := range policyDescendants {
			if descendant.apType == model.Policy {
				details.newBindings.AddSet(descendant.GetExistingOrNewBindings())
			}
		}
	}
}
