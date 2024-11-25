package data_access

/*
type UserGroupMapFunc func(ctx context.Context) (map[string][]string, error)

type AccessProvidersByType struct {
	Roles          map[string]*AccessProviderDetails
	Policies       map[string]*AccessProviderDetails
	AccessPoints   map[string]*AccessProviderDetails
	PermissionSets map[string]*AccessProviderDetails

	accessProviderById map[string]*AccessProviderDetails
	idToExternalIdMap  map[string]string
}

func NewAccessProvidersByType() AccessProvidersByType {
	return AccessProvidersByType{
		Roles:          map[string]*AccessProviderDetails{},
		Policies:       map[string]*AccessProviderDetails{},
		AccessPoints:   map[string]*AccessProviderDetails{},
		PermissionSets: map[string]*AccessProviderDetails{},

		accessProviderById: map[string]*AccessProviderDetails{},
		idToExternalIdMap:  map[string]string{},
	}
}

func (a *AccessProvidersByType) AddAccessProvider(t model.AccessProviderType, ap *sync_to_target.AccessProvider, apFeedback *sync_to_target.AccessProviderSyncFeedback, nameGenerator *NameGenerator) *model.AccessProviderType {
	details := NewAccessProviderDetails(ap, t, apFeedback)

	apFeedback.Type = ptr.String(string(t))

	a.accessProviderById[ap.Id] = details

	if ap.ExternalId != nil {
		a.idToExternalIdMap[ap.Id] = *ap.ExternalId
	}

	// Generate name
	name, err := nameGenerator.GenerateName(ap, t)
	if err != nil {
		logFeedbackError(apFeedback, fmt.Sprintf("failed to generate actual name for access provider %q: %s", ap.Name, err.Error()))

		return nil
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

	return &t
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

type AccessHandlerExecutor interface {
	Initialize(configmap *config.ConfigMap)
	FetchExistingBindings(ctx context.Context, name string, bucketRegionMap map[string]string) (set.Set[model.PolicyBinding], error)
	HookInlinePolicies(ap *sync_to_target.AccessProvider)
	ExternalId(name string, details *AccessProviderDetails) *string
	HandleGroupBindings(ctx context.Context, groups []string) (set.Set[model.PolicyBinding], error)
	ExecuteUpdates(ctx context.Context)
	ExecuteDeletes(ctx context.Context)
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
	bucketRegionMap       map[string]string

	executor AccessHandlerExecutor
}

func (a *AccessHandler) Initialize(ctx context.Context, configmap *config.ConfigMap, bucketRegionMap map[string]string) error {
	a.executor.Initialize(configmap)

	a.bucketRegionMap = bucketRegionMap

	return nil
}

func (a *AccessHandler) PrepareAccessProviders(ctx context.Context) {
	for name, details := range a.accessProviderDetails {
		a.prepareAccessProvider(ctx, name, details)
	}
}

func (a *AccessHandler) getExistingBindings(ctx context.Context, name string) (set.Set[model.PolicyBinding], error) {
	return a.executor.FetchExistingBindings(ctx, name, a.bucketRegionMap)
}

func (a *AccessHandler) prepareAccessProvider(ctx context.Context, name string, details *AccessProviderDetails) {
	ap := details.ap
	apFeedback := details.apFeedback

	existingBindings, err := a.getExistingBindings(ctx, name)
	if err != nil {
		logFeedbackError(apFeedback, fmt.Sprintf("fetching existing binding for %q: %v", name, err.Error()))

		return
	}

	if existingBindings != nil {
		details.existingBindings = existingBindings
	}

	if ap.Action != sync_to_target.Grant && ap.Action != sync_to_target.Purpose {
		logFeedbackError(apFeedback, fmt.Sprintf("unsupported access provider action: %d", ap.Action))

		return
	}

	a.executor.HookInlinePolicies(ap)

	if ap.Delete {
		if existingBindings != nil {
			details.action = ActionDelete
			a.accessProviderDetails[name] = details
		}

		return
	}

	// Create or update
	details.action = ActionCreate
	if existingBindings != nil {
		details.action = ActionUpdate
	}

	apFeedback.ExternalId = a.executor.ExternalId(name, details)

	// Handling the WHO by converting it to policy bindings
	details.targetBindings = set.NewSet[model.PolicyBinding]()

	for _, user := range ap.Who.Users {
		key := model.PolicyBinding{
			Type:         iam.UserResourceType,
			ResourceName: user,
		}
		details.targetBindings.Add(key)
	}

	apGroupBindings, err := a.executor.HandleGroupBindings(ctx, ap.Who.Groups)
	if err != nil {
		logFeedbackError(apFeedback, fmt.Sprintf("handling group bindings: %s", err.Error()))

		return
	}

	details.targetBindings.AddSet(apGroupBindings)
}

func (a *AccessHandler) HandleDeletes(ctx context.Context) {
	a.executor.ExecuteDeletes(ctx)
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
	existing        map[string]set.Set[model.PolicyBinding]

	configMap *config.ConfigMap
}

func (r *roleAccessHandler) Initialize(configmap *config.ConfigMap) {
	r.configMap = configmap
}

func (r *roleAccessHandler) FetchExistingBindings(ctx context.Context, name string, bucketRegionMap map[string]string) (set.Set[model.PolicyBinding], error) {
	// TODO naive and slow implementation, should be optimized by only fetching this specific role
	err := r.fetchAllExistingBindings(ctx, bucketRegionMap)
	if err != nil {
		return nil, err
	}

	return r.existing[name], nil
}

func (r *roleAccessHandler) fetchAllExistingBindings(ctx context.Context, bucketRegionMap map[string]string) error {
	if r.existing != nil { // already loaded the existing roles
		return nil
	}

	utils.Logger.Info("Fetching all existing roles")

	roleExcludes := slice.ParseCommaSeparatedList(r.configMap.GetString(constants.AwsAccessRoleExcludes))

	roles, err := r.repo.GetRoles(ctx, roleExcludes)
	if err != nil {
		return fmt.Errorf("error fetching existing roles: %w", err)
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

	r.existing = existingRoleAssumptions
	return nil
}

func (r *roleAccessHandler) HookInlinePolicies(ap *sync_to_target.AccessProvider) {
	// No-op
}

func (r *roleAccessHandler) ExternalId(_ string, details *AccessProviderDetails) *string {
	return ptr.String(fmt.Sprintf("%s%s", constants.RoleTypePrefix, details.name))
}
func (r *roleAccessHandler) HandleGroupBindings(ctx context.Context, groups []string) (set.Set[model.PolicyBinding], error) {
	return unpackGroups(ctx, groups, r.getUserGroupMap)
}

func (r *roleAccessHandler) ExecuteDeletes(ctx context.Context) {
	for name, details := range r.accessProviders.Roles {
		utils.Logger.Info(fmt.Sprintf("Processing role %s with action %s", name, details.action))

		if details.action != ActionDelete {
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Removing role %s", name))

		err := r.repo.DeleteRole(ctx, name)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to delete role %q: %s", name, err.Error()))

			continue
		}
	}
}

func (r *roleAccessHandler) ExecuteUpdates(ctx context.Context) {
	for name, details := range r.accessProviders.Roles {
		utils.Logger.Info(fmt.Sprintf("Processing role %s with action %s", name, details.action))

		if details.action != ActionCreate && details.action != ActionUpdate {
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Existing bindings for %s: %s", name, details.existingBindings))
		utils.Logger.Info(fmt.Sprintf("Export bindings for %s: %s", name, details.targetBindings))

		// Getting the who (for roles, this should already contain the list of unpacked users from the groups (as those are not supported for roles)
		userNames := make([]string, 0, len(details.targetBindings))
		for binding := range details.targetBindings {
			userNames = append(userNames, binding.ResourceName)
		}

		sort.Strings(userNames)

		// Getting the what
		ap := details.ap
		statements := createPolicyStatementsFromWhat(ap.What, r.configMap)

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
	existing        map[string]set.Set[model.PolicyBinding]

	inlineUserPoliciesToDelete  map[string][]string
	inlineGroupPoliciesToDelete map[string][]string

	configMap *config.ConfigMap
}

func (p *policyAccessHandler) Initialize(configmap *config.ConfigMap) {
	p.configMap = configmap
}

func (p *policyAccessHandler) FetchExistingBindings(ctx context.Context, name string, bucketRegionMap map[string]string) (set.Set[model.PolicyBinding], error) {
	policy, err := p.repo.GetManagedPolicyByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("fetching policy by name %q: %w", name, err)
	}

	if policy == nil {
		return nil, nil
	}

	bindings := set.Set[model.PolicyBinding]{}

	bindings.Add(removeArn(policy.UserBindings)...)
	bindings.Add(removeArn(policy.GroupBindings)...)
	bindings.Add(removeArn(policy.RoleBindings)...)

	return bindings, nil
}

func (p *policyAccessHandler) fetchAllExistingBindings(ctx context.Context, bucketRegionMap map[string]string) error {
	if p.existing != nil { // already loaded the existing policies
		return nil
	}

	utils.Logger.Info("Fetching existing managed policies")

	managedPolicies, err := p.repo.GetManagedPolicies(ctx)
	if err != nil {
		return fmt.Errorf("error fetching existing managed policies: %w", err)
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

	p.existing = existingPolicyBindings
	return nil
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

func (p *policyAccessHandler) ExternalId(_ string, details *AccessProviderDetails) *string {
	return ptr.String(fmt.Sprintf("%s%s", constants.PolicyTypePrefix, details.name))
}

func (p *policyAccessHandler) HandleGroupBindings(_ context.Context, groups []string) (set.Set[model.PolicyBinding], error) {
	return groupBindings(groups)
}

func (p *policyAccessHandler) ExecuteDeletes(ctx context.Context) {
	managedPolicies := p.getManagedPolicies(p.accessProviders.Policies)

	p.deleteOldPolicies(ctx, p.accessProviders.Policies, managedPolicies)

	// Delete old inline policies on users that are not needed anymore
	p.deleteInlinePolicies(ctx, p.inlineUserPoliciesToDelete, iam.UserResourceType)

	// Delete old inline policies on groups that are not needed anymore
	p.deleteInlinePolicies(ctx, p.inlineGroupPoliciesToDelete, iam.GroupResourceType)
}

func (p *policyAccessHandler) ExecuteUpdates(ctx context.Context) {
	managedPolicies := p.getManagedPolicies(p.accessProviders.Policies)
	skippedPolicies := p.createAndUpdateRaitoPolicies(ctx, p.accessProviders.Policies, managedPolicies)

	p.updatePolicyBindings(ctx, p.accessProviders.Policies, skippedPolicies, managedPolicies)
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
			policyBindingsToAdd[name] = set.NewSet(details.targetBindings.Slice()...)
			policyBindingsToAdd[name].RemoveAll(details.existingBindings.Slice()...)

			policyBindingsToRemove[name] = set.NewSet(details.existingBindings.Slice()...)
			policyBindingsToRemove[name].RemoveAll(details.targetBindings.Slice()...)
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
				utils.Logger.Debug(fmt.Sprintf("Detaching policy %s from role: %s", name, binding.ResourceName))

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

func (p *policyAccessHandler) getManagedPolicies(detailMap map[string]*AccessProviderDetails) set.Set[string] {
	managedPolicies := set.NewSet[string]()

	for name, details := range detailMap {
		if details.ap.WhatLocked != nil && *details.ap.WhatLocked {
			managedPolicies.Add(name)
		}
	}

	return managedPolicies
}

func (p *policyAccessHandler) createAndUpdateRaitoPolicies(ctx context.Context, detailMap map[string]*AccessProviderDetails, managedPolicies set.Set[string]) set.Set[string] {
	skippedPolicies := set.NewSet[string]()

	for name, details := range detailMap {
		action := details.action

		utils.Logger.Info(fmt.Sprintf("Process policy %s, action: %s", name, action))

		statements := createPolicyStatementsFromWhat(details.ap.What, p.configMap)

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

	return skippedPolicies
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

func NewAccessPointHandler(allAccessProviders *AccessProvidersByType, repo dataAccessRepository, getUserGroupMap UserGroupMapFunc, account string) AccessHandler {
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
	defaultRegion   string
	existing        map[string]set.Set[model.PolicyBinding]

	configMap *config.ConfigMap
}

func (a *accessPointHandler) Initialize(configmap *config.ConfigMap) {
	a.configMap = configmap

	a.defaultRegion = strings.Split(configmap.GetStringWithDefault(constants.AwsRegions, "eu-central1"), ",")[0]
}

func (a *accessPointHandler) FetchExistingBindings(ctx context.Context, name string, bucketRegionMap map[string]string) (set.Set[model.PolicyBinding], error) {
	// TODO naive and slow implementation, should be optimized by only fetching this specific access point
	err := a.fetchAllExistingBindings(ctx, bucketRegionMap)
	if err != nil {
		return nil, err
	}

	return a.existing[name], nil
}

func (a *accessPointHandler) fetchAllExistingBindings(ctx context.Context, bucketRegionMap map[string]string) error {
	if a.existing != nil { // already loaded the existing access points
		return nil
	}

	utils.Logger.Info("Fetching existing access points")

	existingPolicyBindings := map[string]set.Set[model.PolicyBinding]{}

	for _, region := range utils.GetRegions(a.configMap) {
		err := a.fetchExistingAccessPointsForRegion(ctx, region, existingPolicyBindings, bucketRegionMap)
		if err != nil {
			return fmt.Errorf("fetching existing access points for region %s: %w", region, err)
		}
	}

	a.existing = existingPolicyBindings
	return nil
}

func (a *accessPointHandler) fetchExistingAccessPointsForRegion(ctx context.Context, region string, existingPolicyBindings map[string]set.Set[model.PolicyBinding], bucketRegionMap map[string]string) error {
	accessPoints, err := a.repo.ListAccessPoints(ctx, region)
	if err != nil {
		return fmt.Errorf("error fetching existing access points: %w", err)
	}

	for ind := range accessPoints {
		accessPoint := accessPoints[ind]

		existingPolicyBindings[accessPoint.Name] = set.Set[model.PolicyBinding]{}

		who, _, _ := iam.CreateWhoAndWhatFromAccessPointPolicy(accessPoint.PolicyParsed, accessPoint.Bucket, accessPoint.Name, a.account, bucketRegionMap, a.configMap)
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

	utils.Logger.Info(fmt.Sprintf("Fetched existing %d access points", len(existingPolicyBindings)))

	return nil
}

func (a *accessPointHandler) HookInlinePolicies(ap *sync_to_target.AccessProvider) {
	// no-op
}

func (a *accessPointHandler) ExternalId(_ string, details *AccessProviderDetails) *string {
	return details.ap.ExternalId // The external ID should contain the permission set ARN. If external id is nil an external ID would be created during creation
}

func (a *accessPointHandler) HandleGroupBindings(ctx context.Context, groups []string) (set.Set[model.PolicyBinding], error) {
	return unpackGroups(ctx, groups, a.getUserGroupMap)
}

func (a *accessPointHandler) ExecuteDeletes(ctx context.Context) {
	for accessPointName, details := range a.accessProviders.AccessPoints {
		if details.action != ActionDelete {
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Processing access point %s with action %s", accessPointName, details.action))

		accessPointAp := details.ap

		utils.Logger.Info(fmt.Sprintf("Removing access point %s", accessPointName))

		if accessPointAp.ExternalId == nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to delete access point %q as no external id is found", accessPointName))
			continue
		}

		// Extract the region from the access point external ID
		extId := *accessPointAp.ExternalId
		extId = extId[len(constants.AccessPointTypePrefix):]

		s3apArn, err := arn.Parse(extId)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to parse external id %q: %s", extId, err.Error()))
			continue
		}

		err = a.repo.DeleteAccessPoint(ctx, s3apArn.Resource[12:], s3apArn.Region)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to delete access point %q: %s", accessPointName, err.Error()))
			continue
		}
	}
}

func (a *accessPointHandler) ExecuteUpdates(ctx context.Context) {
	roleExcludes := slice.ParseCommaSeparatedList(a.configMap.GetString(constants.AwsAccessRoleExcludes))

	for accessPointName, details := range a.accessProviders.AccessPoints {
		if details.action != ActionCreate && details.action != ActionUpdate {
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Processing access point %s with action %s", accessPointName, details.action))

		accessPointAp := details.ap

		utils.Logger.Info(fmt.Sprintf("Existing bindings for %s: %s", accessPointName, details.existingBindings))
		utils.Logger.Info(fmt.Sprintf("Export bindings for %s: %s", accessPointName, details.targetBindings))

		who := set.NewSet(details.targetBindings.Slice()...)

		// Getting the who (for access points, this should already contain the list of unpacked users from the groups (as those are not supported for roles)
		principals := make([]string, 0, len(who))

		for _, binding := range who.Slice() {
			if binding.Type == iam.UserResourceType || binding.Type == iam.RoleResourceType {
				principals = append(principals, utils.GetTrustUserPolicyArn(binding.Type, binding.ResourceName, a.account).String())
			} else if binding.Type == iam.SsoRoleResourceType {
				role, err := a.repo.GetSsoRoleWithPrefix(ctx, binding.ResourceName, roleExcludes)
				if err != nil {
					logFeedbackError(details.apFeedback, fmt.Sprintf("failed to get sso role %q: %s", binding.ResourceName, err.Error()))

					continue
				}

				principals = append(principals, role.ARN)
			}
		}

		sort.Strings(principals)

		// Getting the what
		statements := createPolicyStatementsFromWhat(accessPointAp.What, a.configMap)
		whatItems := make([]sync_to_target.WhatItem, 0, len(accessPointAp.What))
		whatItems = append(whatItems, accessPointAp.What...)

		bucketName, region, err2 := extractBucketForAccessPoint(whatItems)
		if err2 != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to extract bucket name for access point %q: %s", accessPointName, err2.Error()))
			continue
		}

		statements = mergeStatementsOnPermissions(statements)
		filterAccessPointPermissions(statements)

		accessPointArn := fmt.Sprintf("arn:aws:s3:%s:%s:accesspoint/%s", region, a.account, accessPointName)
		convertResourceURLsForAccessPoint(statements, accessPointArn)

		if len(principals) > 0 {
			for _, statement := range statements {
				statement.Principal = map[string][]string{
					"AWS": principals,
				}
			}
		}

		if details.action == ActionCreate {
			utils.Logger.Info(fmt.Sprintf("Creating access point %s", accessPointName))

			// Create the new access point with the who
			s3ApArn, err := a.repo.CreateAccessPoint(ctx, accessPointName, bucketName, region, statements)
			if err != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to create access point %q: %s", accessPointName, err.Error()))
				continue
			}

			externalId := fmt.Sprintf("%s%s", constants.AccessPointTypePrefix, s3ApArn)

			details.ap.ExternalId = &externalId
			details.apFeedback.ExternalId = &externalId
		} else {
			utils.Logger.Info(fmt.Sprintf("Updating access point %s", accessPointName))

			// Handle the who
			err := a.repo.UpdateAccessPoint(ctx, accessPointName, region, statements)
			if err != nil {
				logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update access point %q: %s", accessPointName, err.Error()))
				continue
			}
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
	existing        map[string]set.Set[model.PolicyBinding]

	config *config.ConfigMap
}

func (s *ssoRoleAccessHandler) Initialize(configmap *config.ConfigMap) {
	s.config = configmap
}

func (s *ssoRoleAccessHandler) FetchExistingBindings(ctx context.Context, name string, bucketRegionMap map[string]string) (set.Set[model.PolicyBinding], error) {
	// TODO naive and slow implementation, should be optimized by only fetching this specific permission set
	err := s.fetchAllExistingBindings(ctx, bucketRegionMap)
	if err != nil {
		return nil, err
	}

	return s.existing[name], nil
}

func (s *ssoRoleAccessHandler) fetchAllExistingBindings(ctx context.Context, bucketRegionMap map[string]string) error {
	result := make(map[string]set.Set[model.PolicyBinding])

	permissionSetArns, err := s.ssoAdmin.ListSsoRoles(ctx)
	if err != nil {
		return fmt.Errorf("fetching existing permission sets: %w", err)
	}

	users, err := s.ssoAdmin.GetUsers(ctx)
	if err != nil {
		return fmt.Errorf("get users: %w", err)
	}

	groups, err := s.ssoAdmin.GetGroups(ctx)
	if err != nil {
		return fmt.Errorf("get groups: %w", err)
	}

	for _, arn := range permissionSetArns {
		createdByRaito, err := s.ssoAdmin.HasRaitoCreatedTag(ctx, arn)
		if err != nil {
			return fmt.Errorf("get raito created tag: %w", err)
		}

		if !createdByRaito {
			utils.Logger.Info(fmt.Sprintf("Skipping permission set %q as it was not created by Raito", arn))

			continue
		}

		permissionSetDetails, err := s.ssoAdmin.GetSsoRole(ctx, arn)
		if err != nil {
			return fmt.Errorf("get permission set details: %w", err)
		}

		assignments, err := s.ssoAdmin.ListPermissionSetAssignment(ctx, arn)
		if err != nil {
			return fmt.Errorf("error fetching existing permission set assignments: %w", err)
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

	s.existing = result
	return nil
}

func (s *ssoRoleAccessHandler) HookInlinePolicies(ap *sync_to_target.AccessProvider) {
	// no-op
}

func (s *ssoRoleAccessHandler) ExternalId(_ string, details *AccessProviderDetails) *string {
	return details.ap.ExternalId // The external ID should contain the permission set ARN. If external id is nil an external ID would be created during creation
}

func (s *ssoRoleAccessHandler) HandleGroupBindings(ctx context.Context, groups []string) (set.Set[model.PolicyBinding], error) {
	return groupBindings(groups)
}

func permissionSetArnFromExternalId(externalId *string) (string, bool) {
	if externalId == nil || !strings.HasPrefix(*externalId, constants.SsoRoleTypePrefix) {
		return "", false
	}

	return (*externalId)[len(constants.SsoRoleTypePrefix):], true
}

func (s *ssoRoleAccessHandler) ExecuteDeletes(ctx context.Context) {
	for name, details := range s.accessProviders.PermissionSets {
		if details.action != ActionDelete {
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Processing sso role %s with action %s", name, details.action))

		s.deletePermissionSet(ctx, name, permissionSetArnFromExternalId, details)
	}
}

func (s *ssoRoleAccessHandler) ExecuteUpdates(ctx context.Context) {
	created := 0

	for name, details := range s.accessProviders.PermissionSets {
		if details.action != ActionCreate && details.action != ActionUpdate {
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Processing sso role %s with action %s", name, details.action))

		utils.Logger.Info(fmt.Sprintf("Existing bindings for %s: %s", name, details.existingBindings))
		utils.Logger.Info(fmt.Sprintf("Export bindings for %s: %s", name, details.targetBindings))

		permissionSetArn, newPermissionSet, err := s.updateOrCreatePermissionSet(ctx, details, permissionSetArnFromExternalId)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update or create permission set %q: %s", name, err.Error()))

			continue
		}

		if newPermissionSet {
			created += 1
		}

		// Update who
		s.updateWho(ctx, details, permissionSetArn, name)

		// Update What
		s.updateWhat(ctx, details, name, permissionSetArn)

		_, err = s.ssoAdmin.ProvisionPermissionSet(ctx, permissionSetArn)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to provision permission set %q: %s", name, err.Error()))
		}
	}

	if created > 0 {
		utils.Logger.Info("Clear cache")
		s.repo.ClearCache()
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
	statements := createPolicyStatementsFromWhat(details.ap.What, s.config) // this should be empty as it is purpose

	err := s.ssoAdmin.UpdateInlinePolicyToPermissionSet(ctx, permissionSetArn, statements)
	if err != nil {
		logFeedbackError(details.apFeedback, fmt.Sprintf("failed to update inline policy for permission set %q: %s", name, err.Error()))
	}
}

func (s *ssoRoleAccessHandler) updateWho(ctx context.Context, details *AccessProviderDetails, permissionSetArn string, name string) {
	bindingsToRemove := utils.SetSubtract(details.existingBindings, details.targetBindings)

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

	for binding := range bindingsToRemove {
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

	bindingsToAdd := utils.SetSubtract(details.targetBindings, details.existingBindings)

	for binding := range bindingsToAdd {
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

		err = s.ssoAdmin.AssignPermissionSet(ctx, permissionSetArn, principalType, principalId)
		if err != nil {
			logFeedbackError(details.apFeedback, fmt.Sprintf("failed to add %s %q from permission set %q: %s", principalType, binding.ResourceName, name, err.Error()))
		}
	}
}

func (s *ssoRoleAccessHandler) updateOrCreatePermissionSet(ctx context.Context, details *AccessProviderDetails, permissionSetArnFn func(externalId *string) (string, bool)) (string, bool, error) {
	permissionSetArn, _ := permissionSetArnFn(details.ap.ExternalId)

	shouldBeCreated := details.action == ActionCreate

	if details.action == ActionUpdate {
		originalPermissionSet, err := s.ssoAdmin.GetSsoRole(ctx, permissionSetArn)
		if err != nil {
			return permissionSetArn, shouldBeCreated, fmt.Errorf("get sso role: %w", err)
		}

		if originalPermissionSet.Name == nil || *originalPermissionSet.Name != details.name {
			shouldBeCreated = true

			err = s.ssoAdmin.DeleteSsoRole(ctx, permissionSetArn)
			if err != nil {
				return permissionSetArn, shouldBeCreated, fmt.Errorf("delete sso role: %w", err)
			}

			permissionSetArn = ""
		} else {
			// Update the permission set name
			err = s.ssoAdmin.UpdateSsoRole(ctx, permissionSetArn, details.ap.Description)
			if err != nil {
				return permissionSetArn, shouldBeCreated, fmt.Errorf("update sso role: %w", err)
			}
		}
	}

	if shouldBeCreated {
		var err error

		permissionSetArn, err = s.ssoAdmin.CreateSsoRole(ctx, details.name, details.ap.Description)
		if err != nil {
			return permissionSetArn, shouldBeCreated, fmt.Errorf("create sso role: %w", err)
		}

		if permissionSetArn == "" {
			return "", shouldBeCreated, errors.New("create sso role: empty permission set arn")
		}

		details.apFeedback.ExternalId = ptr.String(fmt.Sprintf("%s%s", constants.SsoRoleTypePrefix, permissionSetArn))
	}

	return permissionSetArn, shouldBeCreated, nil
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
*/
