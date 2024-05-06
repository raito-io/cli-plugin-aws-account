package iam

import (
	"fmt"
	"strings"

	"github.com/aws/smithy-go/ptr"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	data_source2 "github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	"github.com/raito-io/cli/base/util/config"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	importer "github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/golang-set/set"
)

func CreateWhoAndWhatFromAccessPointPolicy(policy *awspolicy.Policy, bucketName string, name string, configMap *config.ConfigMap) (*sync_from_target.WhoItem, []sync_from_target.WhatItem, bool) {
	if policy == nil {
		return nil, nil, false
	}

	awsAccount := configMap.GetString(constants.AwsAccountId)
	whoItem := &sync_from_target.WhoItem{}
	whatMap := make(map[string]set.Set[string])

	users := set.NewSet[string]()
	groups := set.NewSet[string]()
	roles := set.NewSet[string]()

	if len(policy.Statements) > 1 {
		utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for access point %q contains more than 1 statement.", name))
		return whoItem, []sync_from_target.WhatItem{}, true
	}

	incomplete := handleStatements(policy, name, func(statement awspolicy.Statement) bool {
		localIncomplete := false

		principalIncomplete := handlePrincipal(statement.Principal, awsAccount, fmt.Sprintf("Policy document for access point %q", name), users, groups, roles)
		if principalIncomplete {
			localIncomplete = true
		}

		actions := statement.Action
		resources := statement.Resource

		for _, resource := range resources {
			incompleteResource := false

			var resourceActions []string
			var fullName string

			path, err := utils.ParseAndValidateArn(strings.TrimSpace(resource), nil, ptr.String("s3"))

			if err == nil {
				prefix := "accesspoint/" + name
				if strings.HasPrefix(path, prefix) {
					path = strings.TrimPrefix(path, prefix)

					if path == "" || path == "/" {
						fullName = bucketName
						resourceActions, incompleteResource = mapResourceActions(actions, data_source.Bucket)
					} else if strings.HasPrefix(path, "/object/") {
						path = utils.RemoveEndingWildcards(strings.TrimPrefix(path, "/object/"))
						if path == "" {
							fullName = bucketName
						} else {
							fullName = bucketName + "/" + path
						}

						resourceActions, incompleteResource = mapResourceActions(actions, data_source.Folder)
					} else {
						utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for access point %q contains unknown resource reference %q. Unexpected access point path", name, resource))
						localIncomplete = true

						continue
					}

					permissionSet := whatMap[fullName]
					if permissionSet == nil {
						permissionSet = set.NewSet[string]()
						whatMap[fullName] = permissionSet
					}

					permissionSet.Add(resourceActions...)

					if !localIncomplete && incompleteResource {
						utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for access point %q contains unknown actions (%v).", name, actions))
						localIncomplete = true
					}
				} else {
					utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for access point %q contains unknown resource reference %q. Expected the path to start with %q", name, resource, prefix))
					localIncomplete = true

					continue
				}
			} else {
				utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for access point %q contains unknown resource reference %q.", name, resource))
				localIncomplete = true

				continue
			}
		}

		return localIncomplete
	})

	whoItem.Users = users.Slice()
	whoItem.Groups = groups.Slice()
	whoItem.AccessProviders = roles.Slice()

	return whoItem, flattenWhatMap(whatMap, awsAccount), incomplete
}

func CreateWhoFromTrustPolicyDocument(policy *awspolicy.Policy, role string, configMap *config.ConfigMap) (*sync_from_target.WhoItem, bool) {
	if policy == nil {
		return nil, false
	}

	awsAccount := configMap.GetString(constants.AwsAccountId)
	whoItem := sync_from_target.WhoItem{}

	users := set.NewSet[string]()
	groups := set.NewSet[string]()

	incomplete := handleStatements(policy, role, func(statement awspolicy.Statement) bool {
		localIncomplete := false
		actions := statement.Action

		for _, action := range actions {
			if strings.EqualFold(action, "sts:AssumeRole") {
				principalIncomplete := handlePrincipal(statement.Principal, awsAccount, fmt.Sprintf("Trusted Policy document for role %q", role), users, groups, nil)
				if principalIncomplete {
					localIncomplete = true
				}

				break
			} else {
				utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy action %q for role %q not recognized.", action, role))
				localIncomplete = true
			}
		}

		return localIncomplete
	})

	whoItem.Users = users.Slice()
	whoItem.Groups = groups.Slice()

	return &whoItem, incomplete
}

func handlePrincipal(p map[string][]string, awsAccount, errorPrefix string, users, groups, roles set.Set[string]) bool {
	localIncomplete := false

	for principalType, principals := range p {
		if principalType == "AWS" {
			for _, principal := range principals {
				if strings.Contains(principal, "*") {
					utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: %s contains wildcards in principal", errorPrefix))
					localIncomplete = true

					continue
				}

				resource, err := utils.ParseAndValidateArn(principal, &awsAccount, ptr.String("iam"))
				if err != nil {
					utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: %s contains invalid arn: %s", errorPrefix, err.Error()))
					localIncomplete = true

					continue
				}

				parts := strings.Split(resource, "/")

				if len(parts) >= 2 {
					if parts[1] == "*" {
						utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: %s contains wildcard IAM resource %q.", errorPrefix, resource))
						localIncomplete = true
					} else if strings.EqualFold(parts[0], "user") {
						users.Add(parts[len(parts)-1])
					} else if strings.EqualFold(parts[0], "group") {
						groups.Add(parts[len(parts)-1])
					} else if strings.EqualFold(parts[0], "role") && roles != nil {
						roles.Add(constants.RoleTypePrefix + parts[len(parts)-1])
					} else {
						utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: %s contains unknown IAM resource %q.", errorPrefix, resource))
						localIncomplete = true
					}
				} else {
					utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: %s contains unknown IAM resource %q.", errorPrefix, resource))
					localIncomplete = true
				}
			}
		} else {
			utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: %s contains unrecognized principal type %q.", errorPrefix, principalType))
			localIncomplete = true

			continue
		}
	}

	return localIncomplete
}

func handleStatements(policy *awspolicy.Policy, name string, handler func(statement awspolicy.Statement) bool) bool {
	policyStatements := policy.Statements
	incomplete := false

	for ind := range policyStatements {
		statement := policyStatements[ind]

		effect := statement.Effect

		if !strings.EqualFold(effect, "allow") {
			utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q has unknown effect statement %q.", name, effect))
			incomplete = true

			continue
		}

		if len(statement.NotResource) > 0 || len(statement.NotPrincipal) > 0 || len(statement.NotAction) > 0 {
			utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q contains not-statements.", name))
			incomplete = true

			continue
		}

		if len(statement.Condition) > 0 {
			utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q contains conditions.", name))
			incomplete = true

			continue
		}

		if handler(statement) {
			incomplete = true
		}
	}

	return incomplete
}

func CreateWhatFromPolicyDocument(policy *awspolicy.Policy, policyName string, configMap *config.ConfigMap) ([]sync_from_target.WhatItem, bool) {
	if policy == nil {
		return nil, false
	}

	awsAccount := configMap.GetString(constants.AwsAccountId)
	whatMap := make(map[string]set.Set[string])

	incomplete := handleStatements(policy, policyName, func(statement awspolicy.Statement) bool {
		localIncomplete := false
		actions := statement.Action
		resources := statement.Resource

		// so trying to import every object as all the data object types.
		// see how this can be improved

		for _, resource := range resources {
			incompleteResource := false

			var resourceActions []string
			var fullName string

			_, err := utils.ParseAndValidateArn(resource, nil, ptr.String("s3"))

			if err == nil {
				fullName = utils.RemoveEndingWildcards(utils.ConvertArnToFullname(resource))

				isBucket := !strings.Contains(fullName, "/")

				if isBucket {
					resourceActions, incompleteResource = mapResourceActions(actions, data_source.Bucket)
				} else {
					resourceActions, incompleteResource = mapResourceActions(actions, data_source.Folder)
				}
			} else if resource == "*" {
				fullName = awsAccount
				resourceActions, incompleteResource = mapResourceActions(actions, data_source.Datasource)
			} else {
				utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q contains unknown resource reference %q.", policyName, resource))
				localIncomplete = true

				continue
			}

			permissionSet := whatMap[fullName]
			if permissionSet == nil {
				permissionSet = set.NewSet[string]()
				whatMap[fullName] = permissionSet
			}

			permissionSet.Add(resourceActions...)

			if !localIncomplete && incompleteResource {
				utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q contains unknown actions (%v).", policyName, actions))
				localIncomplete = true
			}
		}

		return localIncomplete
	})

	return flattenWhatMap(whatMap, awsAccount), incomplete
}

func flattenWhatMap(whatMap map[string]set.Set[string], awsAccount string) []sync_from_target.WhatItem {
	whatItems := make([]sync_from_target.WhatItem, 0, len(whatMap))

	for fullName, permissionSet := range whatMap {
		// We don't specify the type as we are not sure about it, but the fullName should be sufficient
		doType := ""

		if fullName == awsAccount {
			doType = data_source.Datasource
		}

		whatItems = append(whatItems, sync_from_target.WhatItem{
			DataObject: &data_source.DataObjectReference{
				FullName: fullName,
				Type:     doType,
			},
			Permissions: permissionSet.Slice(),
		})
	}

	return whatItems
}

// mapResourceActions maps the permissions given to the ones we know for the given resource type.
// It returns the mapped actions, together with a boolean indicating whether any actions were skipped (true) or not (false).
func mapResourceActions(actions []string, resourceType string) ([]string, bool) {
	mappedActions := make([]string, 0, len(actions))

	dot := data_source2.GetDataObjectType(resourceType)
	dotPermissions := dot.GetPermissions()
	incomplete := false

	for _, action := range actions {
		found := false

		for _, permission := range dotPermissions {
			perm := permission.Permission

			if action == perm {
				// Exact match with a permission from the data object type
				mappedActions = append(mappedActions, perm)
				found = true
			} else if action == "*" {
				// For wildcard actions, just add all permission from the data object type. We don't consider it found as we may not have all.
				mappedActions = append(mappedActions, perm)
			} else if strings.HasSuffix(action, "*") {
				// Action ending in a wildcard, so only add the permissions that have the right prefix. We don't consider it found as we may not have all.
				if strings.HasPrefix(perm, action[:len(action)-1]) {
					mappedActions = append(mappedActions, perm)
				}
			}
		}

		// If we didn't find the action in the permissions list, we mark this resource as incomplete
		if !found {
			incomplete = true
		}
	}

	return mappedActions, incomplete
}

func ResolveInheritedApNames(apTypeResolver func(*importer.AccessProvider) (model.AccessProviderType, error), exportedAps []*importer.AccessProvider, aps ...string) ([]string, error) {
	result := make([]string, 0, len(aps))

	for _, ap := range aps {
		if !strings.HasPrefix(ap, "ID:") {
			result = append(result, ap)
			continue
		}

		parts := strings.Split(ap, "ID:")
		if len(parts) != 2 {
			continue
		}

		apID := parts[1]
		for _, ap2 := range exportedAps {
			if ap2 != nil && ap2.Id == apID {
				ap2Type, err := apTypeResolver(ap2)
				if err != nil {
					return nil, err
				}

				apName, _ := utils.GenerateName(ap2, ap2Type)
				result = append(result, apName)
			}
		}
	}

	return result, nil
}

func getExistingOrNewBindings(existingBindings map[string]set.Set[model.PolicyBinding], newBindings map[string]set.Set[model.PolicyBinding], name string) set.Set[model.PolicyBinding] {
	if b, f := newBindings[name]; f {
		return b
	}

	return existingBindings[name]
}

// processRoleInheritance flattens the role bindings for roles because no role inheritance is supported in AWS
func processRoleInheritance(roleInheritanceMap map[string]set.Set[string], newRoleWhoBindings map[string]set.Set[model.PolicyBinding], existingRoleWhoBindings map[string]set.Set[model.PolicyBinding]) {
	// Run over the role inheritance map and for each role add the inherited who from the dependant roles
	for k := range roleInheritanceMap {
		// A role can only have other roles as descendants
		descendants := getDescendants(roleInheritanceMap, k)
		for _, descendant := range descendants.Slice() {
			newRoleWhoBindings[k].AddSet(getExistingOrNewBindings(existingRoleWhoBindings, newRoleWhoBindings, descendant))
		}
	}
}

// processPolicyInheritance flattens the policy bindings for policies and access points because no policy inheritance is supported in AWS
// Note that the same logic is used for policies and access points because they are both represented as policies in AWS and we use the same inheritance logic for them.
func processPolicyInheritance(roleInheritanceMap map[string]set.Set[string], policyInheritanceMap map[string]set.Set[string],
	newRoleWhoBindings map[string]set.Set[model.PolicyBinding], newPolicyWhoBindings map[string]set.Set[model.PolicyBinding],
	existingRoleWhoBindings map[string]set.Set[model.PolicyBinding], existingPolicyWhoBindings map[string]set.Set[model.PolicyBinding]) {
	for k := range policyInheritanceMap {
		// We fetch the dependant policies for the current policy
		policyDescendants := getDescendants(policyInheritanceMap, k)
		roleDescendants := set.NewSet[string]()

		for _, descendant := range policyDescendants.Slice() {
			_, isNewRole := newRoleWhoBindings[descendant]
			_, isExistingRole := existingRoleWhoBindings[descendant]

			if isNewRole || isExistingRole {
				// If the dependency is a role, we register it as a role descendant
				roleDescendants.Add(descendant)
				roleDescendants.AddSet(getDescendants(roleInheritanceMap, descendant))
			} else if _, f := newPolicyWhoBindings[descendant]; !f {
				// In this case the descendant is not an internal access provider. Let's see if it is an external one to get those dependencies
				if policyWho, f2 := existingPolicyWhoBindings[descendant]; f2 {
					// The case where the internal AP depends on an external AP (of type policy). In that case we have to look at the bindings to see if there are roles in there.
					for _, binding := range policyWho.Slice() {
						if binding.Type == RoleResourceType {
							_, isNewRole2 := newRoleWhoBindings[binding.ResourceName]
							_, isExistingRole2 := existingRoleWhoBindings[binding.ResourceName]

							if isNewRole2 || isExistingRole2 {
								roleDescendants.Add(binding.ResourceName)
								roleDescendants.AddSet(getDescendants(roleInheritanceMap, binding.ResourceName))
							}
						}
					}
				}
			}
		}

		// For descendants that are roles, we need to add that role as a binding for this policy
		for _, descendant := range roleDescendants.Slice() {
			roleBinding := model.PolicyBinding{
				Type:         RoleResourceType,
				ResourceName: descendant,
			}
			newPolicyWhoBindings[k].Add(roleBinding)
		}
	}

	for k := range policyInheritanceMap {
		policyDescendants := getDescendants(policyInheritanceMap, k)

		// For descendants that are policies,
		for _, descendant := range policyDescendants.Slice() {
			newPolicyWhoBindings[k].AddSet(getExistingOrNewBindings(existingPolicyWhoBindings, newPolicyWhoBindings, descendant))
		}
	}
}

func ProcessApInheritance(roleInheritanceMap map[string]set.Set[string], policyInheritanceMap map[string]set.Set[string], accessPointInheritanceMap map[string]set.Set[string],
	newRoleWhoBindings map[string]set.Set[model.PolicyBinding], newPolicyWhoBindings map[string]set.Set[model.PolicyBinding], newAccessPointWhoBindings map[string]set.Set[model.PolicyBinding],
	existingRoleWhoBindings map[string]set.Set[model.PolicyBinding], existingPolicyWhoBindings map[string]set.Set[model.PolicyBinding], existingAccessPointWhoBindings map[string]set.Set[model.PolicyBinding]) {
	// Handle inheritance for roles
	processRoleInheritance(roleInheritanceMap, newRoleWhoBindings, existingRoleWhoBindings)

	// Handle inheritance for policies
	processPolicyInheritance(roleInheritanceMap, policyInheritanceMap, newRoleWhoBindings, newPolicyWhoBindings, existingRoleWhoBindings, existingPolicyWhoBindings)

	// Handle inheritance for access points
	processPolicyInheritance(roleInheritanceMap, accessPointInheritanceMap, newRoleWhoBindings, newAccessPointWhoBindings, existingRoleWhoBindings, existingAccessPointWhoBindings)
}

func getDescendants(childMap map[string]set.Set[string], apName string) set.Set[string] {
	descendants := set.NewSet[string]()

	if v, found := childMap[apName]; !found || len(v) == 0 {
		return descendants
	}

	for _, child := range childMap[apName].Slice() {
		descendants.Add(child)
		descendants.AddSet(getDescendants(childMap, child))
	}

	return descendants
}
