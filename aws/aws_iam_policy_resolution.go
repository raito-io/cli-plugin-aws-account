package aws

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/smithy-go/ptr"

	"github.com/raito-io/cli/base/util/config"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	importer "github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/golang-set/set"
)

const (
	TypePolicy string = "policy"
	TypeRole   string = "role"
)

func createWhoFromTrustPolicyDocument(policy *awspolicy.Policy, role string, configMap *config.ConfigMap) (*sync_from_target.WhoItem, bool) {
	if policy == nil {
		return nil, false
	}

	awsAccount := strconv.Itoa(configMap.GetInt(AwsAccountId))
	incomplete := false
	policyStatements := policy.Statements
	whoItem := sync_from_target.WhoItem{}

	users := set.NewSet[string]()
	groups := set.NewSet[string]()

	for ind := range policyStatements {
		statement := policyStatements[ind]

		effect := statement.Effect
		if !strings.EqualFold(effect, "allow") {
			logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q has unknown effect statement %q.", role, effect))
			incomplete = true

			continue
		}

		if len(statement.NotResource) > 0 || len(statement.NotPrincipal) > 0 || len(statement.NotAction) > 0 {
			logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains not-statements.", role))
			incomplete = true

			continue
		}

		actions := statement.Action
		for _, action := range actions {
			if strings.EqualFold(action, "sts:AssumeRole") {
				for principalType, principals := range statement.Principal {
					if principalType == "AWS" {
						for _, principal := range principals {
							resource, err := parseAndValidateArn(principal, &awsAccount, ptr.String("iam"))
							if err != nil {
								logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains not-statements.", role))
								incomplete = true

								continue
							}

							parts := strings.Split(resource, "/")

							if len(parts) == 2 {
								if parts[1] == "*" {
									logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains wildcard IAM resource %q.", role, resource))
									incomplete = true
								} else if strings.EqualFold(parts[0], "user") {
									users.Add(parts[1])
								} else if strings.EqualFold(parts[0], "group") {
									groups.Add(parts[1])
								} else {
									logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains unknown IAM resource %q.", role, resource))
									incomplete = true
								}
							} else {
								logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains unknown IAM resource %q.", role, resource))
								incomplete = true
							}
						}
					} else {
						logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains unrecognized principal type %q.", role, principalType))
						incomplete = true

						continue
					}
				}

				break
			} else {
				logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy action %q for role %q not recognized.", action, role))
				incomplete = true
			}
		}
	}

	whoItem.Users = users.Slice()
	whoItem.Groups = groups.Slice()

	return &whoItem, incomplete
}

func createWhatFromPolicyDocument(policy *awspolicy.Policy, policyName string, configMap *config.ConfigMap) ([]sync_from_target.WhatItem, bool) {
	if policy == nil {
		return nil, false
	}

	awsAccount := strconv.Itoa(configMap.GetInt(AwsAccountId))
	incomplete := false
	policyStatements := policy.Statements
	whatMap := make(map[string]set.Set[string])

	for ind := range policyStatements {
		statement := policyStatements[ind]

		effect := statement.Effect

		if !strings.EqualFold(effect, "allow") {
			logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q has unknown effect statement %q.", policyName, effect))
			incomplete = true

			continue
		}

		if len(statement.NotResource) > 0 || len(statement.NotPrincipal) > 0 || len(statement.NotAction) > 0 {
			logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q contains not-statements.", policyName))
			incomplete = true

			continue
		}

		actions := statement.Action
		resources := statement.Resource

		// so trying to import every object as all the data object types.
		// see how this can be improved

		for _, resource := range resources {
			incompleteResource := false

			var resourceActions []string
			var fullName string

			_, err := parseAndValidateArn(resource, nil, ptr.String("s3"))

			if err == nil {
				fullName = removeEndingWildcards(convertArnToFullname(resource))

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
				logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q contains unknown resource reference %q.", policyName, resource))
				incomplete = true
				continue
			}

			permissionSet := whatMap[fullName]
			if permissionSet == nil {
				permissionSet = set.NewSet[string]()
				whatMap[fullName] = permissionSet
			}

			permissionSet.Add(resourceActions...)

			if !incomplete && incompleteResource {
				logger.Warn(fmt.Sprintf("UNSUPPORTED: Policy document for %q contains unknown actions (%v).", policyName, actions))
				incomplete = true
			}
		}
	}

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

	return whatItems, incomplete
}

// mapResourceActions maps the permissions given to the ones we know for the given resource type.
// It returns the mapped actions, together with a boolean indicating whether any actions were skipped (true) or not (false).
func mapResourceActions(actions []string, resourceType string) ([]string, bool) {
	mappedActions := make([]string, 0, len(actions))

	dot := GetDataObjectType(resourceType)
	dotPermissions := dot.GetPermissions()
	incomplete := false

	for _, action := range actions {
		for _, permission := range dotPermissions {
			perm := permission.Permission

			if action == perm {
				// Exact match with a permission from the data object type
				mappedActions = append(mappedActions, perm)
			} else if action == "*" {
				// For wildcard actions, just add all permission from the data object type. Mark as incomplete as go from wildcard to explicit permissions
				incomplete = true
				mappedActions = append(mappedActions, perm)
			} else if strings.HasSuffix(action, "*") {
				// Action ending in a wildcard, so only add the permissions that have the right prefix + mark incomplete
				incomplete = true
				if strings.HasPrefix(perm, action[:len(action)-1]) {
					mappedActions = append(mappedActions, perm)
				}
			} else {
				// Unknown permission, so we ignore and mark as incomplete
				incomplete = true
			}
		}
	}

	return mappedActions, incomplete
}

func resolveInheritedApNames(exportedAps []*importer.AccessProvider, aps ...string) []string {
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
				apName, _ := generateName(ap2)
				result = append(result, apName)
			}
		}
	}

	return result
}

func getExistingOrNewBindings(existingBindings map[string]set.Set[PolicyBinding], newBindings map[string]set.Set[PolicyBinding], name string) set.Set[PolicyBinding] {
	if b, f := newBindings[name]; f {
		return b
	}

	return existingBindings[name]
}

func processApInheritance(roleInheritanceMap map[string]set.Set[string], policyInheritanceMap map[string]set.Set[string],
	newRoleWhoBindings map[string]set.Set[PolicyBinding], newPolicyWhoBindings map[string]set.Set[PolicyBinding],
	existingRoleWhoBindings map[string]set.Set[PolicyBinding], existingPolicyWhoBindings map[string]set.Set[PolicyBinding]) error {
	for k := range roleInheritanceMap {
		// A role can only have other roles as descendants
		descendants := getDescendants(roleInheritanceMap, k)
		logger.Info(fmt.Sprintf("Descendants for role %s: %s", k, descendants.Slice()))

		for _, descendant := range descendants.Slice() {
			newRoleWhoBindings[k].AddSet(getExistingOrNewBindings(existingRoleWhoBindings, newRoleWhoBindings, descendant))
		}
	}

	for k := range policyInheritanceMap {
		policyDescendants := getDescendants(policyInheritanceMap, k)
		roleDescendants := set.NewSet[string]()

		for _, descendant := range policyDescendants.Slice() {
			_, isNewRole := newRoleWhoBindings[descendant]
			_, isExistingRole := existingRoleWhoBindings[descendant]

			if isNewRole || isExistingRole {
				roleDescendants.Add(descendant)
				roleDescendants.AddSet(getDescendants(roleInheritanceMap, descendant))
			}
		}

		logger.Info(fmt.Sprintf("Role descendants for policy %s: %s", k, roleDescendants.Slice()))

		// For descendants that are roles, we need to add that role as a binding for this policy
		for _, descendant := range roleDescendants.Slice() {
			roleBinding := PolicyBinding{
				Type:         TypeRole,
				ResourceName: descendant,
			}
			newPolicyWhoBindings[k].Add(roleBinding)
		}
	}

	for k := range policyInheritanceMap {
		policyDescendants := getDescendants(policyInheritanceMap, k)
		logger.Info(fmt.Sprintf("Policy descendants for policy %s: %s", k, policyDescendants.Slice()))

		// For descendants that are policies,
		for _, descendant := range policyDescendants.Slice() {
			newPolicyWhoBindings[k].AddSet(getExistingOrNewBindings(existingPolicyWhoBindings, newPolicyWhoBindings, descendant))
		}
	}

	return nil
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
