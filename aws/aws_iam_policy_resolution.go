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
		if strings.EqualFold(effect, "deny") {
			logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q has deny statement. Ignoring", role))
			incomplete = true

			continue
		}

		if len(statement.NotResource) > 0 || len(statement.NotPrincipal) > 0 || len(statement.NotAction) > 0 {
			logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains not-statements. Ignoring", role))
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
								logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains not-statements. Ignoring", role))
								incomplete = true

								continue
							}

							parts := strings.Split(resource, "/")

							if len(parts) == 2 {
								if parts[1] == "*" {
									logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains wildcard IAM resource %q. Ignoring", role, resource))
									incomplete = true
								} else if strings.EqualFold(parts[0], "user") {
									users.Add(parts[1])
								} else if strings.EqualFold(parts[0], "group") {
									groups.Add(parts[1])
								} else {
									logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains unknown IAM resource %q. Ignoring", role, resource))
									incomplete = true
								}
							} else {
								logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains unknown IAM resource %q. Ignoring", role, resource))
								incomplete = true
							}
						}
					} else {
						logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy document for role %q contains unrecognized principal type %q. Ignoring", principalType, role))
						incomplete = true

						continue
					}
				}

				break
			} else {
				logger.Warn(fmt.Sprintf("UNSUPPORTED: Trust Policy action %q for role %q not recognized. Ignoring", action, role))
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
		if strings.EqualFold(effect, "deny") {
			logger.Warn(fmt.Sprintf("Policy document for %q has deny statement. Ignoring", policyName))
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

			if strings.HasPrefix(resource, "arn:aws:s3:") {
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
			}

			permissionSet := whatMap[fullName]
			if permissionSet == nil {
				permissionSet = set.NewSet[string]()
				whatMap[fullName] = permissionSet
			}

			permissionSet.Add(resourceActions...)

			if !incomplete && incompleteResource {
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

func getApNames(exportedAps []*importer.AccessProvider, aps ...string) []string {
	result := []string{}

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
		for _, ap := range exportedAps {
			if ap != nil && ap.Id == apID {
				result = append(result, ap.Name)
			}
		}
	}

	return result
}

func processApInheritance(inheritanceMap map[string]set.Set[string], policyMap map[string]string, roleMap map[string]string,
	newBindings *map[string]set.Set[PolicyBinding], existingBindings map[string]set.Set[PolicyBinding]) error { //nolint: gocritic // pointer needs to be used for newBindings, otherwise it doesn't work
	for k := range inheritanceMap {
		descendants := set.Set[string]{}
		getAllDescendant(inheritanceMap, k, &descendants)
		logger.Info(fmt.Sprintf("Descendents for %s: %s", k, descendants.Slice()))

		currentType := getApType(k, policyMap, roleMap)

		for _, descendent := range descendants.Slice() {
			descendentType := getApType(descendent, policyMap, roleMap)

			if (currentType == TypePolicy && descendentType == TypePolicy) || (currentType == TypeRole && descendentType == TypeRole) {
				(*newBindings)[k].AddSet((*newBindings)[descendent])
				(*newBindings)[k].AddSet(existingBindings[descendent])
			} else if currentType == TypeRole && descendentType == TypePolicy {
				logger.Warn(fmt.Sprintf("AP %s of type %s should not have an descendant of type %s (%s)", k, currentType, descendentType, descendent))
			} else if currentType == TypePolicy && descendentType == TypeRole {
				roleBinding := PolicyBinding{
					Type:         TypeRole,
					ResourceName: descendent,
				}
				(*newBindings)[k].Add(roleBinding)
			}
		}
	}

	return nil
}

func getApType(apName string, policyMap map[string]string, roleMap map[string]string) string {
	if _, found := policyMap[apName]; found {
		return TypePolicy
	} else if _, f := roleMap[apName]; f {
		return TypeRole
	}

	return "none"
}

func getAllDescendant(childMap map[string]set.Set[string], apName string, descendantList *set.Set[string]) {
	if v, found := childMap[apName]; !found || len(v) == 0 {
		return
	}

	for _, child := range childMap[apName].Slice() {
		descendantList.Add(child)
		getAllDescendant(childMap, child, descendantList)
	}
}
