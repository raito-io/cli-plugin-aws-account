package aws

import (
	"fmt"
	"strconv"
	"strings"

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

func CreateWhatFromPolicyDocument(policyName string, policy *awspolicy.Policy, configMap *config.ConfigMap) ([]sync_from_target.WhatItem, bool, error) {
	awsAccount := strconv.Itoa(configMap.GetInt(AwsAccountId))

	if policy == nil {
		logger.Warn(fmt.Sprintf("Policy document for %s is empty", policyName))
		return nil, true, nil
	}

	incomplete := false

	policyStatements := policy.Statements
	var whatItems []sync_from_target.WhatItem

	for ind := range policyStatements {
		statement := policyStatements[ind]

		effect := statement.Effect
		if strings.EqualFold(effect, "deny") {
			logger.Warn(fmt.Sprintf("Policy document for %s has deny statement. Ignoring", policyName))
			continue
		}

		actions := statement.Action
		resources := statement.Resource

		// so trying to import every object as all the data object types.
		// see how this can be improved

		for _, resource := range resources {
			incompleteResource := false

			if strings.HasPrefix(resource, "arn:aws:s3:") {
				fullName := removeEndingWildcards(convertArnToFullname(resource))

				isBucket := !strings.Contains(fullName, "/")
				var resourceActions []string

				if isBucket {
					resourceActions, incompleteResource = mapResourceActions(actions, data_source.Bucket)
				} else {
					resourceActions, incompleteResource = mapResourceActions(actions, data_source.Folder)
				}

				whatItems = append(whatItems, sync_from_target.WhatItem{
					DataObject: &data_source.DataObjectReference{
						// We don't specify the type as we are not sure about it, but the fullName should be sufficient
						FullName: fullName,
					},
					Permissions: resourceActions,
				})
			} else if resource == "*" {
				var resourceActions []string

				resourceActions, incompleteResource = mapResourceActions(actions, data_source.Datasource)

				whatItems = append(whatItems, sync_from_target.WhatItem{
					DataObject: &data_source.DataObjectReference{
						FullName: awsAccount,
						Type:     data_source.Datasource,
					},
					Permissions: resourceActions,
				})
			}

			if !incomplete && incompleteResource {
				incomplete = true
			}
		}
	}

	return whatItems, incomplete, nil
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

	logger.Debug(fmt.Sprintf("Mapping actions %+v for resource type %q to (incomplete %t): %+v", actions, resourceType, incomplete, mappedActions))

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
