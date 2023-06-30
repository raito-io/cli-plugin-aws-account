package aws

import (
	"fmt"
	"strings"

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

func CreateWhatFromPolicyDocument(policyName string, policy *awspolicy.Policy) ([]sync_from_target.WhatItem, error) {
	if policy == nil {
		logger.Warn(fmt.Sprintf("Policy document for %s is empty", policyName))
		return nil, nil
	}

	policyStatements := policy.Statements
	var whatItems []sync_from_target.WhatItem

	for ind := range policyStatements {
		statement := policyStatements[ind]

		effect := statement.Effect
		if strings.EqualFold(effect, "deny") {
			continue
		}

		actions := statement.Action
		resources := statement.Resource

		// TODO: decide how we deal with wildcards in resource names
		// TODO: hard to check the data object type during AP sync.
		// so trying to import every object as all the data object types.
		// see how this can be improved
		for _, resource := range resources {
			whatItems = append(whatItems, sync_from_target.WhatItem{
				DataObject: &data_source.DataObjectReference{
					FullName: convertArnToFullname(resource),
					Type:     data_source.File,
				},
				Permissions: actions,
			}, sync_from_target.WhatItem{
				DataObject: &data_source.DataObjectReference{
					// Raito doesn't need wildcard to interpret access on a folder: bucket/folder/* => bucket/folder
					FullName: removeEndingWildcards(convertArnToFullname(resource)),
					Type:     data_source.Folder,
				},
				Permissions: actions,
			}, sync_from_target.WhatItem{
				DataObject: &data_source.DataObjectReference{
					FullName: convertArnToFullname(resource),
					Type:     data_source.Bucket,
				},
				Permissions: actions,
			})
		}
	}

	return whatItems, nil
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
