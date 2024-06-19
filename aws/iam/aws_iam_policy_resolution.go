package iam

import (
	"fmt"
	"strings"

	"github.com/aws/smithy-go/ptr"
	"github.com/raito-io/cli/base/util/config"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	data_source2 "github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/golang-set/set"
)

func CreateWhoAndWhatFromAccessPointPolicy(policy *awspolicy.Policy, bucketName string, name string, account string, cfg *config.ConfigMap) (*sync_from_target.WhoItem, []sync_from_target.WhatItem, bool) {
	if policy == nil {
		return nil, nil, false
	}

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

		principalIncomplete := handlePrincipal(statement.Principal, account, fmt.Sprintf("Policy document for access point %q", name), users, groups, roles)
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
						resourceActions, incompleteResource = mapResourceActions(actions, data_source.Bucket, cfg)
					} else if strings.HasPrefix(path, "/object/") {
						path = utils.RemoveEndingWildcards(strings.TrimPrefix(path, "/object/"))
						if path == "" {
							fullName = bucketName
						} else {
							fullName = bucketName + "/" + path
						}

						resourceActions, incompleteResource = mapResourceActions(actions, data_source.Folder, cfg)
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

	return whoItem, flattenWhatMap(whatMap, account), incomplete
}

func CreateWhoFromTrustPolicyDocument(policy *awspolicy.Policy, role string, account string) (*sync_from_target.WhoItem, bool) {
	if policy == nil {
		return nil, false
	}

	whoItem := sync_from_target.WhoItem{}

	users := set.NewSet[string]()
	groups := set.NewSet[string]()

	incomplete := handleStatements(policy, role, func(statement awspolicy.Statement) bool {
		localIncomplete := false
		actions := statement.Action

		for _, action := range actions {
			if strings.EqualFold(action, "sts:AssumeRole") {
				principalIncomplete := handlePrincipal(statement.Principal, account, fmt.Sprintf("Trusted Policy document for role %q", role), users, groups, nil)
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
					lastPart := parts[len(parts)-1]

					if parts[1] == "*" {
						utils.Logger.Warn(fmt.Sprintf("UNSUPPORTED: %s contains wildcard IAM resource %q.", errorPrefix, resource))
						localIncomplete = true
					} else if strings.EqualFold(parts[0], "user") {
						users.Add(lastPart)
					} else if strings.EqualFold(parts[0], "group") {
						groups.Add(lastPart)
					} else if strings.EqualFold(parts[0], "role") && roles != nil {
						if strings.HasPrefix(lastPart, constants.SsoReservedPrefix+constants.SsoRolePrefix) {
							continue
						}

						roles.Add(constants.RoleTypePrefix + lastPart)
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

func CreateWhatFromPolicyDocument(policy *awspolicy.Policy, policyName string, account string, cfg *config.ConfigMap) ([]sync_from_target.WhatItem, bool) {
	if policy == nil {
		return nil, false
	}

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
					resourceActions, incompleteResource = mapResourceActions(actions, data_source.Bucket, cfg)
				} else {
					resourceActions, incompleteResource = mapResourceActions(actions, data_source.Folder, cfg)
				}
			} else if resource == "*" {
				fullName = account
				resourceActions, incompleteResource = mapResourceActions(actions, data_source.Datasource, cfg)
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

	return flattenWhatMap(whatMap, account), incomplete
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
func mapResourceActions(actions []string, resourceType string, cfg *config.ConfigMap) ([]string, bool) {
	mappedActions := make([]string, 0, len(actions))

	dot := data_source2.GetDataObjectType(resourceType, cfg)
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
