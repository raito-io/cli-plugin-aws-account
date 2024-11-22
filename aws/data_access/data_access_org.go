package data_access

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/raito-io/cli/base/util/config"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/repo"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
)

const ReservedSSOPrefix = "AWSReservedSSO_"

type roleEnricher struct {
	ctx            context.Context
	configMap      *config.ConfigMap
	orgConfig      aws.Config
	identityStores []string
	instanceArns   []string
	account        string
	userMap        map[string]string
	groupMap       map[string]string
}

func newRoleEnricher(ctx context.Context, configMap *config.ConfigMap) *roleEnricher {
	return &roleEnricher{
		ctx:       ctx,
		configMap: configMap,
	}
}

func (e *roleEnricher) enrich(aps []model.AccessProviderInputExtended) error {
	orgProfile := e.configMap.GetString(constants.AwsOrganizationProfile)
	if orgProfile == "" {
		utils.Logger.Info("No organization profile specified. Skipping role enrichment")

		return nil
	}

	var err error

	e.account, err = repo.GetAccountId(e.ctx, e.configMap)
	if err != nil {
		return fmt.Errorf("get account id: %s", err.Error())
	}

	cfg, err := repo.GetAWSOrgConfig(e.ctx, e.configMap, nil)

	if err != nil {
		return fmt.Errorf("failed to get AWS organization config: %s", err.Error())
	}

	e.orgConfig = cfg

	utils.Logger.Info("Fetching SSO identityStores from organization")

	err = e.fetchSSOInstances()
	if err != nil {
		return fmt.Errorf("failed to fetch SSO identityStores: %s", err.Error())
	}

	utils.Logger.Info("Fetching users from organization")

	err = e.fetchUserMap()
	if err != nil {
		return fmt.Errorf("failed to fetch users: %s", err.Error())
	}

	utils.Logger.Info("Fetching groups from organization")

	err = e.fetchGroupMap()
	if err != nil {
		return fmt.Errorf("failed to fetch groups: %s", err.Error())
	}

	utils.Logger.Info("Fetching permission sets from organization")

	permissionSets, err := e.fetchPermissionSets()
	if err != nil {
		return fmt.Errorf("failed to fetch permission sets: %s", err.Error())
	}

	for i := range aps {
		ap := aps[i]

		if ap.ApInput == nil {
			utils.Logger.Warn(fmt.Sprintf("Access provider input is nil for ap of type: %s", ap.PolicyType))
			continue
		}

		if isPermissionSetRole(ap.ApInput.Name) {
			permissionSet := toPermissionSetName(ap.ApInput.Name)
			if permissionSet == "" {
				return fmt.Errorf("failed to get permission set name for role %q", ap.ApInput.Name)
			}

			utils.Logger.Info(fmt.Sprintf("Handling SSO Role %s: %s", ap.ApInput.Name, permissionSet))

			// Changing the (display) name of the role to the permission set name. Leaving actualName and others to the original as they are used to match on.
			ap.ApInput.Name = permissionSet

			ap.ApInput.ExternalId = constants.SsoRoleTypePrefix + strings.Split(ap.ApInput.ExternalId, ":")[1] // Replacing the prefix of the external ID
			ap.ApInput.Type = aws.String(string(model.SSORole))
			ap.ApInput.WhatLocked = aws.Bool(true)
			ap.ApInput.WhatLockedReason = aws.String("This policy is managed by AWS")
			ap.ApInput.NameLocked = aws.Bool(true)
			ap.ApInput.NameLockedReason = aws.String("This policy is managed by AWS")
			ap.ApInput.DeleteLocked = aws.Bool(true)
			ap.ApInput.DeleteLockedReason = aws.String("This policy is managed by AWS")

			if assignees, f := permissionSets[permissionSet]; f {
				for _, assignee := range assignees {
					if assignee.User != nil {
						ap.ApInput.Who.Users = append(ap.ApInput.Who.Users, *assignee.User)
					} else if assignee.Group != nil {
						ap.ApInput.Who.Groups = append(ap.ApInput.Who.Groups, *assignee.Group)
					}
				}
			} else {
				utils.Logger.Warn(fmt.Sprintf("permission set %q not found", permissionSet))
			}
		}
	}

	return nil
}

func (e *roleEnricher) fetchUserMap() error {
	client := identitystore.NewFromConfig(e.orgConfig)

	e.userMap = make(map[string]string)

	for _, identityStoreId := range e.identityStores {
		isID := identityStoreId
		moreObjectsAvailable := true
		var nextToken *string

		for moreObjectsAvailable {
			input := identitystore.ListUsersInput{
				NextToken:       nextToken,
				IdentityStoreId: &isID,
			}

			response, err := client.ListUsers(e.ctx, &input)
			if err != nil {
				return fmt.Errorf("error while listing users: %s", err.Error())
			}

			moreObjectsAvailable = response.NextToken != nil
			nextToken = response.NextToken

			for i := range response.Users {
				user := response.Users[i]
				e.userMap[*user.UserId] = *user.UserName
			}
		}
	}

	return nil
}

func (e *roleEnricher) fetchGroupMap() error {
	client := identitystore.NewFromConfig(e.orgConfig)

	e.groupMap = make(map[string]string)

	for _, identityStoreId := range e.identityStores {
		isID := identityStoreId
		moreObjectsAvailable := true
		var nextToken *string

		for moreObjectsAvailable {
			input := identitystore.ListGroupsInput{
				NextToken:       nextToken,
				IdentityStoreId: &isID,
			}

			response, err := client.ListGroups(e.ctx, &input)
			if err != nil {
				return fmt.Errorf("error while listing groups: %s", err.Error())
			}

			moreObjectsAvailable = response.NextToken != nil
			nextToken = response.NextToken

			for i := range response.Groups {
				group := response.Groups[i]
				e.groupMap[*group.GroupId] = *group.DisplayName
			}
		}
	}

	return nil
}

func (e *roleEnricher) fetchSSOInstances() error {
	client := ssoadmin.NewFromConfig(e.orgConfig)

	instances, err := client.ListInstances(e.ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		return fmt.Errorf("list instances: %w", err)
	}

	e.identityStores = make([]string, 0)
	e.instanceArns = make([]string, 0)

	for _, instance := range instances.Instances {
		if instance.InstanceArn != nil {
			e.identityStores = append(e.identityStores, *instance.IdentityStoreId)
			e.instanceArns = append(e.instanceArns, *instance.InstanceArn)
		}
	}

	return nil
}

type Assignee struct {
	User  *string
	Group *string
}

func (e *roleEnricher) fetchPermissionSets() (map[string][]Assignee, error) {
	client := ssoadmin.NewFromConfig(e.orgConfig)

	ret := make(map[string][]Assignee)

	for i := range e.instanceArns {
		instance := e.instanceArns[i]

		utils.Logger.Info(fmt.Sprintf("Fetching permission sets for SSO instance %s", instance))

		moreObjectsAvailable := true
		var nextToken *string

		for moreObjectsAvailable {
			response, err := client.ListPermissionSets(e.ctx, &ssoadmin.ListPermissionSetsInput{
				InstanceArn: &instance,
				NextToken:   nextToken,
			})

			if err != nil {
				return nil, fmt.Errorf("error while listing permission sets: %s", err.Error())
			}

			moreObjectsAvailable = response.NextToken != nil
			nextToken = response.NextToken

			for _, permissionSet := range response.PermissionSets {
				psName, err := e.fetchPermissionSetName(client, instance, permissionSet)
				if err != nil {
					return nil, fmt.Errorf("error while fetching permission set details for %q: %s", permissionSet, err.Error())
				}

				psDetails, err := e.fetchPermissionSetAssignees(client, instance, permissionSet)
				if err != nil {
					return nil, fmt.Errorf("error while fetching permission set assignees for %q in account %s: %s", permissionSet, e.account, err.Error())
				}

				ret[psName] = psDetails
			}
		}
	}

	return ret, nil
}

func (e *roleEnricher) fetchPermissionSetAssignees(client *ssoadmin.Client, instanceArn, permissionSetArn string) ([]Assignee, error) {
	psAssignments, err := client.ListAccountAssignments(e.ctx, &ssoadmin.ListAccountAssignmentsInput{
		InstanceArn:      &instanceArn,
		PermissionSetArn: &permissionSetArn,
		AccountId:        &e.account,
	})

	if err != nil {
		return nil, fmt.Errorf("list account assignments: %w", err)
	}

	var ret []Assignee

	for _, aa := range psAssignments.AccountAssignments {
		principal := *aa.PrincipalId
		if aa.PrincipalType == types.PrincipalTypeUser {
			if user, f := e.userMap[principal]; f {
				ret = append(ret, Assignee{User: &user})
			} else {
				utils.Logger.Warn(fmt.Sprintf("unable to find user with id %q", principal))
			}
		} else if aa.PrincipalType == types.PrincipalTypeGroup {
			if group, f := e.groupMap[principal]; f {
				ret = append(ret, Assignee{Group: &group})
			} else {
				utils.Logger.Warn(fmt.Sprintf("unable to find group with id %q", principal))
			}
		}
	}

	return ret, nil
}

func (e *roleEnricher) fetchPermissionSetName(client *ssoadmin.Client, instanceArn, permissionSetArn string) (string, error) {
	details, err := client.DescribePermissionSet(e.ctx, &ssoadmin.DescribePermissionSetInput{
		InstanceArn:      &instanceArn,
		PermissionSetArn: &permissionSetArn,
	})

	if err != nil {
		return "", fmt.Errorf("describe permission set: %w", err)
	}

	return *details.PermissionSet.Name, nil
}

func toPermissionSetName(name string) string {
	prefix := ReservedSSOPrefix
	if len(name) <= len(prefix) {
		return ""
	}

	name = name[len(prefix):]

	i := strings.LastIndex(name, "_")
	if i < 0 {
		return ""
	}

	return name[:i]
}

func isPermissionSetRole(name string) bool {
	return strings.HasPrefix(name, ReservedSSOPrefix)
}
