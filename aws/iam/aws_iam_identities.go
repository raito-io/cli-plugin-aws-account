package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gammazero/workerpool"
	"github.com/hashicorp/go-multierror"
	"github.com/raito-io/cli/base/tag"
	"github.com/raito-io/cli/base/util/match"
	"github.com/raito-io/cli/base/util/slice"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils/trie"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	awspolicy "github.com/n4ch04/aws-policy"
)

var rolesCache []model.RoleEntity
var ssoRolesCache *trie.Trie[*model.RoleEntity]

func (repo *AwsIamRepository) GetUsers(ctx context.Context, withDetails bool) ([]model.UserEntity, error) {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return nil, err
	}

	moreObjectsAvailable := true
	var marker *string
	var allUsers []types.User

	for moreObjectsAvailable {
		input := iam.ListUsersInput{
			Marker: marker,
		}

		response, err2 := client.ListUsers(ctx, &input)
		if err2 != nil {
			return nil, fmt.Errorf("list users: %w", err2)
		}

		allUsers = append(allUsers, response.Users...)

		moreObjectsAvailable = response.IsTruncated
		marker = response.Marker
	}

	result := make([]model.UserEntity, 0, len(allUsers))

	workerPool := workerpool.New(utils.GetConcurrency(repo.configMap))
	var smu sync.Mutex

	var resultErr error

	excludes := slice.ParseCommaSeparatedList(repo.configMap.GetString(constants.AwsUserExcludes))

	for i := range allUsers {
		user := allUsers[i]

		workerPool.Submit(func() {
			emailAddress := *user.UserName
			var tags []*tag.Tag

			if withDetails {
				matched, err3 := match.MatchesAny(*user.UserName, excludes)
				if err3 != nil {
					smu.Lock()
					resultErr = multierror.Append(resultErr, err3)
					smu.Unlock()

					return
				}

				if matched {
					utils.Logger.Debug(fmt.Sprintf("Skipping details fetching for user %s as it is excluded", *user.UserName))
				} else {
					userInput := iam.GetUserInput{
						UserName: user.UserName,
					}

					userRaw, err2 := client.GetUser(ctx, &userInput)
					if err2 != nil {
						utils.Logger.Error(fmt.Sprintf("failed to get user %s: %s", *user.UserName, err2.Error()))

						smu.Lock()
						resultErr = multierror.Append(resultErr, err2)
						smu.Unlock()

						return
					}

					user = *userRaw.User
					tags = utils.GetTags(user.Tags)
					emailAddress = utils.GetEmailAddressFromTags(tags, *user.UserName)
				}
			}

			smu.Lock()
			defer smu.Unlock()

			result = append(result, model.UserEntity{
				ExternalId: *user.UserId,
				ARN:        *user.Arn,
				Name:       *user.UserName,
				Email:      emailAddress,
				Tags:       tags,
			})
		})
	}

	workerPool.StopWait()

	utils.Logger.Info(fmt.Sprintf("A total of %d users has been found", len(result)))

	result = append(result, model.UserEntity{
		ARN:        fmt.Sprintf("arn:aws:iam::%s:user/root", repo.account),
		ExternalId: fmt.Sprintf("arn:aws:iam::%s:user/root", repo.account),
		Name:       "root",
		Email:      "root@" + repo.account,
	})

	return result, resultErr
}

func (repo *AwsIamRepository) GetGroups(ctx context.Context) ([]model.GroupEntity, error) {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return nil, err
	}

	moreObjectsAvailable := true
	var marker *string
	var allGroups []types.Group

	for moreObjectsAvailable {
		input := iam.ListGroupsInput{
			Marker: marker,
		}

		response, err2 := client.ListGroups(ctx, &input)
		if err2 != nil {
			return nil, err
		}

		allGroups = append(allGroups, response.Groups...)

		moreObjectsAvailable = response.IsTruncated
		marker = response.Marker
	}

	result := make([]model.GroupEntity, 0, len(allGroups))

	for _, group := range allGroups {
		moreGroupDetailsAvailable := true
		var groupMarker *string
		var memberIds []string

		for moreGroupDetailsAvailable {
			groupInput := iam.GetGroupInput{
				GroupName: group.GroupName,
				Marker:    groupMarker,
			}

			groupDetails, err := client.GetGroup(ctx, &groupInput)
			if err != nil {
				return nil, fmt.Errorf("get group: %w", err)
			}

			moreGroupDetailsAvailable = groupDetails.IsTruncated
			groupMarker = groupDetails.Marker

			for _, u := range groupDetails.Users {
				memberIds = append(memberIds, *u.UserId)
			}
		}

		result = append(result, model.GroupEntity{
			ARN:        *group.Arn,
			ExternalId: *group.GroupId,
			Name:       *group.GroupName,
			Members:    memberIds,
		})
	}

	return result, nil
}

func (repo *AwsIamRepository) ClearRolesCache() {
	rolesCache = nil
	ssoRolesCache = nil
}

func (repo *AwsIamRepository) GetRoles(ctx context.Context, roleExcludes []string) ([]model.RoleEntity, error) {
	if rolesCache != nil {
		return rolesCache, nil
	}

	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return nil, err
	}

	var marker *string
	var allRoles []types.Role

	for {
		input := iam.ListRolesInput{
			Marker: marker,
		}

		resp, err2 := client.ListRoles(ctx, &input)
		if err2 != nil {
			return nil, err
		}

		allRoles = append(allRoles, resp.Roles...)

		if !resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}

	result := make([]model.RoleEntity, 0, len(allRoles))

	workerPool := workerpool.New(utils.GetConcurrency(repo.configMap))
	var smu sync.Mutex
	var resultErr error

	for i := range allRoles {
		roleFromList := allRoles[i]

		skip, err2 := match.MatchesAny(*roleFromList.RoleName, roleExcludes)
		if err2 != nil {
			utils.Logger.Error(fmt.Sprintf("invalid value for parameter %q: %s", constants.AwsAccessRoleExcludes, err2.Error()))
		}

		if skip {
			utils.Logger.Debug(fmt.Sprintf("Skipping role %q as it was requested to be skipped", *roleFromList.RoleName))
			continue
		}

		workerPool.Submit(func() {
			roleDetailsRaw, err3 := client.GetRole(ctx, &iam.GetRoleInput{
				RoleName: roleFromList.RoleName,
			})

			if err3 != nil {
				utils.Logger.Error(fmt.Sprintf("Error getting role details for %q: %s", *roleFromList.RoleName, err3.Error()))

				smu.Lock()
				resultErr = multierror.Append(resultErr, err3)
				smu.Unlock()

				return
			}

			var Arn, Id, Name, Description string
			var roleLastUsed *time.Time

			role := roleDetailsRaw.Role
			if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
				roleLastUsed = role.RoleLastUsed.LastUsedDate
			}

			if role.Arn != nil {
				Arn = *role.Arn
			}

			if role.RoleId != nil {
				Id = *role.RoleId
			}

			if role.RoleName != nil {
				Name = *role.RoleName
			}

			if role.Description != nil {
				Description = *role.Description
			}

			tags := utils.GetTags(role.Tags)

			trustPolicy, trustPolicyDocument, err2 := repo.parsePolicyDocument(role.AssumeRolePolicyDocument, Name, "trust-policy")
			if err2 != nil {
				utils.Logger.Error(fmt.Sprintf("Error reading trust policy from role %s: %s", *roleFromList.RoleName, err2.Error()))

				smu.Lock()
				resultErr = multierror.Append(resultErr, err2)
				smu.Unlock()

				return
			}

			smu.Lock()
			defer smu.Unlock()

			result = append(result, model.RoleEntity{
				ARN:                      Arn,
				Id:                       Id,
				Name:                     Name,
				Description:              Description,
				AssumeRolePolicyDocument: trustPolicyDocument,
				AssumeRolePolicy:         trustPolicy,
				Tags:                     tags,
				LastUsedDate:             roleLastUsed,
			})
		})
	}

	workerPool.StopWait()

	utils.Logger.Info(fmt.Sprintf("A total of %d roles have been found", len(result)))

	rolesCache = result

	return rolesCache, resultErr
}

// CreateRole creates an AWS Role. Every role needs a non-empty policy document (otherwise the Role is useless).
// the principals input parameters define which users will be able to assume the policy initially
func (repo *AwsIamRepository) CreateRole(ctx context.Context, name, description string, userNames []string) (bool, error) {
	if len(userNames) == 0 {
		return false, fmt.Errorf("no who defined")
	}

	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return false, err
	}

	initialPolicy, err := repo.CreateAssumeRolePolicyDocument(nil, userNames...)
	if err != nil {
		return false, err
	}

	_, err = client.CreateRole(ctx, &iam.CreateRoleInput{
		AssumeRolePolicyDocument: &initialPolicy,
		RoleName:                 &name,
		Description:              &description,
		Path:                     nil,
		Tags: []types.Tag{
			{
				Key:   aws.String("creator"),
				Value: aws.String("RAITO"),
			},
		},
	})
	if err != nil {
		return false, fmt.Errorf("create role: %w", err)
	}

	return true, nil
}

func (repo *AwsIamRepository) DeleteRole(ctx context.Context, name string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	_, err = client.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(name),
	})
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	return nil
}

func (repo *AwsIamRepository) loadSsoRolesWithPrefix(ctx context.Context, excludedRoles []string) error {
	roles, err := repo.GetRoles(ctx, excludedRoles)
	if err != nil {
		return fmt.Errorf("get roles: %w", err)
	}

	roleTrie := trie.New[*model.RoleEntity]("_")

	for i := range roles {
		role := &roles[i]

		if !strings.HasPrefix(role.Name, constants.SsoReservedPrefix) {
			continue
		}

		roleNameWithOutSsoReservedPrefix := role.Name[len(constants.SsoReservedPrefix):]
		utils.Logger.Info(fmt.Sprintf("Insert sso role %s to radixTree", roleNameWithOutSsoReservedPrefix))

		// Add role to roleTrie so we can search for it based on prefix
		roleTrie.Insert(roleNameWithOutSsoReservedPrefix, role)
	}

	ssoRolesCache = roleTrie

	return nil
}

func (repo *AwsIamRepository) GetSsoRoleWithPrefix(ctx context.Context, prefixName string, excludedRoles []string) (*model.RoleEntity, error) {
	if ssoRolesCache == nil {
		err := repo.loadSsoRolesWithPrefix(ctx, excludedRoles)
		if err != nil {
			return nil, fmt.Errorf("load sso roles: %w", err)
		}
	}

	utils.Logger.Info(fmt.Sprintf("Search for prefix: %s in tree with length %d", prefixName, ssoRolesCache.Size()))

	possibleRoles := ssoRolesCache.SearchPrefix(prefixName) // Search for all roles with that starts with prefixName

	if len(possibleRoles) == 0 {
		return nil, fmt.Errorf("sso role with prefix %s not found", prefixName)
	} else if len(possibleRoles) > 1 {
		return nil, fmt.Errorf("multiple sso roles (%d) with prefix %s found", len(possibleRoles), prefixName)
	}

	return possibleRoles[0], nil
}

func (repo *AwsIamRepository) ClearCache() {
	repo.ClearRolesCache() // To be optimized. But need role reload after creating SSO roles
	ssoRolesCache = nil
}

func (repo *AwsIamRepository) UpdateAssumeEntities(ctx context.Context, roleName string, userNames []string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	newPolicyDoc, err := repo.CreateAssumeRolePolicyDocument(nil, userNames...)
	if err != nil {
		return err
	}

	_, err = client.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		PolicyDocument: aws.String(newPolicyDoc),
		RoleName:       &roleName,
	})
	if err != nil {
		return fmt.Errorf("update assume role policy: %w", err)
	}

	return nil
}

func (repo *AwsIamRepository) CreateAssumeRolePolicyDocument(existingPolicyDoc *string, userNames ...string) (string, error) {
	newPrincipals := []string{}

	for _, userName := range userNames {
		newPrincipals = append(newPrincipals, utils.GetTrustUserPolicyArn(UserResourceType, userName, repo.account).String())
	}

	var policy *awspolicy.Policy

	if existingPolicyDoc != nil {
		var err error

		policy, _, err = repo.parsePolicyDocument(existingPolicyDoc, "", "")
		if err != nil {
			return "", fmt.Errorf("parse policy document: %w", nil)
		}

		for ind := range policy.Statements {
			// check if it's an assume role policy
			containsAssumeRole := false

			statement := policy.Statements[ind]

			for _, action := range statement.Action {
				if strings.EqualFold(action, "sts:AssumeRole") {
					containsAssumeRole = true
					break
				}
			}

			if containsAssumeRole {
				policy.Statements[ind].Principal["AWS"] = append(policy.Statements[ind].Principal["AWS"], newPrincipals...)
			}
		}
	} else {
		statements := []awspolicy.Statement{{
			Effect:    "Allow",
			Action:    []string{"sts:AssumeRole"},
			Principal: map[string][]string{"AWS": newPrincipals},
		}}

		policy = &awspolicy.Policy{
			Version:    "2012-10-17",
			Statements: statements,
		}
	}

	bytes, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}
	existingPolicyDoc = aws.String(string(bytes))

	return *existingPolicyDoc, nil
}
