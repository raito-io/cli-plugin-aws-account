package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gammazero/workerpool"
	"github.com/raito-io/cli/base/tag"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/raito-io/golang-set/set"

	awspolicy "github.com/n4ch04/aws-policy"
)

func (repo *AwsIamRepository) GetUsers(ctx context.Context, withDetails bool) ([]UserEntity, error) {
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
			return nil, err
		}

		allUsers = append(allUsers, response.Users...)

		moreObjectsAvailable = response.IsTruncated
		marker = response.Marker
	}

	result := make([]UserEntity, 0, len(allUsers))

	workerPool := workerpool.New(getConcurrency(repo.ConfigMap))
	var smu sync.Mutex

	for i := range allUsers {
		user := allUsers[i]

		workerPool.Submit(func() {
			emailAddress := *user.UserName
			var tags []*tag.Tag

			if withDetails {
				userInput := iam.GetUserInput{
					UserName: user.UserName,
				}

				userRaw, err2 := client.GetUser(ctx, &userInput)
				if err2 != nil {
					return
				}
				user = *userRaw.User
				tags = getTags(user.Tags)
				emailAddress = getEmailAddressFromTags(tags, *user.UserName)
			}

			smu.Lock()
			defer smu.Unlock()
			result = append(result, UserEntity{
				ExternalId: *user.UserId,
				ARN:        *user.Arn,
				Name:       *user.UserName,
				Email:      emailAddress,
				Tags:       tags,
			})
		})
	}

	workerPool.StopWait()

	logger.Info(fmt.Sprintf("A total of %d users has been found", len(result)))

	return result, nil
}

func (repo *AwsIamRepository) GetGroups(ctx context.Context) ([]GroupEntity, error) {
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

	result := make([]GroupEntity, 0, len(allGroups))

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
				return nil, nil
			}

			moreGroupDetailsAvailable = groupDetails.IsTruncated
			groupMarker = groupDetails.Marker

			for _, u := range groupDetails.Users {
				memberIds = append(memberIds, *u.UserId)
			}
		}

		result = append(result, GroupEntity{
			ARN:        *group.Arn,
			ExternalId: *group.GroupId,
			Name:       *group.GroupName,
			Members:    memberIds,
		})
	}

	return result, nil
}

func (repo *AwsIamRepository) GetRoles(ctx context.Context) ([]RoleEntity, error) {
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

	logger.Info(fmt.Sprintf("%d roles received from AWS", len(allRoles)))

	result := make([]RoleEntity, 0, len(allRoles))

	workerPool := workerpool.New(getConcurrency(repo.ConfigMap))
	var smu sync.Mutex

	for i := range allRoles {
		roleFromList := allRoles[i]

		workerPool.Submit(func() {
			roleDetailsRaw, err2 := client.GetRole(ctx, &iam.GetRoleInput{
				RoleName: roleFromList.RoleName,
			})

			if err2 != nil {
				logger.Error(fmt.Sprintf("Error getting role %s: %s", *roleFromList.RoleName, err2.Error()))
				// TODO error handling
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

			tags := getTags(role.Tags)

			trustPolicy, trustPolicyDocument, err2 := repo.parsePolicyDocument(role.AssumeRolePolicyDocument, Name, "trust-policy")
			if err2 != nil {
				logger.Error(fmt.Sprintf("Error reading trust policy from role %s: %s", *roleFromList.RoleName, err2.Error()))
				// TODO error handling
				return
			}

			smu.Lock()
			defer smu.Unlock()
			result = append(result, RoleEntity{
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

	logger.Info(fmt.Sprintf("A total of %d roles have been found", len(result)))

	return result, nil
}

// CreateRole creates an AWS Role. Every role needs a non-empty policy document (otherwise the Role is useless).
// the principals input parameters define which users will be able to assume the policy initially
func (repo *AwsIamRepository) CreateRole(ctx context.Context, name, description string, userNames []string) error {
	if len(userNames) == 0 {
		logger.Warn("No users provided to assume the role")
		return nil
	}

	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	initialPolicy, err := repo.CreateAssumeRolePolicyDocument(nil, userNames...)
	if err != nil {
		return err
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
		return err
	}

	return nil
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
		return nil
	}

	return nil
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
		return err
	}

	return nil
}

func (repo *AwsIamRepository) CreateAssumeRolePolicyDocument(existingPolicyDoc *string, userNames ...string) (string, error) {
	newPrincipals := []string{}

	for _, userName := range userNames {
		newPrincipals = append(newPrincipals, getTrustPolicyArn(userName, repo.ConfigMap))
	}

	var policy *awspolicy.Policy

	if existingPolicyDoc != nil {
		var err error

		policy, _, err = repo.parsePolicyDocument(existingPolicyDoc, "", "")
		if err != nil {
			return "", nil
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
		return "", err
	}
	existingPolicyDoc = aws.String(string(bytes))

	return *existingPolicyDoc, nil
}

func (repo *AwsIamRepository) GetPrincipalsFromAssumeRolePolicyDocument(policyDocument *string) ([]string, error) {
	// TODO replace with new createWhoFromTrustPolicyDocument method ?
	principals := set.Set[string]{}

	if policyDocument == nil {
		return nil, nil
	}

	policy, _, err := repo.parsePolicyDocument(policyDocument, "", "")
	if err != nil {
		return nil, err
	}

	for ind := range policy.Statements {
		statement := policy.Statements[ind]
		containsAssumeRole := false

		for ind := range statement.Action {
			action := statement.Action[ind]
			if strings.Contains(action, "sts:AssumeRole") {
				containsAssumeRole = true
				break
			}
		}

		if containsAssumeRole {
			for _, principal := range statement.Principal["AWS"] {
				userName := convertArnToFullname(principal)
				parts := strings.Split(userName, "/")

				if len(parts) == 2 {
					principals.Add(parts[1])
				}
			}
		}
	}

	return principals.Slice(), nil
}
