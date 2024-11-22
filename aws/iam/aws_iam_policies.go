package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/smithy-go/transport/http"
	"github.com/hashicorp/go-multierror"
	"github.com/raito-io/cli/base/util/match"
	"github.com/raito-io/cli/base/util/slice"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	baserepo "github.com/raito-io/cli-plugin-aws-account/aws/repo"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	"github.com/gammazero/workerpool"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/util/config"
)

const (
	UserResourceType    string = "user"
	GroupResourceType   string = "group"
	RoleResourceType    string = "role"
	SsoRoleResourceType string = "ssorole"
)

var smu sync.Mutex

var managedPoliciesCache []model.PolicyEntity

func (repo *AwsIamRepository) ClearManagedPoliciesCache() {
	managedPoliciesCache = nil
}

func (repo *AwsIamRepository) GetManagedPolicyByName(ctx context.Context, name string) (*model.PolicyEntity, error) {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return nil, err
	}

	policyArn := repo.GetPolicyArn(name, false, repo.configMap)

	policyOutput, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &policyArn})
	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			// Instead, searching as an aws managed policy
			policyArn = repo.GetPolicyArn(name, true, repo.configMap)

			policyOutput, err = client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &policyArn})
			if err != nil {
				if errors.As(err, &noSuchEntityErr) {
					return nil, nil
				} else {
					return nil, fmt.Errorf("get policy: %w", err)
				}

			}
		} else {
			return nil, fmt.Errorf("get policy: %w", err)
		}
	}

	if policyOutput == nil || policyOutput.Policy == nil {
		return nil, nil
	}

	// Now gather the policy details
	parsedPolicy := policyOutput.Policy
	tags := utils.GetTags(parsedPolicy.Tags)

	policyVersionInput := iam.GetPolicyVersionInput{
		PolicyArn: parsedPolicy.Arn,
		VersionId: parsedPolicy.DefaultVersionId,
	}

	policyVersionResp, err3 := client.GetPolicyVersion(ctx, &policyVersionInput)
	if err3 != nil {
		return nil, fmt.Errorf("get policy version for %q: %w", *parsedPolicy.PolicyName, err3)
	}

	policyDoc, policyDocReadable, err3 := repo.parsePolicyDocument(policyVersionResp.PolicyVersion.Document, "", *parsedPolicy.PolicyName)
	if err3 != nil {
		return nil, fmt.Errorf("parse policy document for %q: %w", *parsedPolicy.PolicyName, err3)
	}

	raitoPolicy := model.PolicyEntity{
		ARN:             *parsedPolicy.Arn,
		Name:            *parsedPolicy.PolicyName,
		Id:              *parsedPolicy.PolicyId,
		AttachmentCount: *parsedPolicy.AttachmentCount,
		Tags:            tags,
		PolicyDocument:  policyDocReadable,
		PolicyParsed:    policyDoc,
	}

	err = repo.AddAttachedEntitiesToManagedPolicy(ctx, client, &raitoPolicy)
	if err != nil {
		return nil, fmt.Errorf("add attached entities to managed policy: %w", err)
	}

	return &raitoPolicy, nil
}

func (repo *AwsIamRepository) GetManagedPolicies(ctx context.Context) ([]model.PolicyEntity, error) {
	excludes := slice.ParseCommaSeparatedList(repo.configMap.GetString(constants.AwsAccessManagedPolicyExcludes))

	if managedPoliciesCache != nil {
		return managedPoliciesCache, nil
	}

	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return nil, err
	}

	var result []model.PolicyEntity

	input := iam.ListPoliciesInput{
		OnlyAttached: false,
	}

	if repo.configMap.GetBool(constants.AwsAccessSkipAWSManagedPolicies) {
		input.Scope = types.PolicyScopeTypeLocal
	}

	var resultErr error

	paginator := iam.NewListPoliciesPaginator(client, &input)

	for paginator.HasMorePages() {
		resp, pageErr := paginator.NextPage(ctx)
		if pageErr != nil {
			return nil, fmt.Errorf("policy nex page: %w", pageErr)
		}

		workerPool := workerpool.New(utils.GetConcurrency(repo.configMap))

		for i := range resp.Policies {
			policy := resp.Policies[i]

			matched, err3 := match.MatchesAny(*policy.PolicyName, excludes)
			if err3 != nil {
				return nil, fmt.Errorf("matching policy to exlude: %w", err3)
			}

			if matched {
				utils.Logger.Debug(fmt.Sprintf("Skipping policy %s as it is excluded", *policy.PolicyName))
				continue
			}

			workerPool.Submit(func() {
				policyInput := iam.GetPolicyInput{
					PolicyArn: policy.Arn,
				}

				policyRespRaw, err3 := client.GetPolicy(ctx, &policyInput)
				if err3 != nil {
					utils.Logger.Error(fmt.Sprintf("Error getting policy details for %s", *policy.Arn))

					smu.Lock()
					resultErr = multierror.Append(resultErr, err3)
					smu.Unlock()

					return
				}
				parsedPolicy := policyRespRaw.Policy
				tags := utils.GetTags(parsedPolicy.Tags)

				policyVersionInput := iam.GetPolicyVersionInput{
					PolicyArn: parsedPolicy.Arn,
					VersionId: parsedPolicy.DefaultVersionId,
				}

				policyVersionResp, err3 := client.GetPolicyVersion(ctx, &policyVersionInput)
				if err3 != nil {
					utils.Logger.Error(fmt.Sprintf("Error getting policy document for %s: %s", *policy.Arn, err3.Error()))

					smu.Lock()
					resultErr = multierror.Append(resultErr, err3)
					smu.Unlock()

					return
				}

				policyDoc, policyDocReadable, err3 := repo.parsePolicyDocument(policyVersionResp.PolicyVersion.Document, "", *policy.PolicyName)
				if err3 != nil {
					utils.Logger.Error(fmt.Sprintf("Error parsing policy document for %s: %s", *policy.Arn, err3.Error()))

					smu.Lock()
					resultErr = multierror.Append(resultErr, err3)
					smu.Unlock()

					return
				}

				raitoPolicy := model.PolicyEntity{
					ARN:             *policy.Arn,
					Name:            *policy.PolicyName,
					Id:              *policy.PolicyId,
					AttachmentCount: *policy.AttachmentCount,
					Tags:            tags,
					PolicyDocument:  policyDocReadable,
					PolicyParsed:    policyDoc,
				}

				smu.Lock()
				defer smu.Unlock()

				err = repo.AddAttachedEntitiesToManagedPolicy(ctx, client, &raitoPolicy)
				if err != nil {
					utils.Logger.Error(fmt.Sprintf("Error adding attached entities to managed policy %s: %s", raitoPolicy.ARN, err.Error()))

					resultErr = multierror.Append(resultErr, err)

					return
				}

				result = append(result, raitoPolicy)
			})
		}

		workerPool.StopWait()

		utils.Logger.Info(fmt.Sprintf("Finished processing %d Policies", len(resp.Policies)))
		utils.Logger.Info(fmt.Sprintf("A total of %d policies have been found so far", len(result)))
	}

	if resultErr != nil {
		return nil, resultErr
	}

	utils.Logger.Info(fmt.Sprintf("A total of %d policies have been found", len(result)))

	managedPoliciesCache = result

	return managedPoliciesCache, nil
}

func (repo *AwsIamRepository) AddAttachedEntitiesToManagedPolicy(ctx context.Context, client *iam.Client, policy *model.PolicyEntity) error {
	var marker *string

	for {
		entityInput := iam.ListEntitiesForPolicyInput{
			Marker:    marker,
			PolicyArn: &policy.ARN,
		}

		attachedEntitiesResp, err := client.ListEntitiesForPolicy(ctx, &entityInput)
		if err != nil {
			return fmt.Errorf("list entities for policy: %w", err)
		}

		for _, entity := range attachedEntitiesResp.PolicyGroups {
			policy.GroupBindings = append(policy.GroupBindings, model.PolicyBinding{
				Type:         GroupResourceType,
				ResourceName: *entity.GroupName,
				ResourceId:   *entity.GroupId,
			})
		}

		for _, entity := range attachedEntitiesResp.PolicyUsers {
			policy.UserBindings = append(policy.UserBindings, model.PolicyBinding{
				Type:         UserResourceType,
				ResourceName: *entity.UserName,
				ResourceId:   *entity.UserId,
			})
		}

		for _, entity := range attachedEntitiesResp.PolicyRoles {
			entityType := RoleResourceType

			if strings.HasPrefix(*entity.RoleName, constants.SsoReservedPrefix+constants.SsoRolePrefix) {
				entityType = SsoRoleResourceType
			}

			policy.RoleBindings = append(policy.RoleBindings, model.PolicyBinding{
				Type:         entityType,
				ResourceName: *entity.RoleName,
				ResourceId:   *entity.RoleId,
			})
		}

		if !attachedEntitiesResp.IsTruncated {
			break
		}
		marker = attachedEntitiesResp.Marker
	}

	return nil
}

func (repo *AwsIamRepository) GetPolicyArn(policyName string, awsManaged bool, configMap *config.ConfigMap) string {
	policyArn := arn.ARN{
		Partition: "aws",
		Service:   "iam",
		AccountID: repo.account,
		Resource:  "policy/" + policyName,
	}

	if awsManaged {
		policyArn.AccountID = "aws"
	}

	return policyArn.String()
}

func (repo *AwsIamRepository) DeleteRoleInlinePolicies(ctx context.Context, roleName string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	// TODO we should handle paging here (unlikely there are too many though)
	listPoliciesOutput, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
		MaxItems: aws.Int32(100),
	})
	if err != nil {
		return fmt.Errorf("list role policies: %w", err)
	}

	for _, policyName := range listPoliciesOutput.PolicyNames {
		pn := policyName
		_, err2 := client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &pn,
		})

		if err2 != nil {
			return fmt.Errorf("delete role policy %q: %w", policyName, err2)
		}

		utils.Logger.Info(fmt.Sprintf("Deleted inline policy %s for role %s", policyName, roleName))
	}

	return nil
}

func (repo *AwsIamRepository) CreateRoleInlinePolicy(ctx context.Context, roleName string, policyName string, statements []*awspolicy.Statement) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	if len(statements) == 0 {
		utils.Logger.Warn(fmt.Sprintf("No statements/What provided for policy %s, skipping create", policyName))
		return nil
	}

	policyDoc, err := createPolicyDocument(statements)
	if err != nil {
		return err
	}

	utils.Logger.Info(fmt.Sprintf("Policy document for role inline policy creation: %s", policyDoc))

	_, err = client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		PolicyDocument: &policyDoc,
		PolicyName:     &policyName,
		RoleName:       &roleName,
	})

	if err != nil {
		utils.Logger.Info(fmt.Sprintf("Failed to create inline policy %q for role %q: %s", policyName, roleName, err.Error()))
		return fmt.Errorf("put role policy: %w", err)
	}

	utils.Logger.Info(fmt.Sprintf("Inline policy %q for role %q created", policyName, roleName))

	return nil
}

func (repo *AwsIamRepository) CreateManagedPolicy(ctx context.Context, policyName string, statements []*awspolicy.Statement) (*types.Policy, error) {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return nil, err
	}

	if len(statements) == 0 {
		utils.Logger.Warn(fmt.Sprintf("No statements/What provided for policy %s, skipping create", policyName))
		return nil, nil
	}

	policyDoc, err := createPolicyDocument(statements)
	if err != nil {
		return nil, err
	}

	utils.Logger.Debug(fmt.Sprintf("Policy document for managed policy creation: %s", policyDoc))

	input := iam.CreatePolicyInput{
		PolicyDocument: &policyDoc,
		PolicyName:     &policyName,
		Description:    nil,
		Path:           nil,
		Tags: []types.Tag{{
			Key:   aws.String("creator"),
			Value: aws.String("RAITO"),
		}},
	}

	resp, err := client.CreatePolicy(ctx, &input)
	if err != nil {
		utils.Logger.Info(fmt.Sprintf("Failed to create managed policy %q: %s", *input.PolicyName, err.Error()))
		return nil, fmt.Errorf("create policy: %w", err)
	}

	utils.Logger.Info(fmt.Sprintf("Managed policy %q created", *input.PolicyName))

	return resp.Policy, nil
}

func createPolicyDocument(statements []*awspolicy.Statement) (string, error) {
	stms := make([]awspolicy.Statement, 0, len(statements))
	for _, statement := range statements {
		stms = append(stms, *statement)
	}

	policy := awspolicy.Policy{
		Version:    "2012-10-17",
		Statements: stms,
	}

	bytes, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}

	policyDoc := string(bytes)

	return policyDoc, nil
}

func (repo *AwsIamRepository) UpdateManagedPolicy(ctx context.Context, policyName string, awsManaged bool, statements []*awspolicy.Statement) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	policyArn := repo.GetPolicyArn(policyName, awsManaged, repo.configMap)

	policyDoc, err := createPolicyDocument(statements)
	if err != nil {
		return fmt.Errorf("updating management policy: %w", err)
	}

	versions, err := client.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{PolicyArn: &policyArn})
	if err != nil {
		return fmt.Errorf("updating management policy: %w", err)
	}

	// check if the current default policy document is the same as the new one, if so, don't update
	for _, version := range versions.Versions {
		if !version.IsDefaultVersion {
			continue
		}

		defaultVersion, localErr := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: &policyArn,
			VersionId: version.VersionId,
		})

		if localErr != nil {
			return fmt.Errorf("updating management policy: %w", localErr)
		}

		existingPolicyDoc, localErr2 := url.QueryUnescape(*defaultVersion.PolicyVersion.Document)
		if localErr2 != nil {
			return fmt.Errorf("updating management policy: %w", localErr2)
		}

		utils.Logger.Debug(existingPolicyDoc)
		utils.Logger.Debug(policyDoc)

		if strings.EqualFold(utils.StripWhitespace(existingPolicyDoc), utils.StripWhitespace(policyDoc)) {
			utils.Logger.Info(fmt.Sprintf("Policy %s is already up-to-date", policyName))

			return nil
		}
	}

	// maximum 5 policy versions are allowed, delete the oldest non-default one to make room
	if len(versions.Versions) == 5 {
		var minCreateData *time.Time
		for _, version := range versions.Versions {
			if !version.IsDefaultVersion && (minCreateData == nil || version.CreateDate.Before(*minCreateData)) {
				minCreateData = version.CreateDate
			}
		}

		for _, version := range versions.Versions {
			if version.CreateDate.Equal(*minCreateData) {
				_, localErr := client.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{
					PolicyArn: &policyArn,
					VersionId: version.VersionId,
				})

				if localErr != nil {
					return fmt.Errorf("updating management policy: %w", localErr)
				}

				break
			}
		}
	}

	_, err = client.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{
		PolicyArn:      &policyArn,
		PolicyDocument: &policyDoc,
		SetAsDefault:   true,
	})
	if err != nil {
		return fmt.Errorf("updating management policy: %w", err)
	}

	return nil
}

func (repo *AwsIamRepository) DeleteManagedPolicy(ctx context.Context, policyName string, awsManaged bool) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	policyArn := repo.GetPolicyArn(policyName, awsManaged, repo.configMap)

	emptyPolicy := model.PolicyEntity{
		ARN: policyArn,
	}

	err = repo.AddAttachedEntitiesToManagedPolicy(ctx, client, &emptyPolicy)
	if err != nil {
		return fmt.Errorf("deleting managed policy: %w", err)
	}

	utils.Logger.Info(fmt.Sprintf("Detaching %d users from policy %s", len(emptyPolicy.UserBindings), policyArn))

	if localErr := repo.DetachUserFromManagedPolicy(ctx, policyArn, utils.GetResourceNamesFromPolicyBindingArray(emptyPolicy.UserBindings)); localErr != nil {
		return fmt.Errorf("deleting managed policy: %w", localErr)
	}

	utils.Logger.Info(fmt.Sprintf("Detaching %d groups from policy %s", len(emptyPolicy.GroupBindings), policyArn))

	if localErr := repo.DetachGroupFromManagedPolicy(ctx, policyArn, utils.GetResourceNamesFromPolicyBindingArray(emptyPolicy.GroupBindings)); localErr != nil {
		return fmt.Errorf("deleting managed policy: %w", localErr)
	}

	utils.Logger.Info(fmt.Sprintf("Detaching %d roles from policy %s", len(emptyPolicy.RoleBindings), policyArn))

	if localErr := repo.DetachRoleFromManagedPolicy(ctx, policyArn, utils.GetResourceNamesFromPolicyBindingArray(emptyPolicy.RoleBindings)); localErr != nil {
		return fmt.Errorf("deleting managed policy: %w", localErr)
	}

	versions, err := client.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{PolicyArn: &policyArn})
	if err != nil {
		return fmt.Errorf("deleting managed policy: %w", err)
	}

	for _, version := range versions.Versions {
		if !version.IsDefaultVersion {
			_, err = client.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{
				PolicyArn: &policyArn,
				VersionId: version.VersionId,
			})

			if err != nil {
				return fmt.Errorf("deleting managed policy: %w", err)
			}
		}
	}

	_, err = client.DeletePolicy(ctx, &iam.DeletePolicyInput{PolicyArn: &policyArn})
	if err != nil {
		return fmt.Errorf("deleting managed policy: %w", err)
	}

	return nil
}

func (repo *AwsIamRepository) AttachUserToManagedPolicy(ctx context.Context, policyArn string, userNames []string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	for _, userName := range userNames {
		_, err := client.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{
			PolicyArn: aws.String(policyArn),
			UserName:  aws.String(userName),
		})
		if err != nil {
			utils.Logger.Error(fmt.Sprintf("Couldn't attach policy %v to user %v: %v\n", policyArn, userName, err.Error()))
			return fmt.Errorf("attach policyto user %q: %w", userName, err)
		}
	}

	return nil
}

func (repo *AwsIamRepository) AttachGroupToManagedPolicy(ctx context.Context, policyArn string, groupNames []string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	for _, groupName := range groupNames {
		_, err := client.AttachGroupPolicy(ctx, &iam.AttachGroupPolicyInput{
			PolicyArn: aws.String(policyArn),
			GroupName: aws.String(groupName),
		})
		if err != nil {
			utils.Logger.Error(fmt.Sprintf("Couldn't attach policy %v to group %v. Here's why: %v\n", policyArn, groupName, err.Error()))
			return fmt.Errorf("attach policy to group %q: %w", groupName, err)
		}
	}

	return nil
}

func (repo *AwsIamRepository) AttachRoleToManagedPolicy(ctx context.Context, policyArn string, roleNames []string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	for _, roleName := range roleNames {
		_, err := client.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  aws.String(roleName),
		})
		if err != nil {
			utils.Logger.Error(fmt.Sprintf("Couldn't attach policy %v to role %v. Here's why: %v\n", policyArn, roleName, err.Error()))
			return fmt.Errorf("attach policy to role %q: %w", roleName, err)
		}
	}

	return nil
}

func (repo *AwsIamRepository) DetachUserFromManagedPolicy(ctx context.Context, policyArn string, userNames []string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	for _, userName := range userNames {
		_, err := client.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
			PolicyArn: aws.String(policyArn),
			UserName:  aws.String(userName),
		})
		if err != nil {
			utils.Logger.Error(fmt.Sprintf("Couldn't detach policy %v from user %v. Here's why: %v\n", policyArn, userName, err.Error()))
			return fmt.Errorf("detach policy from user %q: %w", userName, err)
		}
	}

	return nil
}

func (repo *AwsIamRepository) DetachGroupFromManagedPolicy(ctx context.Context, policyArn string, groupNames []string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	for _, groupName := range groupNames {
		_, err := client.DetachGroupPolicy(ctx, &iam.DetachGroupPolicyInput{
			PolicyArn: aws.String(policyArn),
			GroupName: aws.String(groupName),
		})
		if err != nil {
			utils.Logger.Error(fmt.Sprintf("Couldn't detach policy %v from group %v. Here's why: %v\n", policyArn, groupName, err.Error()))
			return fmt.Errorf("detach policy from group %q: %w", groupName, err)
		}
	}

	return nil
}

func (repo *AwsIamRepository) DetachRoleFromManagedPolicy(ctx context.Context, policyArn string, roleNames []string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	for _, roleName := range roleNames {
		_, err := client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  aws.String(roleName),
		})
		if err != nil {
			utils.Logger.Error(fmt.Sprintf("Couldn't detach policy %v from role %v. Here's why: %v\n", policyArn, roleName, err.Error()))
			return fmt.Errorf("detach policy from role %q: %w", roleName, err)
		}
	}

	return nil
}

func (repo *AwsIamRepository) UpdateInlinePolicy(ctx context.Context, policyName, resourceName, resourceType string, statements []*awspolicy.Statement) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	policyDocument, err := createPolicyDocument(statements)
	if err != nil {
		return err
	}

	switch resourceType {
	case UserResourceType:
		_, err = client.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
			PolicyName:     &policyName,
			UserName:       &resourceName,
			PolicyDocument: &policyDocument,
		})
		if err != nil {
			return fmt.Errorf("put user policy: %w", err)
		}
	case GroupResourceType:
		_, err = client.PutGroupPolicy(ctx, &iam.PutGroupPolicyInput{
			PolicyName:     &policyName,
			GroupName:      &resourceName,
			PolicyDocument: &policyDocument,
		})
		if err != nil {
			return fmt.Errorf("put group policy: %w", err)
		}
	case RoleResourceType:
		_, err = client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			PolicyName:     &policyName,
			RoleName:       &resourceName,
			PolicyDocument: &policyDocument,
		})
		if err != nil {
			return fmt.Errorf("put role policy: %w", err)
		}
	default:
		return fmt.Errorf("error updating inline policy %s for %s of type %s, unknown type", policyName, resourceName, resourceType)
	}

	return nil
}

func (repo *AwsIamRepository) DeleteInlinePolicy(ctx context.Context, policyName, resourceName, resourceType string) error {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return err
	}

	utils.Logger.Info(fmt.Sprintf("Deleting inline policy %s for %s/%s", policyName, resourceType, resourceName))

	switch resourceType {
	case UserResourceType:
		_, err = client.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
			PolicyName: &policyName,
			UserName:   &resourceName,
		})
		if err != nil {
			return fmt.Errorf("delete user policy: %w", err)
		}
	case GroupResourceType:
		_, err = client.DeleteGroupPolicy(ctx, &iam.DeleteGroupPolicyInput{
			PolicyName: &policyName,
			GroupName:  &resourceName,
		})
		if err != nil {
			return fmt.Errorf("delete group policy: %w", err)
		}
	case RoleResourceType:
		_, err = client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			PolicyName: &policyName,
			RoleName:   &resourceName,
		})
		if err != nil {
			return fmt.Errorf("delete role policy: %w", err)
		}
	default:
		return fmt.Errorf("error deleting inline policy %s for %s of type %s, unknown type", policyName, resourceName, resourceType)
	}

	return nil
}

func (repo *AwsIamRepository) GetInlinePoliciesForEntities(ctx context.Context, entityNames []string, entityType string) (map[string][]model.PolicyEntity, error) {
	client, err := repo.GetIamClient(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]model.PolicyEntity)
	var bindings []model.PolicyBinding

	switch strings.ToLower(entityType) {
	case UserResourceType:
		bindings, err = repo.getUserInlinePolicyBindings(ctx, client, entityNames)
		if err != nil {
			return nil, fmt.Errorf("get user inline policy bindings: %w", err)
		}
	case GroupResourceType:
		bindings, err = repo.getGroupInlinePolicyBindings(ctx, client, entityNames)
		if err != nil {
			return nil, fmt.Errorf("get group inline policy bindings: %w", err)
		}
	case RoleResourceType:
		bindings, err = repo.getRoleInlinePolicyBindings(ctx, client, entityNames)
		if err != nil {
			return nil, fmt.Errorf("get role inline policy bindings: %w", err)
		}
	}

	workerPool := workerpool.New(utils.GetConcurrency(repo.configMap))
	var mut sync.Mutex
	var resultErr error

	for i := range bindings {
		policyBinding := bindings[i]

		workerPool.Submit(func() {
			entityName := policyBinding.ResourceName
			policyName := policyBinding.PolicyName

			unparsedPolicyDocument, err2 := repo.getEntityPolicy(ctx, client, entityType, entityName, policyName)
			if err2 != nil {
				mut.Lock()
				resultErr = multierror.Append(resultErr, err2)
				mut.Unlock()

				return
			}

			if unparsedPolicyDocument == nil {
				return
			}

			policy, policyReadable, err2 := repo.parsePolicyDocument(unparsedPolicyDocument, entityName, policyName)
			if err2 != nil {
				mut.Lock()
				resultErr = multierror.Append(resultErr, err2)
				mut.Unlock()

				return
			}

			if policy == nil {
				return
			}

			var userPolicyBinding, groupPolicyBinding, rolePolicyBinding []model.PolicyBinding

			switch entityType {
			case UserResourceType:
				userPolicyBinding = append(userPolicyBinding, model.PolicyBinding{ResourceName: entityName, Type: entityType})
			case GroupResourceType:
				groupPolicyBinding = append(groupPolicyBinding, model.PolicyBinding{ResourceName: entityName, Type: entityType})
			case RoleResourceType:
				rolePolicyBinding = append(rolePolicyBinding, model.PolicyBinding{ResourceName: entityName, Type: entityType})
			}

			// Lock to add to map safely
			mut.Lock()
			defer mut.Unlock()

			result[entityName] = append(result[entityName], model.PolicyEntity{
				Name:           policyName,
				Description:    "inline policy",
				PolicyDocument: policyReadable,
				PolicyParsed:   policy,
				PolicyType:     model.Policy,
				InlineParent:   &entityName,
				UserBindings:   userPolicyBinding,
				GroupBindings:  groupPolicyBinding,
				RoleBindings:   rolePolicyBinding,
			})
		})
	}

	workerPool.StopWait()

	return result, resultErr
}

func (repo *AwsIamRepository) getUserInlinePolicyBindings(ctx context.Context, client *iam.Client, entityNames []string) ([]model.PolicyBinding, error) {
	var marker *string
	var policyBindings []model.PolicyBinding

	entityType := UserResourceType

	userExcludes := slice.ParseCommaSeparatedList(repo.configMap.GetString(constants.AwsUserExcludes))

	workerPool := workerpool.New(utils.GetConcurrency(repo.configMap))
	var smu sync.Mutex
	var resultErr error

	for i := range entityNames {
		entityName := entityNames[i]

		if entityName == "root" {
			continue
		}

		matched, err3 := match.MatchesAny(entityName, userExcludes)
		if err3 != nil {
			return nil, fmt.Errorf("matching user to exlude: %w", err3)
		}

		if matched {
			utils.Logger.Debug(fmt.Sprintf("Skipping policy fetching for user %s as it is excluded", entityName))
			continue
		}

		workerPool.Submit(func() {
			for {
				userPolicyInput := iam.ListUserPoliciesInput{
					UserName: &entityName,
					Marker:   marker,
				}

				resp, err := client.ListUserPolicies(ctx, &userPolicyInput)
				if err != nil {
					smu.Lock()
					resultErr = multierror.Append(resultErr, err)
					smu.Unlock()

					return
				}

				smu.Lock()
				for ind := range resp.PolicyNames {
					policyBindings = append(policyBindings, model.PolicyBinding{
						PolicyName:   resp.PolicyNames[ind],
						ResourceName: entityName,
						Type:         entityType,
					})
				}
				smu.Unlock()

				if !resp.IsTruncated {
					break
				}
				marker = resp.Marker
			}
		})
	}

	workerPool.StopWait()

	return policyBindings, resultErr
}

func (repo *AwsIamRepository) getGroupInlinePolicyBindings(ctx context.Context, client *iam.Client, entityNames []string) ([]model.PolicyBinding, error) { //nolint:dupl //We may want to optimise this later
	var marker *string
	var policyBindings []model.PolicyBinding

	entityType := GroupResourceType

	workerPool := workerpool.New(utils.GetConcurrency(repo.configMap))
	var smu sync.Mutex
	var resultErr error

	for i := range entityNames {
		entityName := entityNames[i]

		workerPool.Submit(func() {
			for {
				groupPolicyInput := iam.ListGroupPoliciesInput{
					GroupName: &entityName,
					Marker:    marker,
				}

				resp, err := client.ListGroupPolicies(ctx, &groupPolicyInput)
				if err != nil {
					smu.Lock()
					resultErr = multierror.Append(resultErr, err)
					smu.Unlock()

					return
				}

				smu.Lock()
				for _, policyName := range resp.PolicyNames {
					policyBindings = append(policyBindings, model.PolicyBinding{
						PolicyName:   policyName,
						ResourceName: entityName,
						Type:         entityType,
					})
				}
				smu.Unlock()

				if !resp.IsTruncated {
					break
				}
				marker = resp.Marker
			}
		})
	}

	workerPool.StopWait()

	return policyBindings, resultErr
}

func (repo *AwsIamRepository) getRoleInlinePolicyBindings(ctx context.Context, client *iam.Client, entityNames []string) ([]model.PolicyBinding, error) { //nolint:dupl //We may want to optimise this later
	var marker *string
	var policyBindings []model.PolicyBinding

	entityType := RoleResourceType

	workerPool := workerpool.New(utils.GetConcurrency(repo.configMap))
	var smu sync.Mutex
	var resultErr error

	for i := range entityNames {
		entityName := entityNames[i]

		workerPool.Submit(func() {
			for {
				rolePolicyInput := iam.ListRolePoliciesInput{
					RoleName: &entityName,
					Marker:   marker,
				}

				resp, err := client.ListRolePolicies(ctx, &rolePolicyInput)
				if err != nil {
					smu.Lock()
					resultErr = multierror.Append(resultErr, err)
					smu.Unlock()

					return
				}

				smu.Lock()
				for _, policyName := range resp.PolicyNames {
					policyBindings = append(policyBindings, model.PolicyBinding{
						PolicyName:   policyName,
						ResourceName: entityName,
						Type:         entityType,
					})
				}
				smu.Unlock()

				if !resp.IsTruncated {
					break
				}
				marker = resp.Marker
			}
		})
	}

	workerPool.StopWait()

	return policyBindings, resultErr
}

func (repo *AwsIamRepository) getEntityPolicy(ctx context.Context, client *iam.Client, entityType, entityName, policyName string) (*string, error) {
	switch strings.ToLower(entityType) {
	case UserResourceType:
		input := iam.GetUserPolicyInput{
			PolicyName: &policyName,
			UserName:   &entityName,
		}

		resp, err := client.GetUserPolicy(ctx, &input)
		if err != nil {
			utils.Logger.Info(fmt.Sprintf("error getting inline policy %s/%s: %s", entityName, policyName, err.Error()))
			return nil, fmt.Errorf("get user policy: %w", err)
		}

		if resp == nil || resp.PolicyDocument == nil {
			utils.Logger.Info(fmt.Sprintf("inline policy document is nil for %s %s/%s", entityType, entityName, policyName))
			return nil, nil
		}

		return resp.PolicyDocument, nil
	case GroupResourceType:
		input := iam.GetGroupPolicyInput{
			PolicyName: &policyName,
			GroupName:  &entityName,
		}
		resp, err := client.GetGroupPolicy(ctx, &input)

		if err != nil {
			utils.Logger.Info(fmt.Sprintf("error getting inline policy %s/%s: %s", entityName, policyName, err.Error()))
			return nil, fmt.Errorf("get group policy: %w", err)
		}

		if resp == nil || resp.PolicyDocument == nil {
			utils.Logger.Info(fmt.Sprintf("inline policy document is nil for %s %s/%s", entityType, entityName, policyName))
			return nil, nil
		}

		return resp.PolicyDocument, nil
	case RoleResourceType:
		input := iam.GetRolePolicyInput{
			PolicyName: &policyName,
			RoleName:   &entityName,
		}
		resp, err := client.GetRolePolicy(ctx, &input)

		if err != nil {
			utils.Logger.Info(fmt.Sprintf("error getting inline policy %s/%s: %s", entityName, policyName, err.Error()))
			return nil, fmt.Errorf("get role policy: %w", err)
		}

		if resp == nil || resp.PolicyDocument == nil {
			utils.Logger.Info(fmt.Sprintf("inline policy document is nil for %s %s/%s", entityType, entityName, policyName))
			return nil, nil
		}

		return resp.PolicyDocument, nil
	default:
		return nil, fmt.Errorf("entity type %s does not exist", entityType)
	}
}

func (repo *AwsIamRepository) parsePolicyDocument(policyDoc *string, entityName, policyName string) (*awspolicy.Policy, *string, error) {
	if policyDoc == nil {
		return nil, nil, fmt.Errorf("policy document is nil for %s/%s", entityName, policyName)
	}

	var policy awspolicy.Policy

	policyDocument, err := url.QueryUnescape(*policyDoc)
	if err != nil {
		utils.Logger.Info(fmt.Sprintf("Failed to unescape policy document %s/%s: %s", entityName, policyName, *policyDoc))
		return nil, nil, fmt.Errorf("query unescape: %w", err)
	}

	err = policy.UnmarshalJSON([]byte(policyDocument))
	if err != nil {
		utils.Logger.Info(fmt.Sprintf("Failed to parse policy document %s/%s: %s", entityName, policyName, *policyDoc))
		return nil, nil, fmt.Errorf("unmashal policy document: %w", err)
	}

	return &policy, &policyDocument, nil
}

func (repo *AwsIamRepository) getS3ControlClient(ctx context.Context, region *string) *s3control.Client {
	cfg, err := baserepo.GetAWSConfig(ctx, repo.configMap, region)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := s3control.NewFromConfig(cfg, func(o *s3control.Options) {})

	return client
}

func (repo *AwsIamRepository) ListAccessPoints(ctx context.Context, region string) ([]model.AwsS3AccessPoint, error) {
	client := repo.getS3ControlClient(ctx, &region)

	moreObjectsAvailable := true
	var nextToken *string

	aps := make([]model.AwsS3AccessPoint, 0, 100)

	for moreObjectsAvailable {
		lapo, err2 := client.ListAccessPoints(ctx, &s3control.ListAccessPointsInput{
			NextToken: nextToken,
			AccountId: &repo.account,
		})

		if err2 != nil {
			return nil, fmt.Errorf("listing access points: %w", err2)
		}

		moreObjectsAvailable = lapo.NextToken != nil
		nextToken = lapo.NextToken

		for _, sourceAp := range lapo.AccessPointList {
			if sourceAp.Name == nil || sourceAp.AccessPointArn == nil {
				continue
			}

			ap := model.AwsS3AccessPoint{
				Name: *sourceAp.Name,
				Arn:  *sourceAp.AccessPointArn,
			}

			if sourceAp.Bucket != nil {
				ap.Bucket = *sourceAp.Bucket
			}

			policy, err3 := client.GetAccessPointPolicy(ctx, &s3control.GetAccessPointPolicyInput{Name: sourceAp.Name, AccountId: &repo.account})

			var operationErr *http.ResponseError
			if errors.As(err3, &operationErr) && operationErr.HTTPStatusCode() == 404 {
				utils.Logger.Info(fmt.Sprintf("No policy found for access point %s", *sourceAp.Name))
				utils.Logger.Debug(fmt.Sprintf("Error of type %T: %+v", err3, err3))
			} else if err3 != nil {
				utils.Logger.Error(fmt.Sprintf("Error of type %T: %+v", err3, err3))

				e := errors.Unwrap(err3)
				for e != nil {
					utils.Logger.Error(fmt.Sprintf("Error of type %T: %+v", e, e))
					e = errors.Unwrap(e)
				}

				return nil, fmt.Errorf("fetching access point policy: %w", err3)
			} else if policy.Policy != nil {
				ap.PolicyParsed, ap.PolicyDocument, err3 = repo.parsePolicyDocument(policy.Policy, *sourceAp.Name, *sourceAp.Name)
				if err3 != nil {
					return nil, fmt.Errorf("parse policy document: %w", err3)
				}
			}

			aps = append(aps, ap)
		}
	}

	return aps, nil
}

func (repo *AwsIamRepository) DeleteAccessPoint(ctx context.Context, name string, region string) error {
	client := repo.getS3ControlClient(ctx, &region)

	_, err := client.DeleteAccessPoint(ctx, &s3control.DeleteAccessPointInput{
		AccountId: &repo.account,
		Name:      aws.String(name),
	})
	if err != nil {
		return fmt.Errorf("deleting access point: %w", err)
	}

	return nil
}

func (repo *AwsIamRepository) CreateAccessPoint(ctx context.Context, name, bucket string, region string, statements []*awspolicy.Statement) (string, error) {
	client := repo.getS3ControlClient(ctx, &region)

	input := &s3control.CreateAccessPointInput{
		AccountId: &repo.account,
		Bucket:    aws.String(bucket),
		Name:      aws.String(name),
	}

	s3Ap, err := client.CreateAccessPoint(ctx, input)

	if err != nil {
		return "", fmt.Errorf("creating access point %s: %w", name, err)
	}

	if s3Ap.AccessPointArn == nil {
		return "", fmt.Errorf("access point ARN is nil for %s", name)
	}

	s3ApArn := *s3Ap.AccessPointArn

	if len(statements) == 0 || len(statements[0].Principal) == 0 {
		utils.Logger.Info("No statements or principals provided for access point, skipping policy creation")
		return s3ApArn, nil
	}

	policyDoc, err := createPolicyDocument(statements)
	if err != nil {
		return s3ApArn, fmt.Errorf("creating policy document for access point %s: %w", name, err)
	}

	utils.Logger.Debug(fmt.Sprintf("Policy document for access point creation: %s", policyDoc))

	_, err = client.PutAccessPointPolicy(ctx, &s3control.PutAccessPointPolicyInput{
		AccountId: &repo.account,
		Name:      aws.String(name),
		Policy:    aws.String(policyDoc),
	})
	if err != nil {
		return s3ApArn, fmt.Errorf("putting policy for access point %s: %w", name, err)
	}

	return s3ApArn, nil
}

func (repo *AwsIamRepository) UpdateAccessPoint(ctx context.Context, name string, region string, statements []*awspolicy.Statement) error {
	client := repo.getS3ControlClient(ctx, &region)

	policyDoc, err := createPolicyDocument(statements)
	if err != nil {
		return fmt.Errorf("creating policy document for access point %s: %w", name, err)
	}

	utils.Logger.Debug(fmt.Sprintf("Policy document for access point update: %s", policyDoc))

	_, err = client.PutAccessPointPolicy(ctx, &s3control.PutAccessPointPolicyInput{
		AccountId: &repo.account,
		Name:      aws.String(name),
		Policy:    aws.String(policyDoc),
	})
	if err != nil {
		return fmt.Errorf("putting policy for access point %s: %w", name, err)
	}

	return nil
}
