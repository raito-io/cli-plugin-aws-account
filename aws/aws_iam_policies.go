package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gammazero/workerpool"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/util/config"
)

const (
	UserResourceType  string = "user"
	GroupResourceType string = "group"
	RoleResourceType  string = "role"
)

func (repo *AwsIamRepository) GetManagedPolicies(ctx context.Context, configMap *config.ConfigMap, withAttachedEntities bool) ([]PolicyEntity, error) {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return nil, err
	}

	var marker *string
	var result []PolicyEntity

	for {
		input := iam.ListPoliciesInput{
			Marker:       marker,
			OnlyAttached: false,
			MaxItems:     aws.Int32(50),
		}

		resp, err := client.ListPolicies(ctx, &input)
		if err != nil {
			return nil, err
		}

		// TODO make number of workers configurable
		workerPool := workerpool.New(5)

		for i := range resp.Policies {
			policy := resp.Policies[i]

			workerPool.Submit(func() {
				// TODO, dev, remove
				if discardPolicy(policy) {
					return
				}

				input := iam.GetPolicyInput{
					PolicyArn: policy.Arn,
				}

				policyRespRaw, err := client.GetPolicy(ctx, &input)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error getting policy details for %s", *policy.Arn))
					return
				}
				policy := policyRespRaw.Policy
				tags := getTags(policy.Tags)

				policyVersionInput := iam.GetPolicyVersionInput{
					PolicyArn: policy.Arn,
					VersionId: policy.DefaultVersionId,
				}

				policyVersionResp, err := client.GetPolicyVersion(ctx, &policyVersionInput)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error getting policy document for %s", *policy.Arn))
					return
				}

				policyDoc, policyDocReadable, err := repo.parsePolicyDocument(policyVersionResp.PolicyVersion.Document, "", *policy.PolicyName)
				if err != nil {
					return
				}

				raitoPolicy := PolicyEntity{
					ARN:             *policy.Arn,
					Name:            *policy.PolicyName,
					Id:              *policy.PolicyId,
					AttachmentCount: *policy.AttachmentCount,
					Tags:            tags,
					PolicyDocument:  policyDocReadable,
					PolicyParsed:    policyDoc,
				}

				if withAttachedEntities {
					err = repo.AddAttachedEntitiesToManagedPolicy(ctx, *client, &raitoPolicy)
					if err != nil {
						return
					}
				}

				result = append(result, raitoPolicy)
			})
		}

		workerPool.StopWait()

		if !resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}

	logger.Info(fmt.Sprintf("A total of %d policies have been found", len(result)))

	return result, nil
}

func (repo *AwsIamRepository) AddAttachedEntitiesToManagedPolicy(ctx context.Context, client iam.Client, policy *PolicyEntity) error {
	var marker *string

	for {
		entityInput := iam.ListEntitiesForPolicyInput{
			Marker:    marker,
			PolicyArn: &policy.ARN,
		}

		attachedEntitiesResp, err := client.ListEntitiesForPolicy(ctx, &entityInput)
		if err != nil {
			return err
		}

		for _, entity := range attachedEntitiesResp.PolicyGroups {
			policy.GroupBindings = append(policy.GroupBindings, PolicyBinding{
				Type:         GroupResourceType,
				ResourceName: *entity.GroupName,
				ResourceId:   *entity.GroupId,
			})
		}

		for _, entity := range attachedEntitiesResp.PolicyUsers {
			policy.UserBindings = append(policy.UserBindings, PolicyBinding{
				Type:         UserResourceType,
				ResourceName: *entity.UserName,
				ResourceId:   *entity.UserId,
			})
		}

		for _, entity := range attachedEntitiesResp.PolicyRoles {
			policy.RoleBindings = append(policy.RoleBindings, PolicyBinding{
				Type:         RoleResourceType,
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

func (repo *AwsIamRepository) GetPolicyArn(policyName string, configMap *config.ConfigMap) string {
	return arn.ARN{
		Partition: "aws",
		Service:   "iam",
		AccountID: configMap.GetString(AwsAccountId),
		Resource:  "policy/" + policyName,
	}.String()
}

func (repo *AwsIamRepository) CreateManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyName string, statements []awspolicy.Statement) (*types.Policy, error) {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return nil, err
	}

	if len(statements) == 0 {
		logger.Warn(fmt.Sprintf("No statements/What provided for policy %s, skipping create", policyName))
		return nil, nil
	}

	policyDoc, err := repo.createPolicyDocument(statements)
	if err != nil {
		return nil, err
	}

	logger.Info(fmt.Sprintf("Policy document for managed policy creation: %s", policyDoc))

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
		logger.Info(fmt.Sprintf("Failed to create managed policy %q: %s", *input.PolicyName, err.Error()))
		return nil, err
	}

	logger.Info(fmt.Sprintf("Managed policy %q created", *input.PolicyName))

	return resp.Policy, nil
}

func (repo *AwsIamRepository) createPolicyDocument(statements []awspolicy.Statement) (string, error) {
	policy := awspolicy.Policy{
		Version:    "2012-10-17",
		Statements: statements,
	}

	bytes, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	policyDoc := string(bytes)

	return policyDoc, nil
}

func (repo *AwsIamRepository) UpdateManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyName string, statements []awspolicy.Statement) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	policyArn := repo.GetPolicyArn(policyName, configMap)

	policyDoc, err := repo.createPolicyDocument(statements)
	if err != nil {
		return err
	}

	versions, err := client.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{PolicyArn: &policyArn})
	if err != nil {
		return err
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
			return localErr
		}

		existingPolicyDoc, localErr2 := url.QueryUnescape(*defaultVersion.PolicyVersion.Document)
		if localErr2 != nil {
			return localErr2
		}

		logger.Info(existingPolicyDoc)
		logger.Info(policyDoc)

		if strings.EqualFold(stripWhitespace(existingPolicyDoc), stripWhitespace(policyDoc)) {
			logger.Info(fmt.Sprintf("Policy %s is already up-to-date", policyName))

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
					return localErr
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
		return err
	}

	return nil
}

func (repo *AwsIamRepository) DeleteManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyName string) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	policyArn := repo.GetPolicyArn(policyName, configMap)

	emptyPolicy := PolicyEntity{
		ARN: policyArn,
	}

	err = repo.AddAttachedEntitiesToManagedPolicy(ctx, *client, &emptyPolicy)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Detaching %d users from policy %s", len(emptyPolicy.UserBindings), policyArn))

	if localErr := repo.DetachUserFromManagedPolicy(ctx, configMap, policyArn, getResourceNamesFromPolicyBindingArray(emptyPolicy.UserBindings)); localErr != nil {
		return localErr
	}

	logger.Info(fmt.Sprintf("Detaching %d groups from policy %s", len(emptyPolicy.GroupBindings), policyArn))

	if localErr := repo.DetachGroupFromManagedPolicy(ctx, configMap, policyArn, getResourceNamesFromPolicyBindingArray(emptyPolicy.GroupBindings)); localErr != nil {
		return localErr
	}

	logger.Info(fmt.Sprintf("Detaching %d roles from policy %s", len(emptyPolicy.RoleBindings), policyArn))

	if localErr := repo.DetachRoleFromManagedPolicy(ctx, configMap, policyArn, getResourceNamesFromPolicyBindingArray(emptyPolicy.RoleBindings)); localErr != nil {
		return localErr
	}

	versions, err := client.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{PolicyArn: &policyArn})
	if err != nil {
		return err
	}

	for _, version := range versions.Versions {
		if !version.IsDefaultVersion {
			_, err = client.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{
				PolicyArn: &policyArn,
				VersionId: version.VersionId,
			})

			if err != nil {
				return err
			}
		}
	}

	_, err = client.DeletePolicy(ctx, &iam.DeletePolicyInput{PolicyArn: &policyArn})
	if err != nil {
		return err
	}

	return nil
}

func (repo *AwsIamRepository) AttachUserToManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, userNames []string) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	for _, userName := range userNames {
		_, err := client.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{
			PolicyArn: aws.String(policyArn),
			UserName:  aws.String(userName),
		})
		if err != nil {
			logger.Error(fmt.Sprintf("Couldn't attach policy %v to user %v. Here's why: %v\n", policyArn, userName, err.Error()))
			return err
		}
	}

	return nil
}

func (repo *AwsIamRepository) AttachGroupToManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, groupNames []string) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	for _, groupName := range groupNames {
		_, err := client.AttachGroupPolicy(ctx, &iam.AttachGroupPolicyInput{
			PolicyArn: aws.String(policyArn),
			GroupName: aws.String(groupName),
		})
		if err != nil {
			logger.Error(fmt.Sprintf("Couldn't attach policy %v to group %v. Here's why: %v\n", policyArn, groupName, err.Error()))
			return err
		}
	}

	return nil
}

func (repo *AwsIamRepository) AttachRoleToManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, roleNames []string) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	for _, roleName := range roleNames {
		_, err := client.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  aws.String(roleName),
		})
		if err != nil {
			logger.Error(fmt.Sprintf("Couldn't attach policy %v to role %v. Here's why: %v\n", policyArn, roleName, err.Error()))
			return err
		}
	}

	return nil
}

func (repo *AwsIamRepository) DetachUserFromManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, userNames []string) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	for _, userName := range userNames {
		_, err := client.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
			PolicyArn: aws.String(policyArn),
			UserName:  aws.String(userName),
		})
		if err != nil {
			logger.Error(fmt.Sprintf("Couldn't detach policy %v from user %v. Here's why: %v\n", policyArn, userName, err.Error()))
			return err
		}
	}

	return nil
}

func (repo *AwsIamRepository) DetachGroupFromManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, groupNames []string) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	for _, groupName := range groupNames {
		_, err := client.DetachGroupPolicy(ctx, &iam.DetachGroupPolicyInput{
			PolicyArn: aws.String(policyArn),
			GroupName: aws.String(groupName),
		})
		if err != nil {
			logger.Error(fmt.Sprintf("Couldn't detach policy %v from group %v. Here's why: %v\n", policyArn, groupName, err.Error()))
			return err
		}
	}

	return nil
}

func (repo *AwsIamRepository) DetachRoleFromManagedPolicy(ctx context.Context, configMap *config.ConfigMap, policyArn string, roleNames []string) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	for _, roleName := range roleNames {
		_, err := client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  aws.String(roleName),
		})
		if err != nil {
			logger.Error(fmt.Sprintf("Couldn't detach policy %v from role %v. Here's why: %v\n", policyArn, roleName, err.Error()))
			return err
		}
	}

	return nil
}

func (repo *AwsIamRepository) UpdateInlinePolicy(ctx context.Context, configMap *config.ConfigMap, policyName, resourceName, resourceType string, statements []awspolicy.Statement) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	policyDocument, err := repo.createPolicyDocument(statements)
	if err != nil {
		return err
	}

	if resourceType == UserResourceType {
		_, err = client.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
			PolicyName:     &policyName,
			UserName:       &resourceName,
			PolicyDocument: &policyDocument,
		})
	} else if resourceType == GroupResourceType {
		_, err = client.PutGroupPolicy(ctx, &iam.PutGroupPolicyInput{
			PolicyName:     &policyName,
			GroupName:      &resourceName,
			PolicyDocument: &policyDocument,
		})
	} else if resourceType == RoleResourceType {
		_, err = client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			PolicyName:     &policyName,
			RoleName:       &resourceName,
			PolicyDocument: &policyDocument,
		})
	} else {
		return fmt.Errorf("error updating inline policy %s for %s of type %s, unknown type", policyName, resourceName, resourceType)
	}

	return err
}

func (repo *AwsIamRepository) DeleteInlinePolicy(ctx context.Context, configMap *config.ConfigMap, policyName, resourceName, resourceType string) error {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Deleting inline policy %s for %s/%s", policyName, resourceType, resourceName))

	if resourceType == UserResourceType {
		_, err = client.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
			PolicyName: &policyName,
			UserName:   &resourceName,
		})
	} else if resourceType == GroupResourceType {
		_, err = client.DeleteGroupPolicy(ctx, &iam.DeleteGroupPolicyInput{
			PolicyName: &policyName,
			GroupName:  &resourceName,
		})
	} else if resourceType == RoleResourceType {
		_, err = client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			PolicyName: &policyName,
			RoleName:   &resourceName,
		})
	} else {
		return fmt.Errorf("error deleting inline policy %s for %s of type %s, unknown type", policyName, resourceName, resourceType)
	}

	return err
}

func (repo *AwsIamRepository) GetAttachedEntity(ap sync_to_target.AccessProvider) (string, string, error) {
	if ap.ActualName == nil || !strings.HasPrefix(*ap.ActualName, "/inline/") {
		return "", "", fmt.Errorf("no attached entity found for %s", *ap.ActualName)
	}

	resourceType := ""
	resourceName := ""
	possibleResourceTypes := []string{UserResourceType, GroupResourceType, RoleResourceType}

	for _, rType := range possibleResourceTypes {
		prefix := fmt.Sprintf("/inline/%s/", rType)

		stripped, ok := strings.CutPrefix(*ap.ActualName, prefix)
		if !ok {
			continue
		}

		parts := strings.Split(stripped, "/")
		if len(parts) <= 1 {
			continue
		}

		return parts[0], rType, nil
	}

	return resourceName, resourceType, nil
}

func (repo *AwsIamRepository) GetInlinePoliciesForEntities(ctx context.Context, configMap *config.ConfigMap, entityNames []string, entityType string) ([]PolicyEntity, error) {
	client, err := repo.GetIamClient(ctx, configMap)
	if err != nil {
		return nil, err
	}

	var result []PolicyEntity
	var bindings []PolicyBinding

	if strings.EqualFold(entityType, UserResourceType) {
		bindings, err = repo.getUserInlinePolicyBindings(ctx, client, entityNames)
		if err != nil {
			return nil, err
		}
	} else if strings.EqualFold(entityType, GroupResourceType) {
		bindings, err = repo.getGroupInlinePolicyBindings(ctx, client, entityNames)
		if err != nil {
			return nil, err
		}
	} else if strings.EqualFold(entityType, RoleResourceType) {
		bindings, err = repo.getRoleInlinePolicyBindings(ctx, client, entityNames)
		if err != nil {
			return nil, err
		}
	}

	// TODO make number of workers configurable
	workerPool := workerpool.New(5)

	for i := range bindings {
		policyBinding := bindings[i]

		workerPool.Submit(func() {
			entityName := policyBinding.ResourceName
			policyName := policyBinding.PolicyName

			unparsedPolicyDocument, err := repo.getEntityPolicy(ctx, client, entityType, entityName, policyName)
			if err != nil {
				return
			}

			if unparsedPolicyDocument == nil {
				return
			}

			policy, policyReadable, err := repo.parsePolicyDocument(unparsedPolicyDocument, entityName, policyName)
			if err != nil || policy == nil {
				return
			}

			var policyType PolicyType
			var userPolicyBinding, groupPolicyBinding, rolePolicyBinding []PolicyBinding

			if entityType == UserResourceType {
				policyType = InlinePolicyUser

				userPolicyBinding = append(userPolicyBinding, PolicyBinding{ResourceName: entityName, Type: entityType})
			} else if entityType == GroupResourceType {
				policyType = InlinePolicyGroup

				groupPolicyBinding = append(groupPolicyBinding, PolicyBinding{ResourceName: entityName, Type: entityType})
			} else if entityType == RoleResourceType {
				policyType = InlinePolicyRole

				rolePolicyBinding = append(rolePolicyBinding, PolicyBinding{ResourceName: entityName, Type: entityType})
			}

			result = append(result, PolicyEntity{
				Name:           policyName,
				Description:    "inline policy",
				PolicyDocument: policyReadable,
				PolicyParsed:   policy,
				PolicyType:     policyType,
				InlineParent:   &entityName,
				UserBindings:   userPolicyBinding,
				GroupBindings:  groupPolicyBinding,
				RoleBindings:   rolePolicyBinding,
			})
		})
	}

	workerPool.StopWait()

	return result, nil
}

func (repo *AwsIamRepository) getUserInlinePolicyBindings(ctx context.Context, client *iam.Client, entityNames []string) ([]PolicyBinding, error) { //nolint:all // TODO no errors are indeed returned, find a way to do this
	var marker *string
	var policyBindings []PolicyBinding

	entityType := UserResourceType

	// TODO make number of workers configurable
	workerPool := workerpool.New(5)

	for i := range entityNames {
		entityName := entityNames[i]

		workerPool.Submit(func() {
			for {
				userPolicyInput := iam.ListUserPoliciesInput{
					UserName: &entityName,
					Marker:   marker,
				}

				resp, err := client.ListUserPolicies(ctx, &userPolicyInput)
				if err != nil {
					return
				}

				for ind := range resp.PolicyNames {
					policyBindings = append(policyBindings, PolicyBinding{
						PolicyName:   resp.PolicyNames[ind],
						ResourceName: entityName,
						Type:         entityType,
					})
				}

				if !resp.IsTruncated {
					break
				}
				marker = resp.Marker
			}
		})
	}

	workerPool.StopWait()

	return policyBindings, nil
}

func (repo *AwsIamRepository) getGroupInlinePolicyBindings(ctx context.Context, client *iam.Client, entityNames []string) ([]PolicyBinding, error) { //nolint: unparam
	var marker *string
	var policyBindings []PolicyBinding

	entityType := GroupResourceType

	// TODO make number of workers configurable
	workerPool := workerpool.New(5)

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
					return
				}

				for _, policyName := range resp.PolicyNames {
					policyBindings = append(policyBindings, PolicyBinding{
						PolicyName:   policyName,
						ResourceName: entityName,
						Type:         entityType,
					})
				}

				if !resp.IsTruncated {
					break
				}
				marker = resp.Marker
			}
		})
	}

	workerPool.StopWait()

	return policyBindings, nil
}

func (repo *AwsIamRepository) getRoleInlinePolicyBindings(ctx context.Context, client *iam.Client, entityNames []string) ([]PolicyBinding, error) { //nolint: unparam // TODO no errors are indeed returned, find a way to do this
	var marker *string
	var policyBindings []PolicyBinding

	entityType := RoleResourceType

	// TODO make number of workers configurable
	workerPool := workerpool.New(5)

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
					return
				}

				for _, policyName := range resp.PolicyNames {
					policyBindings = append(policyBindings, PolicyBinding{
						PolicyName:   policyName,
						ResourceName: entityName,
						Type:         entityType,
					})
				}

				if !resp.IsTruncated {
					break
				}
				marker = resp.Marker
			}
		})
	}

	workerPool.StopWait()

	return policyBindings, nil
}

func (repo *AwsIamRepository) getEntityPolicy(ctx context.Context, client *iam.Client, entityType, entityName, policyName string) (*string, error) {
	if strings.EqualFold(entityType, UserResourceType) {
		input := iam.GetUserPolicyInput{
			PolicyName: &policyName,
			UserName:   &entityName,
		}

		resp, err := client.GetUserPolicy(ctx, &input)
		if err != nil {
			logger.Info(fmt.Sprintf("error getting inline policy %s/%s: %s", entityName, policyName, err.Error()))
			return nil, err
		}

		if resp == nil || resp.PolicyDocument == nil {
			logger.Info(fmt.Sprintf("inline policy document is nil for %s %s/%s", entityType, entityName, policyName))
			return nil, err
		}

		return resp.PolicyDocument, nil
	} else if strings.EqualFold(entityType, GroupResourceType) {
		input := iam.GetGroupPolicyInput{
			PolicyName: &policyName,
			GroupName:  &entityName,
		}
		resp, err := client.GetGroupPolicy(ctx, &input)
		if err != nil {
			logger.Info(fmt.Sprintf("error getting inline policy %s/%s: %s", entityName, policyName, err.Error()))
			return nil, err
		}

		if resp == nil || resp.PolicyDocument == nil {
			logger.Info(fmt.Sprintf("inline policy document is nil for %s %s/%s", entityType, entityName, policyName))
			return nil, err
		}

		return resp.PolicyDocument, nil
	} else if strings.EqualFold(entityType, RoleResourceType) {
		input := iam.GetRolePolicyInput{
			PolicyName: &policyName,
			RoleName:   &entityName,
		}
		resp, err := client.GetRolePolicy(ctx, &input)
		if err != nil {
			logger.Info(fmt.Sprintf("error getting inline policy %s/%s: %s", entityName, policyName, err.Error()))
			return nil, err
		}

		if resp == nil || resp.PolicyDocument == nil {
			logger.Info(fmt.Sprintf("inline policy document is nil for %s %s/%s", entityType, entityName, policyName))
			return nil, err
		}

		return resp.PolicyDocument, nil
	}

	return nil, fmt.Errorf("entity type %s does not exist", entityType)
}

func (repo *AwsIamRepository) parsePolicyDocument(policyDoc *string, entityName, policyName string) (*awspolicy.Policy, *string, error) {
	if policyDoc == nil {
		return nil, nil, fmt.Errorf("policy document is nil for %s/%s", entityName, policyName)
	}

	var policy awspolicy.Policy

	policyDocument, err := url.QueryUnescape(*policyDoc)
	if err != nil {
		logger.Info(fmt.Sprintf("Failed to unescape policy document %s/%s: %s", entityName, policyName, *policyDoc))
		return nil, nil, err
	}

	err = policy.UnmarshalJSON([]byte(policyDocument))
	if err != nil {
		logger.Info(fmt.Sprintf("Failed to parse policy document %s/%s: %s", entityName, policyName, *policyDoc))
		return nil, nil, err
	}

	return &policy, &policyDocument, err
}
