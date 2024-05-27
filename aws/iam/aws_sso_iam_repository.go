package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
)

type AwsSsoIamRepository struct {
	configMap   *config.ConfigMap
	account     string
	instanceArn string
	client      *ssoadmin.Client
}

func NewAwsSsoIamRepository(configMap *config.ConfigMap, account string, client *ssoadmin.Client) (*AwsSsoIamRepository, error) {
	instanceArn := configMap.GetStringWithDefault(constants.AwsOrganizationIdentityCenterInstanceArn, "")
	if instanceArn == "" {
		return nil, errors.New("SSO instance ARN is not set")
	}

	return &AwsSsoIamRepository{
		configMap:   configMap,
		account:     account,
		instanceArn: instanceArn,
		client:      client,
	}, nil
}

func (repo *AwsSsoIamRepository) CreateSsoRole(ctx context.Context, name, description string) (arn string, err error) {
	permissionSet, err := repo.client.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{
		InstanceArn: &repo.instanceArn,
		Name:        &name,
		Description: &description,
		Tags: []ssoTypes.Tag{
			{
				Key:   aws.String("creator"),
				Value: aws.String("RAITO"),
			},
		},
	})

	if err != nil {
		return "", fmt.Errorf("create permission set: %w", err)
	}

	return *permissionSet.PermissionSet.PermissionSetArn, nil
}

func (repo *AwsSsoIamRepository) UpdateSsoRole(ctx context.Context, arn string, description string) error {
	_, err := repo.client.UpdatePermissionSet(ctx, &ssoadmin.UpdatePermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &arn,
		Description:      &description,
	})

	if err != nil {
		return fmt.Errorf("update permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) GetSsoRole(ctx context.Context, permissionSetArn string) (*ssoTypes.PermissionSet, error) {
	permissionSet, err := repo.client.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
	})

	if err != nil {
		return nil, fmt.Errorf("describe permission set: %w", err)
	}

	return permissionSet.PermissionSet, nil
}

func (repo *AwsSsoIamRepository) DeleteSsoRole(ctx context.Context, permissionSetArn string) error {
	_, err := repo.client.DeletePermissionSet(ctx, &ssoadmin.DeletePermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
	})

	if err != nil {
		return fmt.Errorf("delete permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) AssignPermissionSet(ctx context.Context, permissionSetArn string, principalType ssoTypes.PrincipalType, principal string) error {
	_, err := repo.client.CreateAccountAssignment(ctx, &ssoadmin.CreateAccountAssignmentInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		PrincipalId:      &principal,
		PrincipalType:    principalType,
		TargetId:         &repo.account,
		TargetType:       ssoTypes.TargetTypeAwsAccount,
	})

	if err != nil {
		return fmt.Errorf("create account assignment: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) UnassignPermissionSet(ctx context.Context, permissionSetArn string, principalType ssoTypes.PrincipalType, principal string) error {
	_, err := repo.client.DeleteAccountAssignment(ctx, &ssoadmin.DeleteAccountAssignmentInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		PrincipalId:      &principal,
		PrincipalType:    principalType,
		TargetId:         &repo.account,
		TargetType:       ssoTypes.TargetTypeAwsAccount,
	})

	if err != nil {
		return fmt.Errorf("create account assignment: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) ProvisionPermissionSet(ctx context.Context, permissionSetArn string) error {
	_, err := repo.client.ProvisionPermissionSet(ctx, &ssoadmin.ProvisionPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		TargetType:       ssoTypes.ProvisionTargetTypeAllProvisionedAccounts,
	})

	if err != nil {
		return fmt.Errorf("provision permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) AttachAwsManagedPolicyToPermissionSet(ctx context.Context, permissionSetArn string, policyArn string) error {
	_, err := repo.client.AttachManagedPolicyToPermissionSet(ctx, &ssoadmin.AttachManagedPolicyToPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		ManagedPolicyArn: &policyArn,
	})

	if err != nil {
		return fmt.Errorf("attach managed policy to permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) DetachAwsManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string, policyArn string) error {
	_, err := repo.client.DetachManagedPolicyFromPermissionSet(ctx, &ssoadmin.DetachManagedPolicyFromPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		ManagedPolicyArn: &policyArn,
	})

	if err != nil {
		return fmt.Errorf("detach managed policy from permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) ListAwsManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string) (set.Set[string], error) {
	result := set.NewSet[string]()

	iterator := ssoadmin.NewListManagedPoliciesInPermissionSetPaginator(repo.client, &ssoadmin.ListManagedPoliciesInPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
	})

	for iterator.HasMorePages() {
		page, err := iterator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list managed policies in permission set: %w", err)
		}

		for _, policy := range page.AttachedManagedPolicies {
			result.Add(*policy.Name)
		}
	}

	return result, nil
}

func (repo *AwsSsoIamRepository) AttachCustomerManagedPolicyToPermissionSet(ctx context.Context, permissionSetArn string, name string, path *string) error {
	_, err := repo.client.AttachCustomerManagedPolicyReferenceToPermissionSet(ctx, &ssoadmin.AttachCustomerManagedPolicyReferenceToPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
			Name: &name,
			Path: path,
		},
	})

	if err != nil {
		return fmt.Errorf("attach managed policy to permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) DetachCustomerManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string, name string, path *string) error {
	_, err := repo.client.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx, &ssoadmin.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
			Name: &name,
			Path: path,
		},
	})

	if err != nil {
		return fmt.Errorf("detach managed policy from permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) ListCustomerManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string) (set.Set[string], error) {
	result := set.NewSet[string]()

	iterator := ssoadmin.NewListManagedPoliciesInPermissionSetPaginator(repo.client, &ssoadmin.ListManagedPoliciesInPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
	})

	for iterator.HasMorePages() {
		page, err := iterator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list managed policies in permission set: %w", err)
		}

		for _, policy := range page.AttachedManagedPolicies {
			result.Add(*policy.Name)
		}
	}

	return result, nil
}

func (repo *AwsSsoIamRepository) UpdateInlinePolicyToPermissionSet(ctx context.Context, permissionSetArn string, statements []*awspolicy.Statement) error {
	_, err := repo.client.DeleteInlinePolicyFromPermissionSet(ctx, &ssoadmin.DeleteInlinePolicyFromPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
	})
	if err != nil {
		return fmt.Errorf("delete inline policy from permission set: %w", err)
	}

	if len(statements) == 0 {
		return nil
	}

	policyDoc, err := createPolicyDocument(statements)
	if err != nil {
		return fmt.Errorf("create policy document: %w", err)
	}

	_, err = repo.client.PutInlinePolicyToPermissionSet(ctx, &ssoadmin.PutInlinePolicyToPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		InlinePolicy:     &policyDoc,
	})

	if err != nil {
		return fmt.Errorf("put inline policy to permission set: %w", err)
	}

	return nil
}
