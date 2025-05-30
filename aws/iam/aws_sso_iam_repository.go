package iam

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	awspolicy "github.com/raito-io/cli-plugin-aws-account/aws/policy"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils/bimap"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/golang-set/set"
	"go.uber.org/ratelimit"
)

type AwsSsoIamRepository struct {
	configMap       *config.ConfigMap
	account         string
	instanceArn     string
	identityStoreId string

	client         *ssoadmin.Client
	identityClient *identitystore.Client

	// Cache
	users     bimap.Bimap[string, string]
	groups    bimap.Bimap[string, string]
	tagsCache map[string][]ssoTypes.Tag

	listTagsLimiter ratelimit.Limiter
	tagsCacheLock   sync.RWMutex
}

func NewAwsSsoIamRepository(configMap *config.ConfigMap, account string, client *ssoadmin.Client, identityStoreClient *identitystore.Client) (*AwsSsoIamRepository, error) {
	instanceArn := configMap.GetStringWithDefault(constants.AwsOrganizationIdentityCenterInstanceArn, "")
	if instanceArn == "" {
		return nil, errors.New("SSO instance ARN is not set")
	}

	identityStoreId := configMap.GetStringWithDefault(constants.AwsOrganizationIdentityStore, "")
	if identityStoreId == "" {
		return nil, errors.New("SSO identity store ID is not set")
	}

	return &AwsSsoIamRepository{
		configMap:       configMap,
		account:         account,
		instanceArn:     instanceArn,
		identityStoreId: identityStoreId,
		client:          client,
		identityClient:  identityStoreClient,
		tagsCache:       make(map[string][]ssoTypes.Tag),
		listTagsLimiter: ratelimit.New(15),
	}, nil
}

func (repo *AwsSsoIamRepository) CreateSsoRole(ctx context.Context, name, description string, tags map[string]string) (arn string, err error) {
	pmTags := make([]ssoTypes.Tag, 0, len(tags))

	for k, v := range tags {
		pmTags = append(pmTags, ssoTypes.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		})
	}

	utils.Logger.Info(fmt.Sprintf("Creating permission set with name: %s, description: %s, tags: %+v", name, description, tags))

	permissionSet, err := repo.client.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{
		InstanceArn: &repo.instanceArn,
		Name:        &name,
		Description: &description,
		Tags:        pmTags,
	})

	if err != nil {
		return "", fmt.Errorf("create permission set: %w", err)
	}

	return *permissionSet.PermissionSet.PermissionSetArn, nil
}

// new method with caching
func (repo *AwsSsoIamRepository) listTagsForResource(ctx context.Context, resourceArn string) ([]ssoTypes.Tag, error) {
	repo.tagsCacheLock.RLock()
	tags, found := repo.tagsCache[resourceArn]
	repo.tagsCacheLock.RUnlock()

	if found {
		utils.Logger.Debug(fmt.Sprintf("Cache hit for tags on resource %s", resourceArn))
		return tags, nil
	}

	utils.Logger.Debug(fmt.Sprintf("Cache miss for tags on resource %s, fetching from AWS", resourceArn))

	repo.listTagsLimiter.Take() // Apply rate limiting before calling the AWS API

	result, err := repo.client.ListTagsForResource(ctx, &ssoadmin.ListTagsForResourceInput{
		InstanceArn: &repo.instanceArn,
		ResourceArn: &resourceArn,
	})
	if err != nil {
		return nil, fmt.Errorf("list tags for resource %s: %w", resourceArn, err)
	}

	repo.tagsCacheLock.Lock()
	repo.tagsCache[resourceArn] = result.Tags
	repo.tagsCacheLock.Unlock()

	utils.Logger.Debug(fmt.Sprintf("Cached %d tags for resource %s", len(result.Tags), resourceArn))

	return result.Tags, nil
}

func (repo *AwsSsoIamRepository) UpdateSsoRole(ctx context.Context, arn string, description string, tags map[string]string) error {
	// Update the permission set description
	_, err := repo.client.UpdatePermissionSet(ctx, &ssoadmin.UpdatePermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &arn,
		Description:      &description,
	})

	if err != nil {
		return fmt.Errorf("update permission set: %w", err)
	}

	// Fetch existing tags
	var fetchedTags []ssoTypes.Tag
	fetchedTags, err = repo.listTagsForResource(ctx, arn) // Use new method, assign to existing err
	if err != nil {
		return fmt.Errorf("list tags for resource: %w", err)
	}

	// Create maps for existing tags
	existingTags := make(map[string]string)

	for _, tag := range fetchedTags {
		existingTags[*tag.Key] = *tag.Value
	}

	// Determine tags to add or update
	tagsToUpsert := make([]ssoTypes.Tag, 0)

	for key, value := range tags {
		existingValue, exists := existingTags[key]

		if !exists || existingValue != value {
			tagsToUpsert = append(tagsToUpsert, ssoTypes.Tag{
				Key:   aws.String(key),
				Value: aws.String(value),
			})
		}
	}

	// Apply tag changes - only add or update tags, don't remove any
	if len(tagsToUpsert) > 0 {
		_, err = repo.client.TagResource(ctx, &ssoadmin.TagResourceInput{
			InstanceArn: &repo.instanceArn,
			ResourceArn: &arn,
			Tags:        tagsToUpsert,
		})
		if err != nil {
			return fmt.Errorf("tag resource: %w", err)
		}

		// Invalidate cache for this resource ARN as tags have been updated
		repo.tagsCacheLock.Lock()
		delete(repo.tagsCache, arn)
		repo.tagsCacheLock.Unlock()
		utils.Logger.Debug(fmt.Sprintf("Invalidated tags cache for resource %s due to update", arn))
	}

	return nil
}

func (repo *AwsSsoIamRepository) HasRaitoCreatedTag(ctx context.Context, permissionSetArn string) (bool, error) {
	fetchedTags, err := repo.listTagsForResource(ctx, permissionSetArn) // Use new method, new err declaration
	if err != nil {
		return false, fmt.Errorf("list tags for resource: %w", err)
	}

	for _, tag := range fetchedTags {
		if *tag.Key == "creator" && *tag.Value == "RAITO" {
			return true, nil
		}
	}

	return false, nil
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
	assignments, err := repo.ListPermissionSetAssignment(ctx, permissionSetArn)
	if err != nil {
		return fmt.Errorf("list permission set assignment: %w", err)
	}

	for _, assignment := range assignments {
		err = repo.UnassignPermissionSet(ctx, permissionSetArn, assignment.PrincipalType, *assignment.PrincipalId)
		if err != nil {
			return fmt.Errorf("unassign permission set: %w", err)
		}
	}

	if len(assignments) > 0 {
		err = repo.ProvisionPermissionSetAndWait(ctx, permissionSetArn)
		if err != nil {
			return fmt.Errorf("provision permission set: %w", err)
		}
	}

	_, err = repo.client.DeletePermissionSet(ctx, &ssoadmin.DeletePermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
	})

	if err != nil {
		return fmt.Errorf("delete permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) ListSsoRoles(ctx context.Context) ([]string, error) {
	result := make([]string, 0)

	utils.Logger.Info("Listing all permission sets")

	iterator := ssoadmin.NewListPermissionSetsPaginator(repo.client, &ssoadmin.ListPermissionSetsInput{
		InstanceArn: &repo.instanceArn,
	})

	utils.Logger.Info("Got iterator for permission sets")

	for iterator.HasMorePages() {
		page, err := iterator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list permission sets: %w", err)
		}

		utils.Logger.Info("Got next page for permission sets")

		result = append(result, page.PermissionSets...)
	}

	return result, nil
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
		return fmt.Errorf("delete account assignment: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) ListPermissionSetAssignment(ctx context.Context, permissionSetArn string) ([]ssoTypes.AccountAssignment, error) {
	result := make([]ssoTypes.AccountAssignment, 0)

	iterator := ssoadmin.NewListAccountAssignmentsPaginator(repo.client, &ssoadmin.ListAccountAssignmentsInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		AccountId:        &repo.account,
	})

	for iterator.HasMorePages() {
		page, err := iterator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list account assignments: %w", err)
		}

		result = append(result, page.AccountAssignments...)
	}

	return result, nil
}

func (repo *AwsSsoIamRepository) ProvisionPermissionSet(ctx context.Context, permissionSetArn string) (*ssoTypes.PermissionSetProvisioningStatus, error) {
	r, err := repo.client.ProvisionPermissionSet(ctx, &ssoadmin.ProvisionPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		TargetType:       ssoTypes.ProvisionTargetTypeAllProvisionedAccounts,
	})

	if err != nil {
		return nil, fmt.Errorf("provision permission set: %w", err)
	}

	return r.PermissionSetProvisioningStatus, nil
}

func (repo *AwsSsoIamRepository) ProvisionPermissionSetAndWait(ctx context.Context, permissionSetArn string) error {
	d := 100 * time.Millisecond

	provisionResult, err := repo.ProvisionPermissionSet(ctx, permissionSetArn)
	if err != nil {
		return fmt.Errorf("provision permission set: %w", err)
	}

	if provisionResult.Status != ssoTypes.StatusValuesInProgress {
		return nil
	}

	getStatus := func() (ssoTypes.StatusValues, error) {
		status, err2 := repo.client.DescribePermissionSetProvisioningStatus(ctx, &ssoadmin.DescribePermissionSetProvisioningStatusInput{
			InstanceArn:                     &repo.instanceArn,
			ProvisionPermissionSetRequestId: provisionResult.RequestId,
		})

		if err2 != nil {
			return ssoTypes.StatusValuesFailed, fmt.Errorf("describe permission set provisioning status: %w", err)
		}

		return status.PermissionSetProvisioningStatus.Status, nil
	}

	ticker := time.NewTicker(d)

	for {
		select {
		case <-ctx.Done():
			return errors.New("context cancelled")
		case <-ticker.C:
			var status ssoTypes.StatusValues

			status, err = getStatus()
			if err != nil {
				return fmt.Errorf("get status: %w", err)
			}

			if status != ssoTypes.StatusValuesInProgress {
				return nil
			}

			ticker.Reset(d)
		}
	}
}

func (repo *AwsSsoIamRepository) AttachAwsManagedPolicyToPermissionSet(ctx context.Context, permissionSetArn string, policyArn string) error {
	_, err := repo.client.AttachManagedPolicyToPermissionSet(ctx, &ssoadmin.AttachManagedPolicyToPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
		ManagedPolicyArn: &policyArn,
	})

	if err != nil {
		return fmt.Errorf("attach aws managed policy to permission set: %w", err)
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
		return fmt.Errorf("detach aws managed policy from permission set: %w", err)
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
		return fmt.Errorf("attach customer managed policy to permission set: %w", err)
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
		return fmt.Errorf("detach customer managed policy from permission set: %w", err)
	}

	return nil
}

func (repo *AwsSsoIamRepository) ListCustomerManagedPolicyFromPermissionSet(ctx context.Context, permissionSetArn string) (set.Set[string], error) {
	result := set.NewSet[string]()

	iterator := ssoadmin.NewListCustomerManagedPolicyReferencesInPermissionSetPaginator(repo.client, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{
		InstanceArn:      &repo.instanceArn,
		PermissionSetArn: &permissionSetArn,
	})

	for iterator.HasMorePages() {
		page, err := iterator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list managed policies in permission set: %w", err)
		}

		for _, policy := range page.CustomerManagedPolicyReferences {
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

func (repo *AwsSsoIamRepository) GetUsers(ctx context.Context) (bimap.Bimap[string, string], error) {
	if repo.users.IsInitialized() {
		return repo.users, nil
	}

	users := make(map[string]string)

	iterator := identitystore.NewListUsersPaginator(repo.identityClient, &identitystore.ListUsersInput{
		IdentityStoreId: &repo.identityStoreId,
	})

	for iterator.HasMorePages() {
		page, err := iterator.NextPage(ctx)
		if err != nil {
			return bimap.Bimap[string, string]{}, fmt.Errorf("list users page: %w", err)
		}

		for i := range page.Users {
			users[*page.Users[i].UserId] = *page.Users[i].UserName
		}
	}

	repo.users = bimap.Of(users)

	utils.Logger.Info(fmt.Sprintf("Found SSO Users: %+v", repo.users.ForwardMap()))

	return repo.users, nil
}

func (repo *AwsSsoIamRepository) GetGroups(ctx context.Context) (bimap.Bimap[string, string], error) {
	if repo.groups.IsInitialized() {
		return repo.groups, nil
	}

	groups := make(map[string]string)

	iterator := identitystore.NewListGroupsPaginator(repo.identityClient, &identitystore.ListGroupsInput{
		IdentityStoreId: &repo.identityStoreId,
	})

	for iterator.HasMorePages() {
		page, err := iterator.NextPage(ctx)
		if err != nil {
			return bimap.Bimap[string, string]{}, fmt.Errorf("list groups page: %w", err)
		}

		for _, group := range page.Groups {
			groups[*group.GroupId] = *group.DisplayName
		}
	}

	repo.groups = bimap.Of(groups)

	utils.Logger.Info(fmt.Sprintf("Found SSO Groups: %+v", repo.groups.ForwardMap()))

	return repo.groups, nil
}
