package aws

import (
	"context"
	"fmt"

	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"

	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	is "github.com/raito-io/cli/base/identity_store"
)

//go:generate go run github.com/vektra/mockery/v2 --name=identityStoreRepository --with-expecter --inpackage
type identityStoreRepository interface {
	GetUsers(ctx context.Context, withDetails bool) ([]model.UserEntity, error)
	GetGroups(ctx context.Context) ([]model.GroupEntity, error)
	GetRoles(ctx context.Context) ([]model.RoleEntity, error)
}

type IdentityStoreSyncer struct {
	repoProvider func(configMap *config.ConfigMap) identityStoreRepository
}

func NewIdentityStoreSyncer() *IdentityStoreSyncer {
	return &IdentityStoreSyncer{repoProvider: newRepoProvider}
}

func (s *IdentityStoreSyncer) GetIdentityStoreMetaData(ctx context.Context, configParams *config.ConfigMap) (*is.MetaData, error) {
	utils.Logger.Debug("Returning meta data for AWS identity store")

	return &is.MetaData{
		Type: "aws-account",
	}, nil
}

func newRepoProvider(configMap *config.ConfigMap) identityStoreRepository {
	return iam.NewAwsIamRepository(configMap)
}

func (s *IdentityStoreSyncer) SyncIdentityStore(ctx context.Context, identityHandler wrappers.IdentityStoreIdentityHandler, configMap *config.ConfigMap) error {
	groups, err := s.repoProvider(configMap).GetGroups(ctx)
	if err != nil {
		return fmt.Errorf("get groups: %w", err)
	}

	userGroupMap := map[string][]string{}

	for _, g := range groups {
		err = identityHandler.AddGroups(&is.Group{
			ExternalId:  g.ExternalId,
			Name:        g.Name,
			DisplayName: g.Name,
			// ParentGroupExternalIds: nil, // AWS IAM doesn't support group hierarchies
		})
		if err != nil {
			return fmt.Errorf("add group to handler: %w", err)
		}

		for _, member := range g.Members {
			userGroupMap[member] = append(userGroupMap[member], g.ExternalId)
		}
	}

	// get users
	users, err := s.repoProvider(configMap).GetUsers(ctx, true)
	if err != nil {
		return fmt.Errorf("get users: %w", err)
	}

	for _, u := range users {
		err = identityHandler.AddUsers(&is.User{
			ExternalId:       u.ExternalId,
			UserName:         u.Name,
			Email:            u.Email,
			Name:             u.Name,
			Tags:             u.Tags,
			GroupExternalIds: userGroupMap[u.ExternalId],
		})
		if err != nil {
			return fmt.Errorf("add user to handler: %w", err)
		}
	}

	return nil
}
