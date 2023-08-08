package aws

import (
	"context"

	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers"

	is "github.com/raito-io/cli/base/identity_store"
)

//go:generate go run github.com/vektra/mockery/v2 --name=identityStoreRepository --with-expecter --inpackage
type identityStoreRepository interface {
	GetUsers(ctx context.Context, withDetails bool) ([]UserEntity, error)
	GetGroups(ctx context.Context) ([]GroupEntity, error)
	GetRoles(ctx context.Context) ([]RoleEntity, error)
}

type IdentityStoreSyncer struct {
	repoProvider func(configMap *config.ConfigMap) identityStoreRepository
}

func NewIdentityStoreSyncer() *IdentityStoreSyncer {
	return &IdentityStoreSyncer{repoProvider: newRepoProvider}
}

func (s *IdentityStoreSyncer) GetIdentityStoreMetaData(ctx context.Context) (*is.MetaData, error) {
	logger.Debug("Returning meta data for AWS identity store")

	return &is.MetaData{
		Type: "aws-account",
	}, nil
}

func newRepoProvider(configMap *config.ConfigMap) identityStoreRepository {
	return &AwsIamRepository{
		ConfigMap: configMap,
	}
}

func (s *IdentityStoreSyncer) SyncIdentityStore(ctx context.Context, identityHandler wrappers.IdentityStoreIdentityHandler, configMap *config.ConfigMap) error {
	groups, err := s.repoProvider(configMap).GetGroups(ctx)
	if err != nil {
		return err
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
			return err
		}

		for _, member := range g.Members {
			userGroupMap[member] = append(userGroupMap[member], g.ExternalId)
		}
	}

	// get users
	users, err := s.repoProvider(configMap).GetUsers(ctx, true)
	if err != nil {
		return err
	}

	for _, u := range users {
		// TODO: figure out what the best mapping is here. No email for AWS users.
		err = identityHandler.AddUsers(&is.User{
			ExternalId:       u.ExternalId,
			UserName:         u.Name,
			Email:            u.Email,
			Name:             u.Name,
			Tags:             u.Tags,
			GroupExternalIds: userGroupMap[u.ExternalId],
		})
		if err != nil {
			return err
		}
	}

	return nil
}
