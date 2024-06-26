package iam

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/raito-io/cli/base/util/config"

	repo2 "github.com/raito-io/cli-plugin-aws-account/aws/repo"
)

type AwsIamRepository struct {
	configMap *config.ConfigMap
	account   string
}

func NewAwsIamRepository(configMap *config.ConfigMap) *AwsIamRepository {
	account, err := repo2.GetAccountId(context.Background(), configMap)
	if err != nil {
		log.Fatalf("failed to get account id: %s", err.Error())
	}

	return &AwsIamRepository{
		configMap: configMap,
		account:   account,
	}
}

func (repo *AwsIamRepository) GetConfig() *config.ConfigMap {
	return repo.configMap
}

func (repo *AwsIamRepository) GetIamClient(ctx context.Context) (*iam.Client, error) {
	cfg, err := repo2.GetAWSConfig(ctx, repo.configMap, nil)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := iam.NewFromConfig(cfg)

	return client, nil
}

func (repo *AwsIamRepository) GetIamOrgClient(ctx context.Context) (*iam.Client, error) {
	cfg, err := repo2.GetAWSOrgConfig(ctx, repo.configMap, nil)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := iam.NewFromConfig(cfg)

	return client, nil
}

func NewSsoClient(ctx context.Context, cfgMap *config.ConfigMap, account string) (*AwsSsoIamRepository, error) {
	cfg, err := repo2.GetAWSOrgConfig(ctx, cfgMap, nil)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := ssoadmin.NewFromConfig(cfg)
	identityClient := identitystore.NewFromConfig(cfg)

	return NewAwsSsoIamRepository(cfgMap, account, client, identityClient)
}
