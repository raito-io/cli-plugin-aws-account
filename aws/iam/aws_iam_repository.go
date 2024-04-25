package iam

import (
	"context"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	repo2 "github.com/raito-io/cli-plugin-aws-account/aws/repo"
	"github.com/raito-io/cli/base/util/config"
)

type AwsIamRepository struct {
	configMap   *config.ConfigMap
	account     string
	globalMutex sync.Mutex
}

func NewAwsIamRepository(configMap *config.ConfigMap) *AwsIamRepository {
	return &AwsIamRepository{
		configMap: configMap,
		account:   configMap.GetString(constants.AwsAccountId),
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
