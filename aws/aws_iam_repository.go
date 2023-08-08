package aws

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/raito-io/cli/base/util/config"
)

type AwsIamRepository struct {
	ConfigMap *config.ConfigMap
}

func (repo *AwsIamRepository) GetIamClient(ctx context.Context) (*iam.Client, error) {
	cfg, err := GetAWSConfig(ctx, repo.ConfigMap, nil)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := iam.NewFromConfig(cfg)

	return client, nil
}

func (repo *AwsIamRepository) GetIamOrgClient(ctx context.Context) (*iam.Client, error) {
	cfg, err := GetAWSOrgConfig(ctx, repo.ConfigMap, nil)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := iam.NewFromConfig(cfg)

	return client, nil
}
