package aws

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/raito-io/cli/base/util/config"
)

type AwsIamRepository struct {
}

func (repo *AwsIamRepository) GetIamClient(ctx context.Context, configMap *config.ConfigMap) (*iam.Client, error) {
	cfg, err := GetAWSConfig(ctx, configMap, nil)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := iam.NewFromConfig(cfg)

	return client, nil
}

func (repo *AwsIamRepository) GetIamOrgClient(ctx context.Context, configMap *config.ConfigMap) (*iam.Client, error) {
	cfg, err := GetAWSOrgConfig(ctx, configMap, nil)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := iam.NewFromConfig(cfg)

	return client, nil
}
