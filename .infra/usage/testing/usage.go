package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iam_types "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/hashicorp/go-hclog"
)

var logger hclog.Logger

type ConfigItem struct {
	Arn  string `json:"arn"`
	Name string `json:"name"`
}

type UsageConfig struct {
	Groups struct {
		Value []struct {
			ConfigItem
		} `json:"value"`
	} `json:"groups"`
	User struct {
		Value []struct {
			UserConfig
		} `json:"value"`
	} `json:"user"`
}

type UserConfig struct {
	ConfigItem
	Secret struct {
		ConfigItem
	} `json:"secret"`
}

type UserSecret struct {
	UserName           string `json:"username"`
	AwsAccessKeyId     string `json:"AwsAccessKeyId"`
	AwsSecretAccessKey string `json:"AwsSecretAccessKey"`
}

var users = map[string]map[string][]string{
	//"m_carissa": { },
	"d_hayden": {"raito-data-corporate": {"sales/housing/prices/housing-prices-2023.parquet", "marketing/passengers/passengers.parquet"}},
}

func generateS3Usage(ctx context.Context, cfg *UsageConfig) error {
	repo := AwsS3Repository{}

	logger.Info("Generate usage data for S3")

	secretMap := map[string]*UserSecret{}

	for user, paths := range users {
		userCfg, ok := findUsageInCfg(cfg, user)
		if !ok {
			logger.Warn(fmt.Sprintf("User %q not found in config", user))

			continue
		}

		creds, ok := secretMap[user]
		if !ok {
			userSecret, err2 := repo.GetUserSecret(ctx, userCfg.Secret.Name)
			if err2 != nil {
				return fmt.Errorf("get user secret: %w", err2)
			}

			secretMap[user] = userSecret
			creds = userSecret
		}

		userRepo := AwsS3Repository{AwsAccessKeyId: aws.String(creds.AwsAccessKeyId), AwsSecretAccessKey: aws.String(creds.AwsSecretAccessKey)}

		logger.Info(fmt.Sprintf("Starting with queries for user %s", user))

		for bucket, files := range paths {
			for _, file := range files {
				_, fileError := userRepo.GetFile(ctx, bucket, file)
				if fileError != nil {
					logger.Error(fmt.Sprintf("Error fetching file %s/%s: %s", bucket, file, fileError.Error()))
				} else {
					logger.Info(fmt.Sprintf("File \"%s/%s\" fetched successfully", bucket, file))
				}
			}

		}
	}

	//err := repo.DeactivateKeys(ctx, secretMap)
	//if err != nil {
	//	return err
	//}

	return nil
}

func findUsageInCfg(cfg *UsageConfig, user string) (*UserConfig, bool) {
	for i, u := range cfg.User.Value {
		if u.Name == user {
			return &cfg.User.Value[i].UserConfig, true
		}
	}

	return nil, false
}

func main() {
	logger = hclog.New(&hclog.LoggerOptions{Name: "usage-logger", Level: hclog.Info})
	ctx := context.Background()

	info, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if info.Mode()&os.ModeCharDevice != 0 {
		fmt.Println("The command is intended to work with pipes.")
		return
	}

	dec := json.NewDecoder(os.Stdin)

	usageConfig := UsageConfig{}

	err = dec.Decode(&usageConfig)
	if err != nil {
		panic(err)
	}

	err = generateS3Usage(ctx, &usageConfig)
	if err != nil {
		logger.Error("Failed to generate usage data", "error", err.Error())
		os.Exit(1)
	}

	logger.Info("Usage data generated successfully")
}

type AwsS3Repository struct {
	AwsAccessKeyId     *string
	AwsSecretAccessKey *string
}

func (repo *AwsS3Repository) GetS3Client(ctx context.Context, region *types.BucketLocationConstraint) (*s3.Client, error) {
	awsRegion := "eu-central-1"
	if region != nil && *region == "" {
		awsRegion = "us-east-1"
	} else if region != nil {
		awsRegion = string(*region)
	}

	cfg, err := aws_config.LoadDefaultConfig(ctx, aws_config.WithRegion(awsRegion))

	if repo.AwsAccessKeyId != nil && repo.AwsSecretAccessKey != nil {
		creds := credentials.NewStaticCredentialsProvider(*repo.AwsAccessKeyId, *repo.AwsSecretAccessKey, "")
		cfg, err = aws_config.LoadDefaultConfig(ctx, aws_config.WithRegion(awsRegion), aws_config.WithCredentialsProvider(creds))
	}

	if err != nil {
		log.Fatalf("failed to load configuration, %s", err.Error())
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	return client, nil
}

func (repo *AwsS3Repository) GetIamClient(ctx context.Context, region *types.BucketLocationConstraint) (*iam.Client, error) {
	awsRegion := "eu-central-1"
	if region != nil && *region == "" {
		awsRegion = "us-east-1"
	} else if region != nil {
		awsRegion = string(*region)
	}

	cfg, err := aws_config.LoadDefaultConfig(ctx, aws_config.WithRegion(awsRegion))

	if repo.AwsAccessKeyId != nil && repo.AwsSecretAccessKey != nil {
		creds := credentials.NewStaticCredentialsProvider(*repo.AwsAccessKeyId, *repo.AwsSecretAccessKey, "")
		cfg, err = aws_config.LoadDefaultConfig(ctx, aws_config.WithRegion(awsRegion), aws_config.WithCredentialsProvider(creds))
	}

	if err != nil {
		log.Fatalf("failed to load configuration, %s", err.Error())
	}

	client := iam.NewFromConfig(cfg)

	return client, nil
}

func (repo *AwsS3Repository) GetSecretsClient(ctx context.Context, region *types.BucketLocationConstraint) (*secretsmanager.Client, error) {
	awsRegion := "eu-central-1"
	if region != nil && *region == "" {
		awsRegion = "us-east-1"
	} else if region != nil {
		awsRegion = string(*region)
	}

	cfg, err := aws_config.LoadDefaultConfig(ctx, aws_config.WithRegion(awsRegion))

	if repo.AwsAccessKeyId != nil && repo.AwsSecretAccessKey != nil {
		creds := credentials.NewStaticCredentialsProvider(*repo.AwsAccessKeyId, *repo.AwsSecretAccessKey, "")
		cfg, err = aws_config.LoadDefaultConfig(ctx, aws_config.WithRegion(awsRegion), aws_config.WithCredentialsProvider(creds))
	}

	if err != nil {
		log.Fatalf("failed to load configuration, %s", err.Error())
	}

	client := secretsmanager.NewFromConfig(cfg)

	return client, nil
}

func (repo *AwsS3Repository) GetFile(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	client, err := repo.GetS3Client(ctx, nil)
	if err != nil {
		return nil, err
	}

	input := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}
	output, err := client.GetObject(ctx, input)

	if err != nil {
		return nil, err
	}

	return output.Body, nil
}

func (repo *AwsS3Repository) GetUserSecret(ctx context.Context, secretId string) (*UserSecret, error) {
	client, err := repo.GetSecretsClient(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get secret manager client: %w", err)
	}

	res, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretId),
	})

	if err != nil {
		return nil, fmt.Errorf("get secret value: %w", err)
	}

	secret := UserSecret{}
	err = json.Unmarshal([]byte(*res.SecretString), &secret)
	if err != nil {
		return nil, fmt.Errorf("unmarshal secret: %w", err)
	}

	return &secret, nil
}

func (repo *AwsS3Repository) ActivateKey(ctx context.Context, userName, key string) error {
	iamClient, err := repo.GetIamClient(ctx, nil)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Activating access key for user: %s", userName))

	_, err = iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		UserName:    &userName,
		AccessKeyId: &key,
		Status:      iam_types.StatusTypeActive,
	})
	if err != nil {
		return err
	}

	for i := 0; i < 10; i++ {
		res, _ := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: &userName,
		})

		if res.AccessKeyMetadata[0].Status == iam_types.StatusTypeActive {
			logger.Info(fmt.Sprintf("Access key for user %s activated, waiting 15 seconds to make sure it's actually active", userName))
			time.Sleep(time.Second * 15)
			break
		}

		time.Sleep(time.Second * 1)
	}

	return nil
}

func (repo *AwsS3Repository) DeactivateKeys(ctx context.Context, secretMap map[string]*UserSecret) error {
	iamClient, err := repo.GetIamClient(ctx, nil)
	if err != nil {
		return err
	}

	for user, keys := range secretMap {
		logger.Info(fmt.Sprintf("Deactivating key for user %s", user))

		_, err = iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
			UserName:    &user,
			AccessKeyId: &keys.AwsAccessKeyId,
			Status:      iam_types.StatusTypeInactive,
		})

		if err != nil {
			return err
		}
	}

	return nil
}

type AwsS3Entity struct {
	Type      string
	Key       string
	ParentKey string
}
