package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
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
	"github.com/raito-io/golang-set/set"
)

var logger hclog.Logger

var users = map[string][]string{
	//"m_carissa": { },
	"d_hayden": {"sales/housing/prices/housing-prices-2023.parquet", "marketing/passengers/passengers.parquet"},
}

func generateS3Usage() error {
	ctx := context.Background()
	repo := AwsS3Repository{}

	logger.Info("Generate usage data for S3")

	secretMap := map[string]AwsAccessKey{}

	includeList := []string{"raito-corporate-data"}
	buckets, err := repo.ListBuckets(ctx, includeList)
	if err != nil {
		return err
	}

	fileMap := map[string][]AwsS3Entity{}
	for _, bucket := range buckets {
		files, err := repo.ListFiles(ctx, bucket.Key, nil)
		if err != nil {
			return err
		}
		fileMap[bucket.Key] = files
	}

	for user, paths := range users {
		/*err = repo.CreateOrFetchUserSecret(ctx, user, secretMap)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to create or fetch user secret: %v", err))
			return err
		}*/

		/*creds, ok := secretMap[user]
		if !ok {
			logger.Warn(fmt.Sprintf("Credentials not found for user %s", user))
			continue
		}*/

		//userRepo := AwsS3Repository{AwsAccessKeyId: aws.String(creds.AwsAccessKeyId), AwsSecretAccessKey: aws.String(creds.AwsSecretAccessKey)}

		logger.Info(fmt.Sprintf("Starting with queries for user %s", user))

		for _, path := range paths {
			_, fileError := repo.GetFile(ctx, "raito-corporate-data", path)
			if fileError != nil {
				logger.Error(fmt.Sprintf("Error fetching file %s: %s", path, fileError.Error()))
			} else {
				logger.Info(fmt.Sprintf("File %q fetched successfully", path))
			}
		}
	}

	err = repo.DeactivateKeys(ctx, secretMap)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	logger = hclog.New(&hclog.LoggerOptions{Name: "usage-logger", Level: hclog.Info})

	err := generateS3Usage()
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

func (repo *AwsS3Repository) ListBuckets(ctx context.Context, includeList []string) ([]AwsS3Entity, error) {
	client, err := repo.GetS3Client(ctx, nil)
	if err != nil {
		return nil, err
	}

	output, err := client.ListBuckets(ctx, nil)
	if err != nil {
		return nil, err
	}

	// TODO; get tags from buckets

	result := []AwsS3Entity{}

	for _, bucket := range output.Buckets {

		logger.Info(fmt.Sprintf("Found bucket: %s", *bucket.Name))

		ignoreBucket := true
		for _, bucketToIgnore := range includeList {
			if strings.EqualFold(*bucket.Name, bucketToIgnore) {
				logger.Info(fmt.Sprintf("Ignoring bucket: %s", *bucket.Name))
				ignoreBucket = false
				continue
			}
		}

		if ignoreBucket {
			continue
		}

		result = append(result, AwsS3Entity{
			Key:  *bucket.Name,
			Type: "bucket",
		})
	}

	return result, nil
}

func (repo *AwsS3Repository) ListFiles(ctx context.Context, bucket string, prefix *string) ([]AwsS3Entity, error) {
	logger.Info(fmt.Sprintf("Fetching files from bucket %s", bucket))

	bucketClient, err := repo.GetS3Client(ctx, nil)
	if err != nil {
		return nil, err
	}

	bucketInfo, err := bucketClient.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: &bucket})
	if err != nil {
		return nil, err
	}

	bucketLocation := bucketInfo.LocationConstraint
	logger.Info(fmt.Sprintf("Location of bucket %q is %s", bucket, bucketLocation))

	client, err := repo.GetS3Client(ctx, &bucketLocation)
	if err != nil {
		return nil, err
	}

	moreObjectsAvailable := true
	var continuationToken *string
	var result []AwsS3Entity

	for moreObjectsAvailable {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			ContinuationToken: continuationToken,
			Prefix:            prefix,
		}

		response, err := client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, err
		}

		moreObjectsAvailable = *response.IsTruncated
		continuationToken = response.NextContinuationToken

		for _, object := range response.Contents {
			result = append(result, AwsS3Entity{
				Key:       *object.Key,
				Type:      "file",
				ParentKey: bucket,
			})
		}
	}

	return result, nil
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

func (repo *AwsS3Repository) CreateOrFetchUserSecret(ctx context.Context, user string, secretMap map[string]AwsAccessKey) error {
	secretsClient, err := repo.GetSecretsClient(ctx, nil)
	if err != nil {
		return err
	}

	res, err := secretsClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(fmt.Sprintf("demo/%s", user)),
	})

	if err != nil || res.SecretString == nil {
		logger.Warn(fmt.Sprintf("Failed to get secret for user '%s', creating...: %s", user, err.Error()))
		return repo.CreateAndStoreKey(ctx, user, secretMap)
	}

	secretParsed := AwsAccessKey{}
	err = json.Unmarshal([]byte(*res.SecretString), &secretParsed)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to parse secret: %s", err.Error()))
		return err
	}

	if secretParsed.AwsAccessKeyId == "" || secretParsed.AwsSecretAccessKey == "" {
		return errors.New("failed to parse secret")
	}

	secretMap[user] = secretParsed

	existingKeys, err := repo.ListKeys(ctx, user)
	if err != nil {
		return err
	}

	if !existingKeys.Contains(secretParsed.AwsAccessKeyId) {
		logger.Warn(fmt.Sprintf("Key stored in secrets for user %s not found among user keys", user))
		return repo.CreateAndStoreKey(ctx, user, secretMap)
	}

	err = repo.ActivateKey(ctx, user, secretParsed.AwsAccessKeyId)
	if err != nil {
		return err
	}

	return nil
}

func (repo *AwsS3Repository) CreateAndStoreKey(ctx context.Context, user string, secretMap map[string]AwsAccessKey) error {
	logger.Info(fmt.Sprintf("Creating secret for user %s", user))

	iamClient, err := repo.GetIamClient(ctx, nil)
	if err != nil {
		return err
	}

	secretsClient, err := repo.GetSecretsClient(ctx, nil)
	if err != nil {
		logger.Warn(fmt.Sprintf("Secret does not exist, creating new access key and secret: %s", err.Error()))
	}

	res, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: aws.String(user),
	})
	if err != nil {
		return err
	}

	newKey := AwsAccessKey{AwsAccessKeyId: *res.AccessKey.AccessKeyId, AwsSecretAccessKey: *res.AccessKey.SecretAccessKey}

	keyJson, err := json.Marshal(newKey)
	if err != nil {
		return err
	}

	_, err = secretsClient.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(fmt.Sprintf("demo/%s", user)),
		SecretString: aws.String(string(keyJson)),
	})
	if err != nil {
		return err
	}

	secretMap[user] = newKey

	return nil
}

func (repo *AwsS3Repository) ListKeys(ctx context.Context, user string) (set.Set[string], error) {
	iamClient, err := repo.GetIamClient(ctx, nil)
	if err != nil {
		return nil, err
	}

	res, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(user)})
	if err != nil {
		return nil, err
	}

	awsKeyIds := set.Set[string]{}

	for _, key := range res.AccessKeyMetadata {
		awsKeyIds.Add(*key.AccessKeyId)
	}

	return awsKeyIds, nil
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

func (repo *AwsS3Repository) DeactivateKeys(ctx context.Context, secretMap map[string]AwsAccessKey) error {
	iamClient, err := repo.GetIamClient(ctx, nil)
	if err != nil {
		return err
	}

	for user, keys := range secretMap {
		logger.Info(fmt.Sprintf("Deactivating key for user %s", user))

		_, err := iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
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

type AwsAccessKey struct {
	AwsAccessKeyId     string `json:"awsAccessKeyId"`
	AwsSecretAccessKey string `json:"awsSecretAccessKey"`
}
