package data_source

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/raito-io/cli/base/util/config"

	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	baserepo "github.com/raito-io/cli-plugin-aws-account/aws/repo"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"

	ds "github.com/raito-io/cli/base/data_source"
)

type AwsS3Repository struct {
	configMap *config.ConfigMap
}

func NewAwsS3Repository(configMap *config.ConfigMap) *AwsS3Repository {
	return &AwsS3Repository{
		configMap: configMap,
	}
}

func (repo *AwsS3Repository) GetS3Client(ctx context.Context, region *string) (*s3.Client, error) {
	cfg, err := baserepo.GetAWSConfig(ctx, repo.configMap, region)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	return client, nil
}

func (repo *AwsS3Repository) ListBuckets(ctx context.Context) ([]model.AwsS3Entity, error) {
	client, err := repo.GetS3Client(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get s3 client: %w", err)
	}

	output, err := client.ListBuckets(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	// TODO; get tags from buckets

	result := []model.AwsS3Entity{}

	for _, bucket := range output.Buckets {
		bl, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bucket.Name})
		if err != nil {
			return nil, fmt.Errorf("fetching bucket location: %w", err)
		}

		region := string(bl.LocationConstraint)

		result = append(result, model.AwsS3Entity{
			Key:    *bucket.Name,
			Region: region,
			Type:   ds.Bucket,
		})
	}

	return result, nil
}

func (repo *AwsS3Repository) ListFiles(ctx context.Context, bucket string, prefix *string) ([]model.AwsS3Entity, string, error) {
	client, region, err := repo.getS3ClientForBucket(ctx, bucket)
	if err != nil {
		return nil, "", err
	}

	moreObjectsAvailable := true

	var continuationToken *string
	var result []model.AwsS3Entity

	for moreObjectsAvailable {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			ContinuationToken: continuationToken,
			Prefix:            prefix,
		}

		response, err2 := client.ListObjectsV2(ctx, input)
		if err2 != nil {
			return nil, "", fmt.Errorf("list objects: %w", err2)
		}

		moreObjectsAvailable = response.IsTruncated != nil && *response.IsTruncated
		continuationToken = response.NextContinuationToken

		for _, object := range response.Contents {
			result = append(result, model.AwsS3Entity{
				Key:       *object.Key,
				Type:      ds.File,
				ParentKey: bucket,
			})
		}
	}

	return result, region, nil
}

func (repo *AwsS3Repository) getS3ClientForBucket(ctx context.Context, bucket string) (*s3.Client, string, error) {
	utils.Logger.Info(fmt.Sprintf("Fetching files from bucket %s", bucket))

	bucketClient, err := repo.GetS3Client(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("get s3 client: %w", err)
	}

	bucketInfo, err := bucketClient.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: &bucket})
	if err != nil {
		return nil, "", fmt.Errorf("get bucket location: %w", err)
	}

	bucketLocation := string(bucketInfo.LocationConstraint)
	utils.Logger.Info(fmt.Sprintf("Location of bucket %q is %s", bucket, bucketLocation))

	client, err := repo.GetS3Client(ctx, &bucketLocation)
	if err != nil {
		return nil, "", err
	}

	return client, bucketLocation, nil
}

func (repo *AwsS3Repository) GetFile(ctx context.Context, bucket, key string, region *string) (io.ReadCloser, error) {
	client, err := repo.GetS3Client(ctx, region)
	if err != nil {
		return nil, err
	}

	input := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	output, err := client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("get object: %w", err)
	}

	return output.Body, nil
}
