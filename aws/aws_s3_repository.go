package aws

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/raito-io/cli/base/util/config"

	ds "github.com/raito-io/cli/base/data_source"
)

type AwsS3Repository struct {
	configMap *config.ConfigMap
}

func (repo *AwsS3Repository) GetS3Client(ctx context.Context, region *string) (*s3.Client, error) {
	cfg, err := GetAWSConfig(ctx, repo.configMap, region)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	return client, nil
}

func (repo *AwsS3Repository) ListBuckets(ctx context.Context) ([]AwsS3Entity, error) {
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
		if !useBucket(bucket) {
			continue
		}

		result = append(result, AwsS3Entity{
			Key:  *bucket.Name,
			Type: ds.Bucket,
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

	bucketLocation := string(bucketInfo.LocationConstraint)
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

		moreObjectsAvailable = response.IsTruncated
		continuationToken = response.NextContinuationToken

		for _, object := range response.Contents {
			result = append(result, AwsS3Entity{
				Key:       *object.Key,
				Type:      ds.File,
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
