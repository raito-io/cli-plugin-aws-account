package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/raito-io/cli/base/util/config"
)

func GetAWSConfig(ctx context.Context, configMap *config.ConfigMap, region *string) (aws.Config, error) {
	awsRegion := "eu-central-1"
	if region != nil && *region == "" {
		awsRegion = "us-east-1"
	} else if region != nil {
		awsRegion = *region
	}

	profile := configMap.GetStringWithDefault(AwsProfile, "")

	if profile == "" {
		logger.Debug("Using AWS credentials from default profile")

		return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(awsRegion))
	} else {
		logger.Debug(fmt.Sprintf("Using AWS credentials from profile %s", profile))

		return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(awsRegion), awsconfig.WithSharedConfigProfile(profile))
	}
}
