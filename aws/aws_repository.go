package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/raito-io/cli/base/util/config"
)

func GetAWSConfig(ctx context.Context, configMap *config.ConfigMap, region *string) (aws.Config, error) {
	return getAWSConfig(ctx, configMap, AwsProfile, AwsRegion, region)
}

func GetAWSOrgConfig(ctx context.Context, configMap *config.ConfigMap, region *string) (aws.Config, error) {
	return getAWSConfig(ctx, configMap, AwsOrganizationProfile, AwsOrganizationRegion, region)
}

func getAWSConfig(ctx context.Context, configMap *config.ConfigMap, profileParam, regionParam string, region *string) (aws.Config, error) {
	loadOptions := make([]func(*awsconfig.LoadOptions) error, 0)

	profile := configMap.GetStringWithDefault(profileParam, "")
	if profile != "" {
		loadOptions = append(loadOptions, awsconfig.WithSharedConfigProfile(profile))
	}

	awsRegion := ""
	if region != nil {
		awsRegion = *region
	} else {
		awsRegion = configMap.GetStringWithDefault(regionParam, "")
	}

	if awsRegion != "" {
		loadOptions = append(loadOptions, awsconfig.WithRegion(awsRegion))
	}

	return awsconfig.LoadDefaultConfig(ctx, loadOptions...)
}
