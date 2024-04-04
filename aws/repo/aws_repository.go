package repo

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	aws2 "github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli/base/util/config"
)

func GetAWSConfig(ctx context.Context, configMap *config.ConfigMap, region *string) (aws.Config, error) {
	return getAWSConfig(ctx, configMap, aws2.AwsProfile, aws2.AwsRegion, region)
}

func GetAWSOrgConfig(ctx context.Context, configMap *config.ConfigMap, region *string) (aws.Config, error) {
	return getAWSConfig(ctx, configMap, aws2.AwsOrganizationProfile, aws2.AwsOrganizationRegion, region)
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
