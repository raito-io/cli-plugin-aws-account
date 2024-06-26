package repo

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/raito-io/cli/base/util/config"

	aws2 "github.com/raito-io/cli-plugin-aws-account/aws/constants"
)

func GetAWSConfig(ctx context.Context, configMap *config.ConfigMap, region *string) (aws.Config, error) {
	return getAWSConfig(ctx, configMap, aws2.AwsProfile, aws2.AwsRegions, region)
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

		// Taking the first region if there are multiple regions defined
		if strings.Contains(awsRegion, ",") {
			awsRegion = strings.Split(awsRegion, ",")[0]
		}
	}

	if awsRegion != "" {
		loadOptions = append(loadOptions, awsconfig.WithRegion(awsRegion))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load default config: %w", err)
	}

	return cfg, nil
}

func GetAccountId(ctx context.Context, configMap *config.ConfigMap) (string, error) {
	cfg, err := GetAWSConfig(ctx, configMap, nil)

	if err != nil {
		return "", fmt.Errorf("get aws config: %w", err)
	}

	client := sts.NewFromConfig(cfg)
	input := &sts.GetCallerIdentityInput{}

	req, err := client.GetCallerIdentity(ctx, input)
	if err != nil {
		return "", fmt.Errorf("get caller indentity: %w", err)
	}

	return *req.Account, nil
}
