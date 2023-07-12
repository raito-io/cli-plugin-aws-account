package main

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/raito-io/cli/base"
	"github.com/raito-io/cli/base/info"
	"github.com/raito-io/cli/base/util/plugin"
	"github.com/raito-io/cli/base/wrappers"

	"github.com/raito-io/cli-plugin-aws-account/aws"
)

var version = "0.0.0"

var logger hclog.Logger

func main() {
	logger = base.Logger()
	logger.SetLevel(hclog.Debug)

	err := base.RegisterPlugins(
		wrappers.IdentityStoreSync(aws.NewIdentityStoreSyncer()),
		wrappers.DataSourceSync(aws.NewDataSourceSyncer()),
		wrappers.DataAccessSync(aws.NewDataAccessSyncer()),
		wrappers.DataUsageSync(aws.NewDataUsageSyncer()), &info.InfoImpl{
			Info: &plugin.PluginInfo{
				Name:    "AWS Account",
				Version: plugin.ParseVersion(version),
				Parameters: []*plugin.ParameterInfo{
					{Name: aws.AwsAccountId, Description: "The AWS account ID", Mandatory: true},
					{Name: aws.AwsProfile, Description: "The AWS SDK profile to use for connecting to the AWS account to synchronize. When not specified, the default profile is used (or what is defined in the AWS_PROFILE environment variable).", Mandatory: false},
					{Name: aws.AwsRegion, Description: "The AWS region to use for connecting to the AWS account to synchronize. When not specified, the default region as found by the AWS SDK is used.", Mandatory: false},
					{Name: aws.AwsOrganizationProfile, Description: "The AWS SDK profile where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). This is optional and can be used to get a full access trace in case access is granted through the AWS IAM Identity Center.", Mandatory: false},
					{Name: aws.AwsOrganizationRegion, Description: fmt.Sprintf("The AWS region where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). If not set and %s parameter is defined, the default region for the profile will be used", aws.AwsOrganizationProfile), Mandatory: false},
					{Name: aws.AwsS3EmulateFolderStructure, Description: "Emulate a folder structure for S3 objects, just like in the AWS UI", Mandatory: false},
					{Name: aws.AwsS3MaxFolderDepth, Description: fmt.Sprintf("If %s is set to true, fetch all objects up to a certain folder depth.", aws.AwsS3EmulateFolderStructure), Mandatory: false},
					{Name: aws.AwsS3IncludeBuckets, Description: "Optional comma-separated list of buckets to include. If specified, only these buckets will be handled. Wildcards (*) can be used.", Mandatory: false},
					{Name: aws.AwsS3ExcludeBuckets, Description: "Optional comma-separated list of buckets to exclude. If specified, these buckets will not be handled. Wildcard (*) can be used. Excludes have preference over includes.", Mandatory: false},
				},
			},
		})

	if err != nil {
		logger.Error(fmt.Sprintf("error while registering plugins: %s", err.Error()))
	}
}
