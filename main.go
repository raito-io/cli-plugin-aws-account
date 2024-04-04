package main

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
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
					{Name: constants.AwsAccountId, Description: "The AWS account ID", Mandatory: true},
					{Name: constants.AwsProfile, Description: "The AWS SDK profile to use for connecting to the AWS account to synchronize. When not specified, the default profile is used (or what is defined in the AWS_PROFILE environment variable).", Mandatory: false},
					{Name: constants.AwsRegion, Description: "The AWS region to use for connecting to the AWS account to synchronize. When not specified, the default region as found by the AWS SDK is used.", Mandatory: false},
					{Name: constants.AwsOrganizationProfile, Description: "The AWS SDK profile where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). This is optional and can be used to get a full access trace in case access is granted through the AWS IAM Identity Center.", Mandatory: false},
					{Name: constants.AwsOrganizationRegion, Description: fmt.Sprintf("The AWS region where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). If not set and %s parameter is defined, the default region for the profile will be used", constants.AwsOrganizationProfile), Mandatory: false},
					{Name: constants.AwsS3EmulateFolderStructure, Description: "Emulate a folder structure for S3 objects, just like in the AWS UI", Mandatory: false},
					{Name: constants.AwsS3MaxFolderDepth, Description: fmt.Sprintf("If %s is set to true, fetch all objects up to a certain folder depth. If not set, 20 is used as default.", constants.AwsS3EmulateFolderStructure), Mandatory: false},
					{Name: constants.AwsS3IncludeBuckets, Description: "Optional comma-separated list of buckets to include. If specified, only these buckets will be handled. Wildcards (*) can be used.", Mandatory: false},
					{Name: constants.AwsS3ExcludeBuckets, Description: "Optional comma-separated list of buckets to exclude. If specified, these buckets will not be handled. Wildcard (*) can be used. Excludes have preference over includes.", Mandatory: false},
					{Name: constants.AwsConcurrency, Description: "The number of threads to use for concurrent API calls to AWS. The default is 5.", Mandatory: false},
					{Name: constants.AwsS3CloudTrailBucket, Description: "The name of the bucket where the usage data for S3 is stored by AWS Cloud Trail. This is necessary to fetch usage data. If not set, no usage data is gathered", Mandatory: false},
				},
			},
		})

	if err != nil {
		logger.Error(fmt.Sprintf("error while registering plugins: %s", err.Error()))
	}
}
