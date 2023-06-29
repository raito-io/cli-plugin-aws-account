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
					{Name: aws.AwsOrganizationProfile, Description: "The AWS SDK profile to use for fetching permission sets. This is optional and can be used to get a full access trace in case access is granted through the AWS IAM Identity Center.", Mandatory: false},
					{Name: aws.AwsS3EmulateFolderStructure, Description: "Emulate a folder structure for S3 objects, just like in the AWS UI", Mandatory: false},
					{Name: aws.AwsS3MaxFolderDepth, Description: fmt.Sprintf("If %s is set to true, fetch all objects up to a certain folder depth.", aws.AwsS3EmulateFolderStructure), Mandatory: false},
				},
			},
		})

	if err != nil {
		logger.Error(fmt.Sprintf("error while registering plugins: %s", err.Error()))
	}
}
