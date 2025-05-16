package main

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/raito-io/cli/base"
	"github.com/raito-io/cli/base/access_provider"
	"github.com/raito-io/cli/base/info"
	"github.com/raito-io/cli/base/util/plugin"
	"github.com/raito-io/cli/base/wrappers"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_access"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source"
	"github.com/raito-io/cli-plugin-aws-account/aws/usage"

	"github.com/raito-io/cli-plugin-aws-account/aws"
)

var version = "0.0.0"

var logger hclog.Logger

//go:generate go run github.com/vektra/mockery/v2 --config .mockery.yaml

func main() {
	logger = base.Logger()
	logger.SetLevel(hclog.Debug)

	err := base.RegisterPlugins(
		wrappers.IdentityStoreSync(aws.NewIdentityStoreSyncer()),
		wrappers.DataSourceSync(data_source.NewDataSourceSyncer()),
		wrappers.DataAccessSync(data_access.NewDataAccessSyncer(), access_provider.WithSupportPartialSync()),
		wrappers.DataUsageSync(usage.NewDataUsageSyncer()), &info.InfoImpl{
			Info: &plugin.PluginInfo{
				Name:    "AWS Account",
				Version: plugin.ParseVersion(version),
				Parameters: []*plugin.ParameterInfo{
					{Name: constants.AwsProfile, Description: "The AWS SDK profile to use for connecting to the AWS account to synchronize. When not specified, the default profile is used (or what is defined in the AWS_PROFILE environment variable).", Mandatory: false},
					{Name: constants.AwsRegions, Description: "A comma separated list of AWS regions to deal with. When not specified, only the default region as found by the AWS SDK is used. The first region in the list must be the default region.", Mandatory: false},
					{Name: constants.AwsOrganizationProfile, Description: "The AWS SDK profile where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). This is optional and can be used to get a full access trace in case access is granted through the AWS IAM Identity Center.", Mandatory: false},
					{Name: constants.AwsOrganizationRegion, Description: fmt.Sprintf("The AWS region where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). If not set and %s parameter is defined, the default region for the profile will be used.", constants.AwsOrganizationProfile), Mandatory: false},
					{Name: constants.AwsOrganizationIdentityCenterInstanceArn, Description: "The ARN of the AWS IAM Identity Center instance.", Mandatory: false},
					{Name: constants.AwsOrganizationIdentityStore, Description: "The ARN of the AWS Identity Store.", Mandatory: false},
					// AWS S3 parameters
					{Name: constants.AwsS3Enabled, Description: fmt.Sprintf("If set to true (default), S3 buckets and objects will be retrieved directly from the S3 API. See all other 'aws-s3-' parameters for more control over what is imported and what not. This cannot be enabled together with the %q parameter.", constants.AwsGlueEnabled), Mandatory: false},
					{Name: constants.AwsS3EmulateFolderStructure, Description: "Emulate a folder structure for S3 objects, just like in the AWS UI", Mandatory: false},
					{Name: constants.AwsS3MaxFolderDepth, Description: fmt.Sprintf("If %s is set to true, fetch all objects up to a certain folder depth. If not set, %d is used as default.", constants.AwsS3EmulateFolderStructure, constants.AwsS3MaxFolderDepthDefault), Mandatory: false},
					{Name: constants.AwsS3IncludeBuckets, Description: "Optional comma-separated list of buckets to include. If specified, only these buckets will be handled. Wildcards (*) can be used.", Mandatory: false},
					{Name: constants.AwsS3ExcludeBuckets, Description: "Optional comma-separated list of buckets to exclude. If specified, these buckets will not be handled. Wildcard (*) can be used. Excludes have preference over includes.", Mandatory: false},
					{Name: constants.AwsConcurrency, Description: "The number of threads to use for concurrent API calls to AWS. The default is 5.", Mandatory: false},
					{Name: constants.AwsS3CloudTrailBucket, Description: "The name of the bucket where the usage data for S3 is stored by AWS Cloud Trail. This is necessary to fetch usage data. If not set, no usage data is gathered", Mandatory: false},
					// AWS Glue parameters
					{Name: constants.AwsGlueEnabled, Description: fmt.Sprintf("If set to true, AWS Glue Catalog will be used to fetch data objects. This approach is recommended instead of using S3 directly, because Glue allows you to define your data on a more logical level. The imported data objects will still be represented as S3 objects. This cannot be enabled together with the %q parameter.", constants.AwsS3Enabled), Mandatory: false},
					// Access parameters
					{Name: constants.AwsAccessSkipIAM, Description: "If set to true, all IAM access entities (roles and policies) will not be read to import into Raito Cloud as access controls.", Mandatory: false},
					{Name: constants.AwsAccessSkipUserInlinePolicies, Description: "If set to true, inline policies on users will not be read to import into Raito Cloud as access controls.", Mandatory: false},
					{Name: constants.AwsAccessSkipGroupInlinePolicies, Description: "If set to true, inline policies on groups will not be read to import into Raito Cloud as access controls.", Mandatory: false},
					{Name: constants.AwsAccessSkipManagedPolicies, Description: "If set to true, managed policies will not be read to import into Raito Cloud as access controls.", Mandatory: false},
					{Name: constants.AwsAccessSkipAWSManagedPolicies, Description: "If set to true, AWS managed policies are excluded.", Mandatory: false},
					{Name: constants.AwsAccessManagedPolicyExcludes, Description: "Optional comma-separated list of managed policy names to exclude. Regular expressions can be used (e.g. 'Amazon.+,AWS.+' will exclude all managed policies starting with Amazon or AWS).", Mandatory: false},
					{Name: constants.AwsAccessSkipS3AccessPoints, Description: "If set to true, S3 access points will not be read to import into Raito Cloud as access controls.", Mandatory: false},
					{Name: constants.AwsAccessRoleExcludes, Description: "Optional comma-separated list of role names to exclude. Regular expressions can be used (e.g. 'Amazon.+,AWS.+' will exclude all roles starting with Amazon or AWS).", Mandatory: false},
					{Name: constants.AwsUserExcludes, Description: "Optional comma-separated list of users to exclude. For the matched users, no details will be fetched, but they will still be imported without details (email address, tags, ...). Regular expressions can be used.", Mandatory: false},

					{Name: constants.AwsAccessRolePrefix, Description: "Optional prefix for AWS IAM Roles generated by the connector. Note: roles currently cannot be renamed, so adding/updating this parameter later will not update existing roles.", Mandatory: false},
					{Name: constants.AwsAccessRoleSuffix, Description: "Optional suffix for AWS IAM Roles generated by the connector. Note: roles currently cannot be renamed, so adding/updating this parameter later will not update existing roles.", Mandatory: false},

					{Name: constants.AwsAccessSsoRolePrefix, Description: "Optional prefix for Permission Sets generated by the connector. Note: permission sets currently cannot be renamed, so adding/updating this parameter later will not update existing permission sets. You can use #account# in the prefix, which will be replaced with the AWS account id this is associated with.", Mandatory: false},
					{Name: constants.AwsAccessSsoRoleSuffix, Description: "Optional suffix for Permission Sets generated by the connector. Note: permissions sets currently cannot be renamed, so adding/updating this parameter later will not update existing permission sets. You can use #account# in the suffix, which will be replaced with the AWS account id this is associated with.", Mandatory: false},

					{Name: constants.AwsAccessPolicyPrefix, Description: "Optional prefix for AWS IAM Policies generated by the connector.", Mandatory: false},
					{Name: constants.AwsAccessPolicySuffix, Description: "Optional suffix for AWS IAM Policies generated by the connector.", Mandatory: false},

					{Name: constants.AwsAccessPointPrefix, Description: "Optional prefix for S3 Access Points generated by the connector. Note: access points currently cannot be renamed, so adding/updating this parameter later will not update existing access points.", Mandatory: false},
					{Name: constants.AwsAccessPointSuffix, Description: "Optional suffix for S3 Access Points generated by the connector. Note: access points currently cannot be renamed, so adding/updating this parameter later will not update existing access points.", Mandatory: false},

					{Name: constants.AwsPermissionSetOwnerEmailTag, Description: "Optional comma-separated list of tag keys to put on permission sets generated by Raito for which the value will be a list of user emails (separated by a / character) representing the owners of the corresponding Grant in Raito.", Mandatory: false},
					{Name: constants.AwsPermissionSetOwnerNameTag, Description: "Optional comma-separated list of tag keys to put on permission sets generated by Raito for which the value will be a list of user names (separated by a / character) representing the owners of the corresponding Grant in Raito.", Mandatory: false},
					{Name: constants.AwsPermissionSetOwnerGroupTag, Description: "Optional comma-separated list of tag keys to put on permission sets generated by Raito for which the value will be a list of group names (separated by a / character) representing the group owners of the corresponding Grant in Raito.", Mandatory: false},
					{Name: constants.AwsPermissionSetCustomTags, Description: "Optional comma-separated list of custom tags to put on permission sets generated by Raito in the form KEY:VALUE.", Mandatory: false},
					{Name: constants.AwsPermissionSetAccountIdTag, Description: "Optional comma-separated list of tag keys to put on permission sets generated by Raito for which the value will be the applicable AWS account id.", Mandatory: false},
				},
			},
		})

	if err != nil {
		logger.Error(fmt.Sprintf("error while registering plugins: %s", err.Error()))
	}
}
