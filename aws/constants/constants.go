package constants

const (
	AwsAccountId = "aws-account-id"

	AwsProfile = "aws-profile"

	AwsRegion = "aws-region"

	AwsConcurrency = "aws-concurrency"

	AwsOrganizationProfile = "aws-organization-profile"

	AwsOrganizationRegion = "aws-organization-region"

	AwsS3Enabled                = "aws-s3-enabled"
	AwsS3EmulateFolderStructure = "aws-s3-emulate-folder-structure"
	AwsS3MaxFolderDepth         = "aws-s3-max-folder-depth"
	AwsS3IncludeBuckets         = "aws-s3-include-buckets"
	AwsS3ExcludeBuckets         = "aws-s3-exclude-buckets"

	AwsGlueEnabled = "aws-glue-enabled"

	AwsAccessSkipIAM                 = "aws-access-skip-iam"
	AwsAccessSkipUserInlinePolicies  = "aws-access-skip-user-inline-policies"
	AwsAccessSkipGroupInlinePolicies = "aws-access-skip-group-inline-policies"
	AwsAccessSkipS3AccessPoints      = "aws-access-skip-s3-access-points"

	AwsS3CloudTrailBucket = "aws-s3-cloudtrail-bucket"

	// To make a distinct difference between policies and roles when reading ACs from the target, we'll prefix policy names with this value.
	PolicyPrefix = "policy/"

	// Inline prefix is used for prefixing part of the external id, preceding the comma-separated list of inline policy ARNs used
	InlinePrefix     = "inline:"
	PolicyTypePrefix = "policy:"
	RoleTypePrefix   = "role:"
	UserTypePrefix   = "user:"
	GroupTypePrefix  = "group:"

	TagSource = "aws-s3"

	S3PermissionPrefix = "s3"
)