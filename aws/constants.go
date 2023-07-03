package aws

const (
	AwsAccountId = "aws-account-id"

	AwsProfile = "aws-profile"

	AwsRegion = "aws-region"

	AwsOrganizationProfile = "aws-organization-profile"

	AwsOrganizationRegion = "aws-organization-region"

	AwsS3EmulateFolderStructure = "aws-s3-emulate-folder-structure"
	AwsS3MaxFolderDepth         = "aws-s3-max-folder-depth"
	AwsS3CloudTrailBucket       = "aws-s3-cloudtrail-bucket"

	// TODO: actually implement the filtering out of AWS-managed policies
	AwsImportAwsManagedPolicies = "aws-import-aws-managed-policies"

	RolePrefix    = "role/"
	InlinePrefix  = "inline/"
	ManagedPrefix = "managed/"

	TagSource = "aws-s3"

	S3PermissionPrefix = "s3"
)
