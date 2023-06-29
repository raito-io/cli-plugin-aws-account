package aws

const (
	AwsAccountId = "aws-account-id"

	AwsProfile = "aws-profile"

	AwsOrganizationProfile = "aws-organization-profile"

	AwsS3EmulateFolderStructure = "aws-s3-emulate-folder-structure"
	AwsS3MaxFolderDepth         = "aws-s3-max-folder-depth"
	AwsS3CloudTrailBucket       = "aws-s3-cloudtrail-bucket"

	// TODO: actually implement the filtering out of AWS-managed policies
	AwsImportAwsManagedPolicies = "aws-import-aws-managed-policies"

	RolePrefix    = "role/"
	InlinePrefix  = "inline/"
	ManagedPrefix = "managed/"
)
