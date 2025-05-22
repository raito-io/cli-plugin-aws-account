package constants

const (
	AwsProfile = "aws-profile"

	AwsRegions = "aws-regions"

	AwsConcurrency = "aws-concurrency"

	AwsOrganizationProfile                   = "aws-organization-profile"
	AwsOrganizationRegion                    = "aws-organization-region"
	AwsOrganizationIdentityCenterInstanceArn = "aws-organization-identity-center-instance-arn"
	AwsOrganizationIdentityStore             = "aws-organization-identity-store"

	AwsS3Enabled                = "aws-s3-enabled"
	AwsS3EmulateFolderStructure = "aws-s3-emulate-folder-structure"

	AwsS3MaxFolderDepth        = "aws-s3-max-folder-depth"
	AwsS3MaxFolderDepthDefault = 20

	AwsS3IncludeBuckets = "aws-s3-include-buckets"
	AwsS3ExcludeBuckets = "aws-s3-exclude-buckets"

	AwsGlueEnabled          = "aws-glue-enabled"
	AwsGlueExcludeDatabases = "aws-glue-exclude-databases"
	AwsGlueExcludeTables    = "aws-glue-exclude-tables"

	AwsAccessSkipIAM                 = "aws-access-skip-iam"
	AwsAccessSkipUserInlinePolicies  = "aws-access-skip-user-inline-policies"
	AwsAccessSkipGroupInlinePolicies = "aws-access-skip-group-inline-policies"
	AwsAccessSkipManagedPolicies     = "aws-access-skip-managed-policies"
	AwsAccessSkipAWSManagedPolicies  = "aws-access-skip-aws-managed-policies"
	AwsAccessManagedPolicyExcludes   = "aws-access-managed-policy-excludes"
	AwsAccessSkipS3AccessPoints      = "aws-access-skip-s3-access-points"
	AwsAccessRoleExcludes            = "aws-access-role-excludes"

	AwsAccessRolePrefix    = "aws-role-prefix"
	AwsAccessRoleSuffix    = "aws-role-suffix"
	AwsAccessPolicyPrefix  = "aws-policy-prefix"
	AwsAccessPolicySuffix  = "aws-policy-suffix"
	AwsAccessSsoRolePrefix = "aws-sso-role-prefix"
	AwsAccessSsoRoleSuffix = "aws-sso-role-suffix"
	AwsAccessPointPrefix   = "aws-access-point-prefix"
	AwsAccessPointSuffix   = "aws-access-point-suffix"

	AwsUserExcludes = "aws-user-excludes"

	AwsS3CloudTrailBucket = "aws-s3-cloudtrail-bucket"

	// Inline prefix is used for prefixing part of the external id, preceding the comma-separated list of inline policy ARNs used
	InlinePrefix          = "inline:"
	PolicyTypePrefix      = "policy:"
	RoleTypePrefix        = "role:"
	SsoRoleTypePrefix     = "ssorole:"
	AccessPointTypePrefix = "accesspoint:"
	UserTypePrefix        = "user:"
	GroupTypePrefix       = "group:"

	TagSource = "aws-s3"

	AwsPermissionSetOwnerEmailTag = "aws-permissionset-owner-email-tag"
	AwsPermissionSetOwnerNameTag  = "aws-permissionset-owner-name-tag"
	AwsPermissionSetOwnerGroupTag = "aws-permissionset-owner-group-tag"
	AwsPermissionSetCustomTags    = "aws-permissionset-owner-custom-tags"
	AwsPermissionSetAccountIdTag  = "aws-permissionset-account-id-tag"

	S3PermissionPrefix = "s3"

	SsoRolePrefix     = "RAITO_"
	SsoReservedPrefix = "AWSReservedSSO_"
)
