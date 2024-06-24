package permissions

import (
	"sync"

	ds "github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/golang-set/set"
)

var AllS3Permissions = []*ds.DataObjectTypePermission{
	&S3AbortMultipartUpload,
	&S3BypassGovernanceRetention,
	&S3CreateAccessPoint,
	&S3CreateAccessPointForObjectLambda,
	&S3CreateBucket,
	&S3CreateJob,
	&S3CreateMultiRegionAccessPoint,
	&S3DeleteAccessPoint,
	&S3DeleteAccessPointForObjectLambda,
	&S3DeleteAccessPointPolicy,
	&S3DeleteAccessPointPolicyForObjectLambda,
	&S3DeleteBucket,
	&S3DeleteBucketPolicy,
	&S3DeleteBucketWebsite,
	&S3DeleteJobTagging,
	&S3DeleteMultiRegionAccessPoint,
	&S3DeleteObject,
	&S3DeleteObjectTagging,
	&S3DeleteObjectVersion,
	&S3DeleteObjectVersionTagging,
	&S3DeleteStorageLensConfiguration,
	&S3DeleteStorageLensConfigurationTagging,
	&S3DescribeJob,
	&S3DescribeMultiRegionAccessPointOperation,
	&S3GetAccelerateConfiguration,
	&S3GetAccessPoint,
	&S3GetAccessPointConfigurationForObjectLambda,
	&S3GetAccessPointForObjectLambda,
	&S3GetAccessPointPolicy,
	&S3GetAccessPointPolicyForObjectLambda,
	&S3GetAccessPointPolicyStatus,
	&S3GetAccessPointPolicyStatusForObjectLambda,
	&S3GetAccountPublicAccessBlock,
	&S3GetAnalyticsConfiguration,
	&S3GetBucketAcl,
	&S3GetBucketCORS,
	&S3GetBucketLocation,
	&S3GetBucketLogging,
	&S3GetBucketNotification,
	&S3GetBucketObjectLockConfiguration,
	&S3GetBucketOwnershipControls,
	&S3GetBucketPolicy,
	&S3GetBucketPolicyStatus,
	&S3GetBucketPublicAccessBlock,
	&S3GetBucketRequestPayment,
	&S3GetBucketTagging,
	&S3GetBucketVersioning,
	&S3GetBucketWebsite,
	&S3GetEncryptionConfiguration,
	&S3GetIntelligentTieringConfiguration,
	&S3GetInventoryConfiguration,
	&S3GetJobTagging,
	&S3GetLifecycleConfiguration,
	&S3GetMetricsConfiguration,
	&S3GetMultiRegionAccessPoint,
	&S3GetMultiRegionAccessPointPolicy,
	&S3GetMultiRegionAccessPointPolicyStatus,
	&S3GetObject,
	&S3GetObjectAcl,
	&S3GetObjectAttributes,
	&S3GetObjectLegalHold,
	&S3GetObjectRetention,
	&S3GetObjectTagging,
	&S3GetObjectTorrent,
	&S3GetObjectVersion,
	&S3GetObjectVersionAcl,
	&S3GetObjectVersionAttributes,
	&S3GetObjectVersionForReplication,
	&S3GetObjectVersionTagging,
	&S3GetObjectVersionTorrent,
	&S3GetReplicationConfiguration,
	&S3GetStorageLensConfiguration,
	&S3GetStorageLensConfigurationTagging,
	&S3GetStorageLensDashboard,
	&S3InitiateReplication,
	&S3ListAccessPoints,
	&S3ListAccessPointsForObjectLambda,
	&S3ListAllMyBuckets,
	&S3ListBucket,
	&S3ListBucketMultipartUploads,
	&S3ListBucketVersions,
	&S3ListJobs,
	&S3ListMultiRegionAccessPoints,
	&S3ListMultipartUploadParts,
	&S3ListStorageLensConfigurations,
	&S3ObjectOwnerOverrideToBucketOwner,
	&S3PutAccelerateConfiguration,
	&S3PutAccessPointConfigurationForObjectLambda,
	&S3PutAccessPointPolicy,
	&S3PutAccessPointPolicyForObjectLambda,
	&S3PutAccessPointPublicAccessBlock,
	&S3PutAccountPublicAccessBlock,
	&S3PutAnalyticsConfiguration,
	&S3PutBucketAcl,
	&S3PutBucketCORS,
	&S3PutBucketLogging,
	&S3PutBucketNotification,
	&S3PutBucketObjectLockConfiguration,
	&S3PutBucketOwnershipControls,
	&S3PutBucketPolicy,
	&S3PutBucketPublicAccessBlock,
	&S3PutBucketRequestPayment,
	&S3PutBucketTagging,
	&S3PutBucketVersioning,
	&S3PutBucketWebsite,
	&S3PutEncryptionConfiguration,
	&S3PutIntelligentTieringConfiguration,
	&S3PutInventoryConfiguration,
	&S3PutJobTagging,
	&S3PutLifecycleConfiguration,
	&S3PutMetricsConfiguration,
	&S3PutMultiRegionAccessPointPolicy,
	&S3PutObject,
	&S3PutObjectAcl,
	&S3PutObjectLegalHold,
	&S3PutObjectRetention,
	&S3PutObjectTagging,
	&S3PutObjectVersionAcl,
	&S3PutObjectVersionTagging,
	&S3PutReplicationConfiguration,
	&S3PutStorageLensConfiguration,
	&S3PutStorageLensConfigurationTagging,
	&S3ReplicateDelete,
	&S3ReplicateObject,
	&S3ReplicateTags,
	&S3RestoreObject,
	&S3UpdateJobPriority,
	&S3UpdateJobStatus,
}

var S3ObjectPermissions = []*ds.DataObjectTypePermission{
	&S3AbortMultipartUpload,
	&S3BypassGovernanceRetention,
	&S3CreateAccessPointForObjectLambda,
	&S3DeleteAccessPointForObjectLambda,
	&S3DeleteAccessPointPolicyForObjectLambda,
	&S3DeleteObject,
	&S3DeleteObjectTagging,
	&S3DeleteObjectVersion,
	&S3DeleteObjectVersionTagging,
	&S3GetAccessPointConfigurationForObjectLambda,
	&S3GetAccessPointForObjectLambda,
	&S3GetAccessPointPolicyForObjectLambda,
	&S3GetAccessPointPolicyStatusForObjectLambda,
	&S3GetObject,
	&S3GetObjectAcl,
	&S3GetObjectAttributes,
	&S3GetObjectLegalHold,
	&S3GetObjectRetention,
	&S3GetObjectTagging,
	&S3GetObjectTorrent,
	&S3GetObjectVersion,
	&S3GetObjectVersionAcl,
	&S3GetObjectVersionAttributes,
	&S3GetObjectVersionForReplication,
	&S3GetObjectVersionTagging,
	&S3GetObjectVersionTorrent,
	&S3InitiateReplication,
	&S3ListMultipartUploadParts,
	&S3ObjectOwnerOverrideToBucketOwner,
	&S3PutAccessPointConfigurationForObjectLambda,
	&S3PutAccessPointPolicyForObjectLambda,
	&S3PutObject,
	&S3PutObjectAcl,
	&S3PutObjectLegalHold,
	&S3PutObjectRetention,
	&S3PutObjectTagging,
	&S3PutObjectVersionAcl,
	&S3PutObjectVersionTagging,
	&S3ReplicateDelete,
	&S3ReplicateObject,
	&S3ReplicateTags,
	&S3RestoreObject,
}

var S3AccessPointPermissions = []*ds.DataObjectTypePermission{
	&S3ListBucket,
	&S3ListBucketMultipartUploads,
	&S3ListBucketVersions,
	&S3ListMultipartUploadParts,
	&S3GetObject,
	&S3GetObjectAcl,
	&S3GetObjectLegalHold,
	&S3GetObjectRetention,
	&S3GetObjectTagging,
	&S3GetObjectVersion,
	&S3GetObjectVersionAcl,
	&S3GetObjectVersionTagging,
	&S3AbortMultipartUpload,
	&S3DeleteObject,
	&S3DeleteObjectVersion,
	&S3PutObject,
	&S3PutObjectLegalHold,
	&S3PutObjectRetention,
	&S3RestoreObject,
	&S3BypassGovernanceRetention,
	&S3PutObjectAcl,
	&S3PutObjectVersionAcl,
	&S3DeleteObjectTagging,
	&S3DeleteObjectVersionTagging,
	&S3PutObjectTagging,
	&S3PutObjectVersionTagging,
}

// S3 Permissions
// taken from https://docs.aws.amazon.com/AmazonS3/latest/userguide/list_amazons3.html#amazons3-resources-for-iam-policies
// the following access levels are available: read, write, list, permissions management, tagging

var S3AbortMultipartUpload = ds.DataObjectTypePermission{
	Permission:             "s3:AbortMultipartUpload",
	Description:            "Grants permission to abort a multipart upload",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3BypassGovernanceRetention = ds.DataObjectTypePermission{
	Permission:             "s3:BypassGovernanceRetention",
	Description:            "Grants permission to allow circumvention of governance-mode object retention settings",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3CreateAccessPoint = ds.DataObjectTypePermission{
	Permission:             "s3:CreateAccessPoint",
	Description:            "Grants permission to create a new access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3CreateAccessPointForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:CreateAccessPointForObjectLambda",
	Description:            "Grants permission to create an object lambda enabled accesspoint",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3CreateBucket = ds.DataObjectTypePermission{
	Permission:             "s3:CreateBucket",
	Description:            "Grants permission to create a new bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3CreateJob = ds.DataObjectTypePermission{
	Permission:             "s3:CreateJob",
	Description:            "Grants permission to create a new Amazon S3 Batch Operations job",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3CreateMultiRegionAccessPoint = ds.DataObjectTypePermission{
	Permission:             "s3:CreateMultiRegionAccessPoint",
	Description:            "Grants permission to create a new multi region access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteAccessPoint = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteAccessPoint",
	Description:            "Grants permission to delete the access point named in the URI",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteAccessPointForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteAccessPointForObjectLambda",
	Description:            "Grants permission to delete the object lambda enabled access point named in the URI",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteAccessPointPolicy = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteAccessPointPolicy",
	Description:            "Grants permission to delete the policy on a specified access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3DeleteAccessPointPolicyForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteAccessPointPolicyForObjectLambda",
	Description:            "Grants permission to delete the policy on a specified object lambda enabled access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3DeleteBucket = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteBucket",
	Description:            "Grants permission to delete the bucket named in the URI",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteBucketPolicy = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteBucketPolicy",
	Description:            "Grants permission to delete the policy on a specified bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3DeleteBucketWebsite = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteBucketWebsite",
	Description:            "Grants permission to remove the website configuration for a bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteJobTagging = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteJobTagging",
	Description:            "Grants permission to remove tags from an existing Amazon S3 Batch Operations job",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3DeleteMultiRegionAccessPoint = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteMultiRegionAccessPoint",
	Description:            "Grants permission to delete the multi region access point named in the URI",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteObject = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteObject",
	Description:            "Grants permission to remove the null version of an object and insert a delete marker, which becomes the current version of the object",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteObjectTagging = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteObjectTagging",
	Description:            "Grants permission to use the tagging subresource to remove the entire tag set from the specified object",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3DeleteObjectVersion = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteObjectVersion",
	Description:            "Grants permission to remove a specific version of an object",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteObjectVersionTagging = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteObjectVersionTagging",
	Description:            "Grants permission to remove the entire tag set for a specific version of the object",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3DeleteStorageLensConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteStorageLensConfiguration",
	Description:            "Grants permission to delete an existing Amazon S3 Storage Lens configuration",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3DeleteStorageLensConfigurationTagging = ds.DataObjectTypePermission{
	Permission:             "s3:DeleteStorageLensConfigurationTagging",
	Description:            "Grants permission to remove tags from an existing Amazon S3 Storage Lens configuration",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3DescribeJob = ds.DataObjectTypePermission{
	Permission:             "s3:DescribeJob",
	Description:            "Grants permission to retrieve the configuration parameters and status for a batch operations job",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3DescribeMultiRegionAccessPointOperation = ds.DataObjectTypePermission{
	Permission:             "s3:DescribeMultiRegionAccessPointOperation",
	Description:            "Grants permission to retrieve the configurations for a multi region access point",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccelerateConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccelerateConfiguration",
	Description:            "Grants permission to uses the accelerate subresource to return the Transfer Acceleration state of a bucket, which is either Enabled or Suspended",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccessPoint = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccessPoint",
	Description:            "Grants permission to return configuration information about the specified access point",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccessPointConfigurationForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccessPointConfigurationForObjectLambda",
	Description:            "Grants permission to retrieve the configuration of the object lambda enabled access point",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccessPointForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccessPointForObjectLambda",
	Description:            "Grants permission to create an object lambda enabled accesspoint",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccessPointPolicy = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccessPointPolicy",
	Description:            "Grants permission to returns the access point policy associated with the specified access point",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccessPointPolicyForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccessPointPolicyForObjectLambda",
	Description:            "Grants permission to returns the access point policy associated with the specified object lambda enabled access point",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccessPointPolicyStatus = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccessPointPolicyStatus",
	Description:            "Grants permission to return the policy status for a specific access point policy",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccessPointPolicyStatusForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccessPointPolicyStatusForObjectLambda",
	Description:            "Grants permission to return the policy status for a specific object lambda enabled access point policy",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAccountPublicAccessBlock = ds.DataObjectTypePermission{
	Permission:             "s3:GetAccountPublicAccessBlock",
	Description:            "Grants permission to retrieve the PublicAccessBlock configuration for an AWS account",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetAnalyticsConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetAnalyticsConfiguration",
	Description:            "Grants permission to get an analytics configuration from an Amazon S3 bucket, identified by the analytics configuration ID",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketAcl = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketAcl",
	Description:            "Grants permission to use the acl subresource to return the access control list (ACL) of an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketCORS = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketCORS",
	Description:            "Grants permission to return the CORS configuration information set for an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketLocation = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketLocation",
	Description:            "Grants permission to return the Region that an Amazon S3 bucket resides in",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketLogging = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketLogging",
	Description:            "Grants permission to return the logging status of an Amazon S3 bucket and the permissions users have to view or modify that status",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketNotification = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketNotification",
	Description:            "Grants permission to get the notification configuration of an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketObjectLockConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketObjectLockConfiguration",
	Description:            "Grants permission to get the Object Lock configuration of an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketOwnershipControls = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketOwnershipControls",
	Description:            "Grants permission to retrieve ownership controls on a bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketPolicy = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketPolicy",
	Description:            "Grants permission to return the policy of the specified bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketPolicyStatus = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketPolicyStatus",
	Description:            "Grants permission to retrieve the policy status for a specific Amazon S3 bucket, which indicates whether the bucket is public",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketPublicAccessBlock = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketPublicAccessBlock",
	Description:            "Grants permission to retrieve the PublicAccessBlock configuration for an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketRequestPayment = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketRequestPayment",
	Description:            "Grants permission to return the request payment configuration of an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketTagging = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketTagging",
	Description:            "Grants permission to return the tag set associated with an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketVersioning = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketVersioning",
	Description:            "Grants permission to return the versioning state of an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetBucketWebsite = ds.DataObjectTypePermission{
	Permission:             "s3:GetBucketWebsite",
	Description:            "Grants permission to return the website configuration for an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetEncryptionConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetEncryptionConfiguration",
	Description:            "Grants permission to return the default encryption configuration an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetIntelligentTieringConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetIntelligentTieringConfiguration",
	Description:            "Grants permission to get an or list all Amazon S3 Intelligent Tiering configuration in a S3 Bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetInventoryConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetInventoryConfiguration",
	Description:            "Grants permission to return an inventory configuration from an Amazon S3 bucket, identified by the inventory configuration ID",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetJobTagging = ds.DataObjectTypePermission{
	Permission:             "s3:GetJobTagging",
	Description:            "Grants permission to return the tag set of an existing Amazon S3 Batch Operations job",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetLifecycleConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetLifecycleConfiguration",
	Description:            "Grants permission to return the lifecycle configuration information set on an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetMetricsConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetMetricsConfiguration",
	Description:            "Grants permission to get a metrics configuration from an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetMultiRegionAccessPoint = ds.DataObjectTypePermission{
	Permission:             "s3:GetMultiRegionAccessPoint",
	Description:            "Grants permission to return configuration information about the specified multi region access point",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetMultiRegionAccessPointPolicy = ds.DataObjectTypePermission{
	Permission:             "s3:GetMultiRegionAccessPointPolicy",
	Description:            "Grants permission to returns the access point policy associated with the specified multi region access point",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetMultiRegionAccessPointPolicyStatus = ds.DataObjectTypePermission{
	Permission:             "s3:GetMultiRegionAccessPointPolicyStatus",
	Description:            "Grants permission to return the policy status for a specific multi region access point policy",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObject = ds.DataObjectTypePermission{
	Permission:             "s3:GetObject",
	Description:            "Grants permission to retrieve objects from Amazon S3",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectAcl = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectAcl",
	Description:            "Grants permission to return the access control list (ACL) of an object",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectAttributes = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectAttributes",
	Description:            "Grants permission to retrieve attributes related to a specific object",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectLegalHold = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectLegalHold",
	Description:            "Grants permission to get an object's current Legal Hold status",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectRetention = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectRetention",
	Description:            "Grants permission to retrieve the retention settings for an object",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectTagging = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectTagging",
	Description:            "Grants permission to return the tag set of an object",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectTorrent = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectTorrent",
	Description:            "Grants permission to return torrent files from an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectVersion = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectVersion",
	Description:            "Grants permission to retrieve a specific version of an object",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectVersionAcl = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectVersionAcl",
	Description:            "Grants permission to return the access control list (ACL) of a specific object version",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectVersionAttributes = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectVersionAttributes",
	Description:            "Grants permission to retrieve attributes related to a specific version of an object",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectVersionForReplication = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectVersionForReplication",
	Description:            "Grants permission to replicate both unencrypted objects and objects encrypted with SSE-S3 or SSE-KMS",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectVersionTagging = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectVersionTagging",
	Description:            "Grants permission to return the tag set for a specific version of the object",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetObjectVersionTorrent = ds.DataObjectTypePermission{
	Permission:             "s3:GetObjectVersionTorrent",
	Description:            "Grants permission to get Torrent files about a different version using the versionId subresource",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetReplicationConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetReplicationConfiguration",
	Description:            "Grants permission to get the replication configuration information set on an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetStorageLensConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:GetStorageLensConfiguration",
	Description:            "Grants permission to get an Amazon S3 Storage Lens configuration",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetStorageLensConfigurationTagging = ds.DataObjectTypePermission{
	Permission:             "s3:GetStorageLensConfigurationTagging",
	Description:            "Grants permission to get the tag set of an existing Amazon S3 Storage Lens configuration",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3GetStorageLensDashboard = ds.DataObjectTypePermission{
	Permission:             "s3:GetStorageLensDashboard",
	Description:            "Grants permission to get an Amazon S3 Storage Lens dashboard",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3InitiateReplication = ds.DataObjectTypePermission{
	Permission:             "s3:InitiateReplication",
	Description:            "Grants permission to initiate the replication process by setting replication status of an object to pending",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3ListAccessPoints = ds.DataObjectTypePermission{
	Permission:             "s3:ListAccessPoints",
	Description:            "Grants permission to list access points",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListAccessPointsForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:ListAccessPointsForObjectLambda",
	Description:            "Grants permission to list object lambda enabled accesspoints",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListAllMyBuckets = ds.DataObjectTypePermission{
	Permission:             "s3:ListAllMyBuckets",
	Description:            "Grants permission to list all buckets owned by the authenticated sender of the request",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListBucket = ds.DataObjectTypePermission{
	Permission:             "s3:ListBucket",
	Description:            "Grants permission to list some or all of the objects in an Amazon S3 bucket (up to 1000)",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListBucketMultipartUploads = ds.DataObjectTypePermission{
	Description:            "Grants permission to list in-progress multipart uploads",
	Permission:             "s3:ListBucketMultipartUploads",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListBucketVersions = ds.DataObjectTypePermission{
	Permission:             "s3:ListBucketVersions",
	Description:            "Grants permission to list metadata about all the versions of objects in an Amazon S3 bucket",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListJobs = ds.DataObjectTypePermission{
	Permission:             "s3:ListJobs",
	Description:            "Grants permission to list current jobs and jobs that have ended recently",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListMultiRegionAccessPoints = ds.DataObjectTypePermission{
	Permission:             "s3:ListMultiRegionAccessPoints",
	Description:            "Grants permission to list multi region access points",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListMultipartUploadParts = ds.DataObjectTypePermission{
	Permission:             "s3:ListMultipartUploadParts",
	Description:            "Grants permission to list the parts that have been uploaded for a specific multipart upload",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ListStorageLensConfigurations = ds.DataObjectTypePermission{
	Permission:             "s3:ListStorageLensConfigurations",
	Description:            "Grants permission to list Amazon S3 Storage Lens configurations",
	GlobalPermissions:      readGlobalPermissions,
	UsageGlobalPermissions: readUsage,
}

var S3ObjectOwnerOverrideToBucketOwner = ds.DataObjectTypePermission{
	Permission:             "s3:ObjectOwnerOverrideToBucketOwner",
	Description:            "Grants permission to override the owner of an object",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutAccelerateConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutAccelerateConfiguration",
	Description:            "Grants permission to use the accelerate subresource to set the Transfer Acceleration state of an existing S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutAccessPointConfigurationForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:PutAccessPointConfigurationForObjectLambda",
	Description:            "Grants permission to set the configuration of the object lambda enabled access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutAccessPointPolicy = ds.DataObjectTypePermission{
	Permission:             "s3:PutAccessPointPolicy",
	Description:            "Grants permission to associate an access policy with a specified access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutAccessPointPolicyForObjectLambda = ds.DataObjectTypePermission{
	Permission:             "s3:PutAccessPointPolicyForObjectLambda",
	Description:            "Grants permission to associate an access policy with a specified object lambda enabled access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutAccessPointPublicAccessBlock = ds.DataObjectTypePermission{
	Permission:             "s3:PutAccessPointPublicAccessBlock",
	Description:            "Grants permission to associate public access block configurations with a specified access point, while creating a access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutAccountPublicAccessBlock = ds.DataObjectTypePermission{
	Permission:             "s3:PutAccountPublicAccessBlock",
	Description:            "Grants permission to create or modify the PublicAccessBlock configuration for an AWS account",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutAnalyticsConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutAnalyticsConfiguration",
	Description:            "Grants permission to set an analytics configuration for the bucket, specified by the analytics configuration ID",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketAcl = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketAcl",
	Description:            "Grants permission to set the permissions on an existing bucket using access control lists (ACLs)",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketCORS = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketCORS",
	Description:            "Grants permission to set the CORS configuration for an Amazon S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketLogging = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketLogging",
	Description:            "Grants permission to set the logging parameters for an Amazon S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketNotification = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketNotification",
	Description:            "Grants permission to receive notifications when certain events happen in an Amazon S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketObjectLockConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketObjectLockConfiguration",
	Description:            "Grants permission to put Object Lock configuration on a specific bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketOwnershipControls = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketOwnershipControls",
	Description:            "Grants permission to add, replace or delete ownership controls on a bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketPolicy = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketPolicy",
	Description:            "Grants permission to add or replace a bucket policy on a bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketPublicAccessBlock = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketPublicAccessBlock",
	Description:            "Grants permission to create or modify the PublicAccessBlock configuration for a specific Amazon S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutBucketRequestPayment = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketRequestPayment",
	Description:            "Grants permission to set the request payment configuration of a bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketTagging = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketTagging",
	Description:            "Grants permission to set the tags for a bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutBucketVersioning = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketVersioning",
	Description:            "Grants permission to set the versioning state of an existing Amazon S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutBucketWebsite = ds.DataObjectTypePermission{
	Permission:             "s3:PutBucketWebsite",
	Description:            "Grants permission to set the configuration of the website that is specified in the website subresource",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutEncryptionConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutEncryptionConfiguration",
	Description:            "Grants permission to set the encryption configuration for an Amazon S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutIntelligentTieringConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutIntelligentTieringConfiguration",
	Description:            "Grants permission to create new or update or delete an existing Amazon S3 Intelligent Tiering configuration",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutInventoryConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutInventoryConfiguration",
	Description:            "Grants permission to add an inventory configuration to the bucket, identified by the inventory ID",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutJobTagging = ds.DataObjectTypePermission{
	Permission:             "s3:PutJobTagging",
	Description:            "Grants permission to replace tags on an existing Amazon S3 Batch Operations job",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutLifecycleConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutLifecycleConfiguration",
	Description:            "Grants permission to create a new lifecycle configuration for the bucket or replace an existing lifecycle configuration",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutMetricsConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutMetricsConfiguration",
	Description:            "Grants permission to set or update a metrics configuration for the CloudWatch request metrics from an Amazon S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutMultiRegionAccessPointPolicy = ds.DataObjectTypePermission{
	Permission:             "s3:PutMultiRegionAccessPointPolicy",
	Description:            "Grants permission to associate an access policy with a specified multi region access point",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutObject = ds.DataObjectTypePermission{
	Permission:             "s3:PutObject",
	Description:            "Grants permission to add an object to a bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutObjectAcl = ds.DataObjectTypePermission{
	Permission:             "s3:PutObjectAcl",
	Description:            "Grants permission to set the access control list (ACL) permissions for new or existing objects in an S3 bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutObjectLegalHold = ds.DataObjectTypePermission{
	Permission:             "s3:PutObjectLegalHold",
	Description:            "Grants permission to apply a Legal Hold configuration to the specified object",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutObjectRetention = ds.DataObjectTypePermission{
	Permission:             "s3:PutObjectRetention",
	Description:            "Grants permission to place an Object Retention configuration on an object",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutObjectTagging = ds.DataObjectTypePermission{
	Permission:             "s3:PutObjectTagging",
	Description:            "Grants permission to set the supplied tag-set to an object that already exists in a bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutObjectVersionAcl = ds.DataObjectTypePermission{
	Permission:             "s3:PutObjectVersionAcl",
	Description:            "Grants permission to use the acl subresource to set the access control list (ACL) permissions for an object that already exists in a bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutObjectVersionTagging = ds.DataObjectTypePermission{
	Permission:             "s3:PutObjectVersionTagging",
	Description:            "Grants permission to set the supplied tag-set for a specific version of an object",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3PutReplicationConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutReplicationConfiguration",
	Description:            "Grants permission to create a new replication configuration or replace an existing one",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutStorageLensConfiguration = ds.DataObjectTypePermission{
	Permission:             "s3:PutStorageLensConfiguration",
	Description:            "Grants permission to create or update an Amazon S3 Storage Lens configuration",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3PutStorageLensConfigurationTagging = ds.DataObjectTypePermission{
	Permission:             "s3:PutStorageLensConfigurationTagging",
	Description:            "Grants permission to put or replace tags on an existing Amazon S3 Storage Lens configuration",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3ReplicateDelete = ds.DataObjectTypePermission{
	Permission:             "s3:ReplicateDelete",
	Description:            "Grants permission to replicate delete markers to the destination bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3ReplicateObject = ds.DataObjectTypePermission{
	Permission:             "s3:ReplicateObject",
	Description:            "Grants permission to replicate objects and object tags to the destination bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3ReplicateTags = ds.DataObjectTypePermission{
	Permission:             "s3:ReplicateTags",
	Description:            "Grants permission to replicate object tags to the destination bucket",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: adminUsage,
}

var S3RestoreObject = ds.DataObjectTypePermission{
	Permission:             "s3:RestoreObject",
	Description:            "Grants permission to restore an archived copy of an object back into Amazon S3",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3UpdateJobPriority = ds.DataObjectTypePermission{
	Permission:             "s3:UpdateJobPriority",
	Description:            "Grants permission to update the priority of an existing job",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var S3UpdateJobStatus = ds.DataObjectTypePermission{
	Permission:             "s3:UpdateJobStatus",
	Description:            "Grants permission to update the status for the specified job",
	GlobalPermissions:      writeGlobalPermissions,
	UsageGlobalPermissions: writeUsage,
}

var applicableS3AccessPointActions set.Set[string]
var applicableS3AccessPointActionsMutex sync.Mutex

func ApplicableS3AccessPointActions() set.Set[string] {
	applicableS3AccessPointActionsMutex.Lock()
	defer applicableS3AccessPointActionsMutex.Unlock()

	if applicableS3AccessPointActions != nil {
		return applicableS3AccessPointActions
	}

	applicableS3AccessPointActions = set.NewSet[string]()

	for _, permission := range S3AccessPointPermissions {
		applicableS3AccessPointActions.Add(permission.Permission)
	}

	return applicableS3AccessPointActions
}

var permissionLookupTable map[string]*ds.DataObjectTypePermission

func GetS3Permission(permission string) (*ds.DataObjectTypePermission, bool) {
	if permissionLookupTable == nil {
		permissionLookupTable = make(map[string]*ds.DataObjectTypePermission)

		for i := range AllS3Permissions {
			p := AllS3Permissions[i]
			permissionLookupTable[p.Permission] = p
		}
	}

	p, found := permissionLookupTable[permission]

	return p, found
}
