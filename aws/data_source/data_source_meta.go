package data_source

import (
	"fmt"
	"strings"
	"sync"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	ds "github.com/raito-io/cli/base/data_source"
)

var metaData *ds.MetaData
var dataObjects map[string]*ds.DataObjectType
var mu sync.Mutex

func GetDataObjectType(name string) *ds.DataObjectType {
	GetS3MetaData()

	return dataObjects[name]
}

func GetS3MetaData() *ds.MetaData {
	mu.Lock()
	defer mu.Unlock()

	if metaData == nil {
		allPermissions := getActionMetadataFromDocs()
		globalPermissions := getPermissionsForResourceType(allPermissions, []string{""})
		bucketPermissions := getPermissionsForResourceType(allPermissions, []string{"", "bucket"})
		objectPermissions := getPermissionsForResourceType(allPermissions, []string{"", "bucket", "object"})

		metaData = &ds.MetaData{
			Type:                  "aws-account",
			SupportedFeatures:     []string{""},
			SupportsApInheritance: true,
			DataObjectTypes: []*ds.DataObjectType{
				{
					Name:        ds.Datasource,
					Type:        ds.Datasource,
					Permissions: globalPermissions,
					Children:    []string{ds.Bucket},
				},
				{
					Name:        ds.Bucket,
					Type:        ds.Bucket,
					Label:       "S3 Bucket",
					Permissions: bucketPermissions,
					Children:    []string{ds.Folder, ds.File, model.GlueTable},
				},
				{
					Name:        ds.Folder,
					Type:        ds.Folder,
					Label:       "S3 Folder",
					Permissions: objectPermissions,
					Children:    []string{ds.Folder, ds.File, model.GlueTable},
				},
				{
					Name:        ds.File,
					Type:        ds.File,
					Label:       "S3 File",
					Permissions: objectPermissions,
					Children:    []string{},
				},
				{
					Name:        model.GlueTable,
					Type:        ds.Table,
					Label:       "Glue Table",
					Permissions: objectPermissions,
					Children:    []string{},
				},
			},
			UsageMetaInfo: &ds.UsageMetaInput{
				DefaultLevel: ds.File,
				Levels: []*ds.UsageMetaInputDetail{
					{
						Name:            ds.File,
						DataObjectTypes: []string{ds.File},
					},
				},
			},
			AccessProviderTypes: []*ds.AccessProviderType{
				{
					Type:                          string(model.Role),
					Label:                         "AWS Role",
					Icon:                          "",
					IsNamedEntity:                 true,
					CanBeCreated:                  true,
					CanBeAssumed:                  true,
					CanAssumeMultiple:             false,
					AllowedWhoAccessProviderTypes: []string{string(model.Role)},
				},
				{
					Type:                          string(model.SSORole),
					Label:                         "AWS SSO Role",
					Icon:                          "",
					IsNamedEntity:                 true,
					CanBeCreated:                  false,
					CanBeAssumed:                  true,
					CanAssumeMultiple:             false,
					AllowedWhoAccessProviderTypes: []string{},
					IdentityStoreTypeForWho:       "aws-organization",
				},
				{
					Type:                          string(model.Policy),
					Label:                         "AWS Policy",
					Icon:                          "",
					IsNamedEntity:                 true,
					CanBeCreated:                  true,
					CanBeAssumed:                  false,
					CanAssumeMultiple:             false,
					AllowedWhoAccessProviderTypes: []string{string(model.Policy), string(model.Role), string(model.SSORole)},
				},
				{
					Type:                          string(model.AccessPoint),
					Label:                         "AWS S3 Access Point",
					Icon:                          "",
					IsNamedEntity:                 true,
					CanBeCreated:                  true,
					CanBeAssumed:                  false,
					CanAssumeMultiple:             false,
					AllowedWhoAccessProviderTypes: []string{string(model.Role), string(model.SSORole)},
				},
			},
		}

		dataObjects = make(map[string]*ds.DataObjectType)

		for _, dot := range metaData.DataObjectTypes {
			dataObjects[dot.Name] = dot
		}
	}

	return metaData
}

func getPermissionsForResourceType(input []model.ActionMetadata, resourceTypes []string) []*ds.DataObjectTypePermission {
	result := []*ds.DataObjectTypePermission{}

	accessLevelMap := map[string][]string{}
	accessLevelMap["write"] = ds.WriteGlobalPermission().StringValues()
	accessLevelMap["permissions management"] = ds.WriteGlobalPermission().StringValues()
	accessLevelMap["tagging"] = ds.WriteGlobalPermission().StringValues()
	accessLevelMap["read"] = ds.ReadGlobalPermission().StringValues()
	accessLevelMap["list"] = ds.ReadGlobalPermission().StringValues()

	usageLevelMap := map[string][]string{}
	usageLevelMap["write"] = []string{ds.Write}
	usageLevelMap["permissions management"] = []string{ds.Admin}
	usageLevelMap["tagging"] = []string{ds.Admin}
	usageLevelMap["read"] = []string{ds.Read}
	usageLevelMap["list"] = []string{ds.Read}
	// Actions don't need to be defined, as the permissions correspond to Actions (e.g. GetObject)

	for _, actionMetadata := range input {
		if isPermissionForResourceTypes(actionMetadata, resourceTypes) {
			result = append(result, &ds.DataObjectTypePermission{
				Permission:             fmt.Sprintf("%s:%s", constants.S3PermissionPrefix, actionMetadata.Action),
				Description:            actionMetadata.Description,
				GlobalPermissions:      accessLevelMap[strings.ToLower(actionMetadata.AccessLevel)],
				UsageGlobalPermissions: usageLevelMap[strings.ToLower(actionMetadata.AccessLevel)],
			})
		}
	}

	return result
}

func isPermissionForResourceTypes(actionMetaData model.ActionMetadata, resourceTypes []string) bool {
	for _, resourceType := range resourceTypes {
		if strings.HasPrefix(actionMetaData.ResourceTypes, strings.ToLower(resourceType)) ||
			strings.EqualFold(actionMetaData.ResourceTypes, resourceType) {
			return true
		}
	}

	return false
}

func getActionMetadataFromDocs() []model.ActionMetadata {
	// taken from https://docs.aws.amazon.com/AmazonS3/latest/userguide/list_amazons3.html#amazons3-resources-for-iam-policies
	// the following access levels are available: read, write, list, permissions management, tagging
	return []model.ActionMetadata{
		{
			Action:        "AbortMultipartUpload",
			Description:   "Grants permission to abort a multipart upload",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "BypassGovernanceRetention",
			Description:   "Grants permission to allow circumvention of governance-mode object retention settings",
			AccessLevel:   "Permissions management",
			ResourceTypes: "object*",
		},
		{
			Action:        "CreateAccessPoint",
			Description:   "Grants permission to create a new access point",
			AccessLevel:   "Write",
			ResourceTypes: "accesspoint*",
		},
		{
			Action:        "CreateAccessPointForObjectLambda",
			Description:   "Grants permission to create an object lambda enabled accesspoint",
			AccessLevel:   "Write",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "CreateBucket",
			Description:   "Grants permission to create a new bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "CreateJob",
			Description:   "Grants permission to create a new Amazon S3 Batch Operations job",
			AccessLevel:   "Write",
			ResourceTypes: "",
		},
		{
			Action:        "CreateMultiRegionAccessPoint",
			Description:   "Grants permission to create a new multi region access point",
			AccessLevel:   "Write",
			ResourceTypes: "multiregionaccesspoint*",
		},
		{
			Action:        "DeleteAccessPoint",
			Description:   "Grants permission to delete the access point named in the URI",
			AccessLevel:   "Write",
			ResourceTypes: "accesspoint*",
		},
		{
			Action:        "DeleteAccessPointForObjectLambda",
			Description:   "Grants permission to delete the object lambda enabled access point named in the URI",
			AccessLevel:   "Write",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "DeleteAccessPointPolicy",
			Description:   "Grants permission to delete the policy on a specified access point",
			AccessLevel:   "Permissions management",
			ResourceTypes: "accesspoint*",
		},
		{
			Action:        "DeleteAccessPointPolicyForObjectLambda",
			Description:   "Grants permission to delete the policy on a specified object lambda enabled access point",
			AccessLevel:   "Permissions management",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "DeleteBucket",
			Description:   "Grants permission to delete the bucket named in the URI",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "DeleteBucketPolicy",
			Description:   "Grants permission to delete the policy on a specified bucket",
			AccessLevel:   "Permissions management",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "DeleteBucketWebsite",
			Description:   "Grants permission to remove the website configuration for a bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "DeleteJobTagging",
			Description:   "Grants permission to remove tags from an existing Amazon S3 Batch Operations job",
			AccessLevel:   "Tagging",
			ResourceTypes: "job*",
		},
		{
			Action:        "DeleteMultiRegionAccessPoint",
			Description:   "Grants permission to delete the multi region access point named in the URI",
			AccessLevel:   "Write",
			ResourceTypes: "multiregionaccesspoint*",
		},
		{
			Action:        "DeleteObject",
			Description:   "Grants permission to remove the null version of an object and insert a delete marker, which becomes the current version of the object",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "DeleteObjectTagging",
			Description:   "Grants permission to use the tagging subresource to remove the entire tag set from the specified object",
			AccessLevel:   "Tagging",
			ResourceTypes: "object*",
		},
		{
			Action:        "DeleteObjectVersion",
			Description:   "Grants permission to remove a specific version of an object",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "DeleteObjectVersionTagging",
			Description:   "Grants permission to remove the entire tag set for a specific version of the object",
			AccessLevel:   "Tagging",
			ResourceTypes: "object*",
		},
		{
			Action:        "DeleteStorageLensConfiguration",
			Description:   "Grants permission to delete an existing Amazon S3 Storage Lens configuration",
			AccessLevel:   "Write",
			ResourceTypes: "storagelensconfiguration*",
		},
		{
			Action:        "DeleteStorageLensConfigurationTagging",
			Description:   "Grants permission to remove tags from an existing Amazon S3 Storage Lens configuration",
			AccessLevel:   "Tagging",
			ResourceTypes: "storagelensconfiguration*",
		},
		{
			Action:        "DescribeJob",
			Description:   "Grants permission to retrieve the configuration parameters and status for a batch operations job",
			AccessLevel:   "Read",
			ResourceTypes: "job*",
		},
		{
			Action:        "DescribeMultiRegionAccessPointOperation",
			Description:   "Grants permission to retrieve the configurations for a multi region access point",
			AccessLevel:   "Read",
			ResourceTypes: "multiregionaccesspointrequestarn*",
		},
		{
			Action:        "GetAccelerateConfiguration",
			Description:   "Grants permission to uses the accelerate subresource to return the Transfer Acceleration state of a bucket, which is either Enabled or Suspended",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetAccessPoint",
			Description:   "Grants permission to return configuration information about the specified access point",
			AccessLevel:   "Read",
			ResourceTypes: "",
		},
		{
			Action:        "GetAccessPointConfigurationForObjectLambda",
			Description:   "Grants permission to retrieve the configuration of the object lambda enabled access point",
			AccessLevel:   "Read",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "GetAccessPointForObjectLambda",
			Description:   "Grants permission to create an object lambda enabled accesspoint",
			AccessLevel:   "Read",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "GetAccessPointPolicy",
			Description:   "Grants permission to returns the access point policy associated with the specified access point",
			AccessLevel:   "Read",
			ResourceTypes: "accesspoint*",
		},
		{
			Action:        "GetAccessPointPolicyForObjectLambda",
			Description:   "Grants permission to returns the access point policy associated with the specified object lambda enabled access point",
			AccessLevel:   "Read",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "GetAccessPointPolicyStatus",
			Description:   "Grants permission to return the policy status for a specific access point policy",
			AccessLevel:   "Read",
			ResourceTypes: "accesspoint*",
		},
		{
			Action:        "GetAccessPointPolicyStatusForObjectLambda",
			Description:   "Grants permission to return the policy status for a specific object lambda access point policy",
			AccessLevel:   "Read",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "GetAccountPublicAccessBlock",
			Description:   "Grants permission to retrieve the PublicAccessBlock configuration for an AWS account",
			AccessLevel:   "Read",
			ResourceTypes: "",
		},
		{
			Action:        "GetAnalyticsConfiguration",
			Description:   "Grants permission to get an analytics configuration from an Amazon S3 bucket, identified by the analytics configuration ID",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketAcl",
			Description:   "Grants permission to use the acl subresource to return the access control list (ACL) of an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketCORS",
			Description:   "Grants permission to return the CORS configuration information set for an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketLocation",
			Description:   "Grants permission to return the Region that an Amazon S3 bucket resides in",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketLogging",
			Description:   "Grants permission to return the logging status of an Amazon S3 bucket and the permissions users have to view or modify that status",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketNotification",
			Description:   "Grants permission to get the notification configuration of an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketObjectLockConfiguration",
			Description:   "Grants permission to get the Object Lock configuration of an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketOwnershipControls",
			Description:   "Grants permission to retrieve ownership controls on a bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketPolicy",
			Description:   "Grants permission to return the policy of the specified bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketPolicyStatus",
			Description:   "Grants permission to retrieve the policy status for a specific Amazon S3 bucket, which indicates whether the bucket is public",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketPublicAccessBlock",
			Description:   "Grants permission to retrieve the PublicAccessBlock configuration for an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketRequestPayment",
			Description:   "Grants permission to return the request payment configuration for an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketTagging",
			Description:   "Grants permission to return the tag set associated with an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketVersioning",
			Description:   "Grants permission to return the versioning state of an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetBucketWebsite",
			Description:   "Grants permission to return the website configuration for an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetEncryptionConfiguration",
			Description:   "Grants permission to return the default encryption configuration an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetIntelligentTieringConfiguration",
			Description:   "Grants permission to get an or list all Amazon S3 Intelligent Tiering configuration in a S3 Bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetInventoryConfiguration",
			Description:   "Grants permission to return an inventory configuration from an Amazon S3 bucket, identified by the inventory configuration ID",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetJobTagging",
			Description:   "Grants permission to return the tag set of an existing Amazon S3 Batch Operations job",
			AccessLevel:   "Read",
			ResourceTypes: "job*",
		},
		{
			Action:        "GetLifecycleConfiguration",
			Description:   "Grants permission to return the lifecycle configuration information set on an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetMetricsConfiguration",
			Description:   "Grants permission to get a metrics configuration from an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetMultiRegionAccessPoint",
			Description:   "Grants permission to return configuration information about the specified multi region access point",
			AccessLevel:   "Read",
			ResourceTypes: "multiregionaccesspoint*",
		},
		{
			Action:        "GetMultiRegionAccessPointPolicy",
			Description:   "Grants permission to returns the access point policy associated with the specified multi region access point",
			AccessLevel:   "Read",
			ResourceTypes: "multiregionaccesspoint*",
		},
		{
			Action:        "GetMultiRegionAccessPointPolicyStatus",
			Description:   "Grants permission to return the policy status for a specific multi region access point policy",
			AccessLevel:   "Read",
			ResourceTypes: "multiregionaccesspoint*",
		},
		{
			Action:        "GetObject",
			Description:   "Grants permission to retrieve objects from Amazon S3",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectAcl",
			Description:   "Grants permission to return the access control list (ACL) of an object",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectAttributes",
			Description:   "Grants permission to retrieve attributes related to a specific object",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectLegalHold",
			Description:   "Grants permission to get an object's current Legal Hold status",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectRetention",
			Description:   "Grants permission to retrieve the retention settings for an object",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectTagging",
			Description:   "Grants permission to return the tag set of an object",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectTorrent",
			Description:   "Grants permission to return torrent files from an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectVersion",
			Description:   "Grants permission to retrieve a specific version of an object",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectVersionAcl",
			Description:   "Grants permission to return the access control list (ACL) of a specific object version",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectVersionAttributes",
			Description:   "Grants permission to retrieve attributes related to a specific version of an object",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectVersionForReplication",
			Description:   "Grants permission to replicate both unencrypted objects and objects encrypted with SSE-S3 or SSE-KMS",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectVersionTagging",
			Description:   "Grants permission to return the tag set for a specific version of the object",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetObjectVersionTorrent",
			Description:   "Grants permission to get Torrent files about a different version using the versionId subresource",
			AccessLevel:   "Read",
			ResourceTypes: "object*",
		},
		{
			Action:        "GetReplicationConfiguration",
			Description:   "Grants permission to get the replication configuration information set on an Amazon S3 bucket",
			AccessLevel:   "Read",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "GetStorageLensConfiguration",
			Description:   "Grants permission to get an Amazon S3 Storage Lens configuration",
			AccessLevel:   "Read",
			ResourceTypes: "storagelensconfiguration*",
		},
		{
			Action:        "GetStorageLensConfigurationTagging",
			Description:   "Grants permission to get the tag set of an existing Amazon S3 Storage Lens configuration",
			AccessLevel:   "Read",
			ResourceTypes: "storagelensconfiguration*",
		},
		{
			Action:        "GetStorageLensDashboard",
			Description:   "Grants permission to get an Amazon S3 Storage Lens dashboard",
			AccessLevel:   "Read",
			ResourceTypes: "storagelensconfiguration*",
		},
		{
			Action:        "InitiateReplication",
			Description:   "Grants permission to initiate the replication process by setting replication status of an object to pending",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "ListAccessPoints",
			Description:   "Grants permission to list access points",
			AccessLevel:   "List",
			ResourceTypes: "",
		},
		{
			Action:        "ListAccessPointsForObjectLambda",
			Description:   "Grants permission to list object lambda enabled accesspoints",
			AccessLevel:   "List",
			ResourceTypes: "",
		},
		{
			Action:        "ListAllMyBuckets",
			Description:   "Grants permission to list all buckets owned by the authenticated sender of the request",
			AccessLevel:   "List",
			ResourceTypes: "",
		},
		{
			Action:        "ListBucket",
			Description:   "Grants permission to list some or all of the objects in an Amazon S3 bucket (up to 1000)",
			AccessLevel:   "List",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "ListBucketMultipartUploads",
			Description:   "Grants permission to list in-progress multipart uploads",
			AccessLevel:   "List",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "ListBucketVersions",
			Description:   "Grants permission to list metadata about all the versions of objects in an Amazon S3 bucket",
			AccessLevel:   "List",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "ListJobs",
			Description:   "Grants permission to list current jobs and jobs that have ended recently",
			AccessLevel:   "List",
			ResourceTypes: "",
		},
		{
			Action:        "ListMultiRegionAccessPoints",
			Description:   "Grants permission to list multi region access points",
			AccessLevel:   "List",
			ResourceTypes: "",
		},
		{
			Action:        "ListMultipartUploadParts",
			Description:   "Grants permission to list the parts that have been uploaded for a specific multipart upload",
			AccessLevel:   "List",
			ResourceTypes: "object*",
		},
		{
			Action:        "ListStorageLensConfigurations",
			Description:   "Grants permission to list Amazon S3 Storage Lens configurations",
			AccessLevel:   "List",
			ResourceTypes: "",
		},
		{
			Action:        "ObjectOwnerOverrideToBucketOwner",
			Description:   "Grants permission to change replica ownership",
			AccessLevel:   "Permissions management",
			ResourceTypes: "object*",
		},
		{
			Action:        "PutAccelerateConfiguration",
			Description:   "Grants permission to use the accelerate subresource to set the Transfer Acceleration state of an existing S3 bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutAccessPointConfigurationForObjectLambda",
			Description:   "Grants permission to set the configuration of the object lambda enabled access point",
			AccessLevel:   "Write",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "PutAccessPointPolicy",
			Description:   "Grants permission to associate an access policy with a specified access point",
			AccessLevel:   "Permissions management",
			ResourceTypes: "accesspoint*",
		},
		{
			Action:        "PutAccessPointPolicyForObjectLambda",
			Description:   "Grants permission to associate an access policy with a specified object lambda enabled access point",
			AccessLevel:   "Permissions management",
			ResourceTypes: "objectlambdaaccesspoint*",
		},
		{
			Action:        "PutAccessPointPublicAccessBlock",
			Description:   "Grants permission to associate public access block configurations with a specified access point, while creating a access point",
			AccessLevel:   "Permissions management",
			ResourceTypes: "",
		},
		{
			Action:        "PutAccountPublicAccessBlock",
			Description:   "Grants permission to create or modify the PublicAccessBlock configuration for an AWS account",
			AccessLevel:   "Permissions management",
			ResourceTypes: "",
		},
		{
			Action:        "PutAnalyticsConfiguration",
			Description:   "Grants permission to set an analytics configuration for the bucket, specified by the analytics configuration ID",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketAcl",
			Description:   "Grants permission to set the permissions on an existing bucket using access control lists (ACLs)",
			AccessLevel:   "Permissions management",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketCORS",
			Description:   "Grants permission to set the CORS configuration for an Amazon S3 bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketLogging",
			Description:   "Grants permission to set the logging parameters for an Amazon S3 bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketNotification",
			Description:   "Grants permission to receive notifications when certain events happen in an Amazon S3 bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketObjectLockConfiguration",
			Description:   "Grants permission to put Object Lock configuration on a specific bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketOwnershipControls",
			Description:   "Grants permission to add, replace or delete ownership controls on a bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketPolicy",
			Description:   "Grants permission to add or replace a bucket policy on a bucket",
			AccessLevel:   "Permissions management",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketPublicAccessBlock",
			Description:   "Grants permission to create or modify the PublicAccessBlock configuration for a specific Amazon S3 bucket",
			AccessLevel:   "Permissions management",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketRequestPayment",
			Description:   "Grants permission to set the request payment configuration of a bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketTagging",
			Description:   "Grants permission to add a set of tags to an existing Amazon S3 bucket",
			AccessLevel:   "Tagging",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketVersioning",
			Description:   "Grants permission to set the versioning state of an existing Amazon S3 bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutBucketWebsite",
			Description:   "Grants permission to set the configuration of the website that is specified in the website subresource",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutEncryptionConfiguration",
			Description:   "Grants permission to set the encryption configuration for an Amazon S3 bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutIntelligentTieringConfiguration",
			Description:   "Grants permission to create new or update or delete an existing Amazon S3 Intelligent Tiering configuration",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutInventoryConfiguration",
			Description:   "Grants permission to add an inventory configuration to the bucket, identified by the inventory ID",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutJobTagging",
			Description:   "Grants permission to replace tags on an existing Amazon S3 Batch Operations job",
			AccessLevel:   "Tagging",
			ResourceTypes: "job*",
		},
		{
			Action:        "PutLifecycleConfiguration",
			Description:   "Grants permission to create a new lifecycle configuration for the bucket or replace an existing lifecycle configuration",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutMetricsConfiguration",
			Description:   "Grants permission to set or update a metrics configuration for the CloudWatch request metrics from an Amazon S3 bucket",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutMultiRegionAccessPointPolicy",
			Description:   "Grants permission to associate an access policy with a specified multi region access point",
			AccessLevel:   "Permissions management",
			ResourceTypes: "multiregionaccesspoint*",
		},
		{
			Action:        "PutObject",
			Description:   "Grants permission to add an object to a bucket",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "PutObjectAcl",
			Description:   "Grants permission to set the access control list (ACL) permissions for new or existing objects in an S3 bucket",
			AccessLevel:   "Permissions management",
			ResourceTypes: "object*",
		},
		{
			Action:        "PutObjectLegalHold",
			Description:   "Grants permission to apply a Legal Hold configuration to the specified object",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "PutObjectRetention",
			Description:   "Grants permission to place an Object Retention configuration on an object",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "PutObjectTagging",
			Description:   "Grants permission to set the supplied tag-set to an object that already exists in a bucket",
			AccessLevel:   "Tagging",
			ResourceTypes: "object*",
		},
		{
			Action:        "PutObjectVersionAcl",
			Description:   "Grants permission to use the acl subresource to set the access control list (ACL) permissions for an object that already exists in a bucket",
			AccessLevel:   "Permissions management",
			ResourceTypes: "object*",
		},
		{
			Action:        "PutObjectVersionTagging",
			Description:   "Grants permission to set the supplied tag-set for a specific version of an object",
			AccessLevel:   "Tagging",
			ResourceTypes: "object*",
		},
		{
			Action:        "PutReplicationConfiguration",
			Description:   "Grants permission to create a new replication configuration or replace an existing one",
			AccessLevel:   "Write",
			ResourceTypes: "bucket*",
		},
		{
			Action:        "PutStorageLensConfiguration",
			Description:   "Grants permission to create or update an Amazon S3 Storage Lens configuration",
			AccessLevel:   "Write",
			ResourceTypes: "",
		},
		{
			Action:        "PutStorageLensConfigurationTagging",
			Description:   "Grants permission to put or replace tags on an existing Amazon S3 Storage Lens configuration",
			AccessLevel:   "Tagging",
			ResourceTypes: "storagelensconfiguration*",
		},
		{
			Action:        "ReplicateDelete",
			Description:   "Grants permission to replicate delete markers to the destination bucket",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "ReplicateObject",
			Description:   "Grants permission to replicate objects and object tags to the destination bucket",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "ReplicateTags",
			Description:   "Grants permission to replicate object tags to the destination bucket",
			AccessLevel:   "Tagging",
			ResourceTypes: "object*",
		},
		{
			Action:        "RestoreObject",
			Description:   "Grants permission to restore an archived copy of an object back into Amazon S3",
			AccessLevel:   "Write",
			ResourceTypes: "object*",
		},
		{
			Action:        "UpdateJobPriority",
			Description:   "Grants permission to update the priority of an existing job",
			AccessLevel:   "Write",
			ResourceTypes: "job*",
		},
		{
			Action:        "UpdateJobStatus",
			Description:   "Grants permission to update the status for the specified job",
			AccessLevel:   "Write",
			ResourceTypes: "job*",
		},
	}
}
