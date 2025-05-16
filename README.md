<hr/>

<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/raito-io/raito-io.github.io/raw/master/assets/images/logo-vertical-dark%402x.png">
    <img height="250px" src="https://github.com/raito-io/raito-io.github.io/raw/master/assets/images/logo-vertical%402x.png">
  </picture>
</h1>

<h4 align="center">
  AWS plugin for the Raito CLI
</h4>

<p align="center">
    <a href="/LICENSE.md" target="_blank"><img src="https://img.shields.io/badge/license-Apache%202-brightgreen.svg?label=License" alt="Software License" /></a>
    <img src="https://img.shields.io/github/v/release/raito-io/cli-plugin-aws-account?sort=semver&label=Release&color=651FFF" />
    <a href="https://github.com/raito-io/cli-plugin-aws-account/actions/workflows/build.yml" target="_blank"><img src="https://img.shields.io/github/actions/workflow/status/raito-io/cli-plugin-aws-account/build.yml?branch=main" alt="Build status" /></a>
    <a href="https://codecov.io/gh/raito-io/cli-plugin-aws-account" target="_blank"><img src="https://img.shields.io/codecov/c/github/raito-io/cli-plugin-aws-account?label=Coverage" alt="Code Coverage" /></a>
    <a href="https://golang.org/"><img src="https://img.shields.io/github/go-mod/go-version/raito-io/cli-plugin-aws-account?color=7fd5ea" /></a>
</p>

<hr/>

# Raito CLI Plugin - AWS

**Note: This repository is still in an early stage of development.
At this point, no contributions are accepted to the project yet.**

This Raito CLI plugin implements the integration with AWS. It is meant to synchronize an entire AWS account with a data source in Raito Cloud. 
Over time, multiple AWS services will be supported, but at the moment only S3 is supported. The plugin can:
 - Synchronize the users and groups from IAM in the AWS account to an identity store in Raito Cloud.
 - Synchronize the AWS S3 meta data (S3 buckets, objects inside those buckets, ...) to a data source in Raito Cloud.
 - Synchronize the access controls from Raito Cloud into IAM/S3 permissions.
 - Synchronize the data usage from CloudTrail to Raito Cloud.

This plugin can be combined with the [cli-plugin-aws-organization plugin](https://github.com/raito-io/cli-plugin-aws-organization).

## How it works
This section explains more in detail how the access control synchronization works between Raito Cloud and your AWS account(s).

### From AWS 
In AWS, permissions can be provided to users in multiple ways: managed policies, inline policies, roles, (organization) permission sets, ...
These need to be converted into Access Controls in Raito. The mapping looks like this:

 - Each relevant AWS IAM Managed Policy is converted into its own Access Control with type `aws_policy` in Raito. 
 - Each relevant AWS IAM Role is converted into its own Access Control with type `aws_role` in Raito. Inline policies that are attached to the AWS role are converted into WHAT items on the access control directly.
 - Inline policies attached to groups or users in AWS IAM are converted to an Access Control per user/group. The access control is then named "User X inline policies" or "Group X inline policies" where X is the name of the corresponding user or group.

When your company used `IAM Identity Center` to manage roles through permission sets on the organization level, you can configure the plugin to also correctly read.
More information on this can be found later in this guide.

### To AWS
Access Controls defined in Raito Cloud, are converted into IAM Roles, Policies, S3 Access Points and Permission sets in AWS, depending on the type of access control chosen.

At this point in time, access controls of type policy are always managed policies (not inline) and attached to the necessary users, groups and/or roles.
Access Controls of type policy that were originally imported for the inline policies of users or groups and that were now internalized in Raito Cloud, will now be created as managed policies as well. The original inline policies that created the Access Control of type policy will be removed.

Access Controls of type role are converted into IAM roles and their WHAT items are converted into inline policies attached to the IAM Role. In a later version of the plugin, this can be made more flexible to generate a combination of inline and managed policies to avoid running into the sizing limitations.

## Prerequisites
To use this plugin, you will need

1. The Raito CLI to be correctly installed. You can check out our [documentation](http://docs.raito.io/docs/cli/installation) for help on this.
2. A Raito Cloud account to synchronize your AWS account with. If you don't have this yet, visit our webpage at (https://www.raito.io/trial) and request a trial account.
3. Access to your AWS environment. Minimal required permissions still need to be defined. Right now we assume that you're set up with one of the default SDK
authentication options: https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html#credentialProviderChain. 

## Usage
To use the plugin, add the following snippet to your Raito CLI configuration file (`raito.yml`, by default) under the `targets` section:

```yaml
- name: aws-account
  connector-name: raito-io/cli-plugin-aws-account
  data-source-id: "{{DATASOURCE_ID}}"
  identity-store-id: "{{IDENTITYSTORE_ID}}"

  aws-account-id: "{{AWS_ACCOUNT_ID}}"
  
  aws-s3-emulate-folder-structure: <true|false>
  aws-s3-max-folder-depth: 10
  aws-s3-cloudtrail-bucket: "{{AWS_CLOUDTRAIL_BUCKET}}"
```

Next, replace the values of the indicated fields with your specific values, or use [environment variables](https://docs.raito.io/docs/cli/configuration):
- `data-source-id`: The ID of the Data source you created in Raito Cloud.
- `identity-store-id`: The ID of the Identity Store you created in Raito Cloud.
- `aws-account-id`: The ID of the AWS account you want to sync. Make sure to remove the hyphens.
- `aws-profile` (optional): The AWS SDK profile to use for connecting to the AWS account to synchronize. When not specified, the default profile is used (or what is defined in the AWS_PROFILE environment variable).
- `aws-region` (optional): The AWS region to use for connecting to the AWS account to synchronize. When not specified, the default region as found by the AWS SDK is used.
- `aws-organization-profile` (optional): The AWS SDK profile where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). This is optional and can be used to get a full access trace in case access is granted through the AWS IAM Identity Center.
- `aws-organization-region` (optional): The AWS region where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). If not set and `aws-organization-profile` parameter is defined, the default region for the profile will be used.
- `aws-concurrency` (optional): The number of threads to use for concurrent API calls to AWS. The default is 5.
- `aws-s3-emulate-folder-structure` (optional): If set to true, S3 objects will be organized in a folder structure, just as in the AWS console. If set to false, you'll get a flat list of all files within a bucket. True, by default.
- `aws-s3-max-folder-depth` (optional): The maximum folder depth that will be synced. Beyond this, no folders or files will be synced. If not set, 20 is used as default.
- `aws-s3-cloudtrail-bucket`: The S3 bucket where S3 usage data, generated by AWS CloudTrail, is stored.
- `aws-s3-include-buckets` (optional): Comma-separated list of buckets to include. If specified, only these buckets will be handled. Wildcards (*) can be used.
- `aws-s3-exclude-buckets` (optional): Comma-separated list of buckets to exclude. If specified, these buckets will not be handled. Wildcard (*) can be used. Excludes have preference over includes.

You will also need to configure the Raito CLI further to connect to your Raito Cloud account, if that's not set up yet.
A full guide on how to configure the Raito CLI can be found on (http://docs.raito.io/docs/cli/configuration).

## Trying it out

As a first step, you can check if the CLI finds this plugin correctly. In a command-line terminal, execute the following command:
```bash
$> raito info raito-io/cli-plugin-aws-account
```

This will download the latest version of the plugin (if you don't have it yet) and output the name and version of the plugin, together with all the plugin-specific parameters to configure it.

When you are ready to try out the synchronization for the first time, execute:
```bash
$> raito run
```
This will take the configuration from the `raito.yml` file (in the current working directory) and start a single synchronization.

Note: if you have multiple targets configured in your configuration file, you can run only this target by adding `--only-targets aws-account` at the end of the command.

## Configuration
The following configuration parameters are available

| Configuration name                              | Description                                                                                                                                                                                                                                                                                                                                  | Mandatory | Default value    |
|-------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|------------------|
| `aws-profile`                                   | The AWS SDK profile to use for connecting to the AWS account to synchronize. When not specified, the default profile is used (or what is defined in the AWS_PROFILE environment variable).                                                                                                                                                   | False     | `${AWS_PROFILE}` |
| `aws-regions`                                   | A comma separated list of AWS regions to deal with. When not specified, only the default region as found by the AWS SDK is used. The first region in the list must be the default region.                                                                                                                                                    | False     |                  |
| `aws-organization-profile`                      | The AWS SDK profile where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). This is optional and can be used to get a full access trace in case access is granted through the AWS IAM Identity Center.                                                                                            | False     |                  |
| `aws-organization-region`                       | The AWS region where the organization is defined (e.g. where permission sets are defined in AWS Identity Center). If not set and `aws-organization-profile` is defined, the default region for the profile will be used.                                                                                                                     | False     |                  |
| `aws-organization-identity-center-instance-arn` | The ARN of the AWS IAM Identity Center instance. Required if aws `aws-organization-profile` is defined.                                                                                                                                                                                                                                      | False     |                  |
| `aws-organization-identity-store`               | The ARN of the AWS Identity Store. Required if aws `aws-organization-profile` is defined.                                                                                                                                                                                                                                                    | False     |                  |
| `aws-s3-enabled`                                | If set to true, S3 buckets and objects will be retrieved directly from the S3 API. See all other 'aws-s3-' parameters for more control over what is imported and what not. This cannot be enabled together with the `aws-glue-enabled` parameter.                                                                                            | False     | `true`           |
| `aws-s3-emulate-folder-structure`               | Emulate a folder structure for S3 objects, just like in the AWS UI.                                                                                                                                                                                                                                                                          | False     |                  |
| `aws-s3-max-folder-depth`                       | If `aws-s3-enabled` is set to true, fetch all objects up to a certain folder depth.                                                                                                                                                                                                                                                          | False     | 20               |
| `aws-s3-include-buckets`                        | Comma-separated list of buckets to include. If specified, only these buckets will be handled. Wildcards (*) can be used.                                                                                                                                                                                                                     | False     | `*`              |
| `aws-s3-exclude-buckets`                        | Comma-separated list of buckets to exclude. If specified, these buckets will not be handled. Wildcard (*) can be used. Excludes have preference over includes.                                                                                                                                                                               | False     |                  |
| `aws-concurrency`                               | The number of threads to use for concurrent API calls to AWS.                                                                                                                                                                                                                                                                                | False     | 5                |
| `aws-glue-enabled`                              | If set to true, AWS Glue Catalog will be used to fetch data objects. This approach is recommended instead of using S3 directly, because Glue allows you to define your data on a more logical level. The imported data objects will still be represented as S3 objects. This cannot be enabled together with the `aws-s3-enabled` parameter. | False     | `false`          |
| `aws-s3-cloudtrail-bucket`                      | The name of the bucket where the usage data for S3 is stored by AWS Cloud Trail. This is necessary to fetch usage data. If not set, no usage data is gathered.                                                                                                                                                                               | False     |                  |
| `aws-access-skip-iam`                           | If set to true, all IAM access entities (roles and policies) will not be read to import into Raito Cloud as access controls.                                                                                                                                                                                                                 | False     | `false`          |
| `aws-access-skip-user-inline-policies`          | If set to true, inline policies on users will not be read to import into Raito Cloud as access controls.                                                                                                                                                                                                                                     | False     | `false`          |
| `aws-access-skip-group-inline-policies`         | If set to true, inline policies on groups will not be read to import into Raito Cloud as access controls.                                                                                                                                                                                                                                    | False     | `false`          |
| `aws-access-skip-managed-policies`              | If set to true, managed policies will not be read to import into Raito Cloud as access controls.                                                                                                                                                                                                                                             | False     | `false`          |
| `aws-access-skip-aws-managed-policies`          | If set to true, AWS managed policies are excluded.                                                                                                                                                                                                                                                                                           | False     | `false`          |
| `aws-access-managed-policy-excludes`            | Optional comma-separated list of managed policy names to exclude. Regular expressions can be used (e.g. 'Amazon.+,AWS.+' will exclude all managed policies starting with Amazon or AWS).                                                                                                                                                     | False     |                  |
| `aws-access-skip-s3-access-points`              | If set to true, S3 access points will not be read to import into Raito Cloud as access controls.                                                                                                                                                                                                                                             | False     | `false`          |
| `aws-access-role-excludes`                      | Optional comma-separated list of role names to exclude. Regular expressions can be used (e.g. 'Amazon.+,AWS.+' will exclude all roles starting with Amazon or AWS).                                                                                                                                                                          | False     |                  |
| `aws-access-role-prefix`                        | Optional prefix for AWS IAM Roles generated by the connector. Note: roles currently cannot be renamed, so adding/updating this parameter later will not update existing roles.                                                                                                                                                              | False     |                  |
| `aws-access-role-suffix`                        | Optional suffix for AWS IAM Roles generated by the connector. Note: roles currently cannot be renamed, so adding/updating this parameter later will not update existing roles.                                                                                                                                                              | False     |                  |
| `aws-access-sso-role-prefix`                    | Optional prefix for Permission Sets generated by the connector. Note: permission sets currently cannot be renamed, so adding/updating this parameter later will not update existing permission sets. You can use #account# in the prefix, which will be replaced with the AWS account id this is associated with.                             | False     |                  |
| `aws-access-sso-role-suffix`                    | Optional suffix for Permission Sets generated by the connector. Note: permissions sets currently cannot be renamed, so adding/updating this parameter later will not update existing permission sets. You can use #account# in the suffix, which will be replaced with the AWS account id this is associated with.                               | False     |                  |
| `aws-access-policy-prefix`                      | Optional prefix for AWS IAM Policies generated by the connector.                                                                                                                                                                                                                                                                               | False     |                  |
| `aws-access-policy-suffix`                      | Optional suffix for AWS IAM Policies generated by the connector.                                                                                                                                                                                                                                                                               | False     |                  |
| `aws-access-point-prefix`                       | Optional prefix for S3 Access Points generated by the connector. Note: access points currently cannot be renamed, so adding/updating this parameter later will not update existing access points.                                                                                                                                             | False     |                  |
| `aws-access-point-suffix`                       | Optional suffix for S3 Access Points generated by the connector. Note: access points currently cannot be renamed, so adding/updating this parameter later will not update existing access points.                                                                                                                                             | False     |                  |
| `aws-permission-set-owner-email-tag`            | Optional comma-separated list of tag keys to put on permission sets generated by Raito for which the value will be a list of user emails (separated by a / character) representing the owners of the corresponding Grant in Raito.                                                                                                            | False     |                  |
| `aws-permission-set-owner-name-tag`             | Optional comma-separated list of tag keys to put on permission sets generated by Raito for which the value will be a list of user names (separated by a / character) representing the owners of the corresponding Grant in Raito.                                                                                                             | False     |                  |
| `aws-permission-set-owner-group-tag`            | Optional comma-separated list of tag keys to put on permission sets generated by Raito for which the value will be a list of group names (separated by a / character) representing the group owners of the corresponding Grant in Raito.                                                                                                          | False     |                  |
| `aws-permission-set-custom-tags`                | Optional comma-separated list of custom tags to put on permission sets generated by Raito in the form KEY:VALUE.                                                                                                                                                                                                                            | False     |                  |
| `aws-permission-set-account-id-tag`             | Optional comma-separated list of tag keys to put on permission sets generated by Raito for which the value will be the applicable AWS account id.                                                                                                                                                                                              | False     |                  |

### Authentication
To authenticate the AWS plugin, the AWS default provider chain will be used:
1. Environment variables: The environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` are used.
2. Shared credentials file. Credentials defined on `~/.aws/credentials` will be used. A profile can be defined with `aws-profile`, This method is required when using the organization feature. `aws-organization-profile` is mandatory in that case.
3. If running on an Amazon EC2 instance, IAM role for Amazon EC2.

More information can be found on the [AWS SDK documentation](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials).


## Supported features

| Feature             | Supported | Remarks                             |
|---------------------|-----------|-------------------------------------|
| Row level filtering | ❌         | Not applicable                      |
| Column masking      | ❌         | Not applicable                      |
| Locking             | ❌         | Not (yet) supported                 |
| Replay              | ✅         | Explicit deletes cannot be replayed |
| Usage               | ✅         | Based on CloudTrail logs            |

## Supported data objects
### S3
- Bucket
- Folder
- S3 File (if S3 is enabled)
- Glue Table (if glue is enabled)

### AWS Glue Mode (Recommended)
When `aws-glue-enabled` is enabled, all Glue tables are synced as data objects into your Raito Cloud.
This mode offers a more efficient way to synchronize data between your AWS Glue Data Catalog and Raito Cloud.
It leverages the metadata stored in Glue tables to identify relevant data, providing an additional layer of abstraction.
Grants can be created to access to Glue tables and folders.

### AWS S3 Files and Folders Mode
When `aws-s3-enabled` is enabled, all files and folders within S3 are synced as data object into your Raito Cloud.
All files and folders within the S3 buckets are used upto a fixed depth (default 20). The depth can be controlled using the `aws-s3-max-folder-depth` parameter.
Grants can be created to access to all folders and files.

## Access controls
### From Target
#### AWS Role
Roles are imported as `grant` with type `AWS Role`.
All users and groups associated with the trust policy document of the Role, are added as who-items to the grant that will be imported in Raito.
Inline policies will be parsed to extract the permissions and added as what-items to the grant that will be imported in Raito.
If organisation is defined and role start with `AWSReservedSSO_`, the role will be imported as `AWS SSO Role`.

#### AWS Permission Set
This is only done when the necessary organization parameters are set in the target configuration (`aws-organization-profile`, `aws-organization-region`, `aws-organization-identity-center-instance-arn`, `aws-organization-identity-store`).

Roles are imported as `grant` with type `AWS Permission Set`.  
What happens is that roles that start with `AWSReservedSSO_` will be matched with the corresponding permission set in the AWS IAM Identity Center from the organization account.
Everything except for the WHO component will be locked for these imported grants, because permission sets are not entirely compatible with Raito's access control model.

#### AWS Policy
Managed policies, inline user and group policies are imported as `grant` with type `AWS Policy`.
All users and groups associated with the policy are added as who-items to the grant that will be imported in Raito.
The permissions of the policy are added as what-items to the grant that will be imported in Raito.
The what, name and deleted will be locked for AWS Managed policies.

#### AWS S3 Access Point
S3 Access points are imported as `grant` with type `AWS Access Point`.
All users and groups associated with the access point are added as who-items to the grant that will be imported in Raito.
The permissions of the access point are added as what-items to the grant that will be imported in Raito.

### To Target
#### AWS Role
Grants of type `AWS Role` are exported as AWS IAM roles. 

The directly linked data objects will be converted into the inline policy of the role.
Users are directly assigned to the role and groups are unpacked to their users and assigned to the role.

#### AWS Permission Set
Grants of type `AWS Permission Set` are exported as AWS permission sets. This is only supported when the necessary organization parameters are set in the target configuration (`aws-organization-profile`, `aws-organization-region`, `aws-organization-identity-center-instance-arn`, `aws-organization-identity-store`).

Note that a permission set is created per account and the name of the permission set will contain the account ID. This is because the permission set model is not entirely compatible with Raito's access control model.
The directly linked data objects will be converted into the inline policy of the role. Grants of type AWS Policy that are linked to this grant will be linked to the resulting permission set in AWS.  
Users and groups from the who-list are directly assigned to the permission set for the target AWS account.

#### AWS Policy
Grants of type `AWS Policy` are exported as AWS IAM managed policies. 

Users and groups from the who-list are directly assigned to the policy. Links to AWS roles and permission sets are also kept up-to-date.

Note: for the link to permission sets, only diffs are applied because these links managed from the side of the permission set. This way, you can add and remove policies to/from permission sets without touching the rest.

#### AWS S3 Account Points
Grants of type `AWS Access Points` are exported as AWS S3 Access Points.

Users are directly assigned to the access point and groups are unpacked to their users and assigned to the access point. Links to AWS roles and permission sets are also kept up-to-date.

## Warnings and Limitations

The plugin only supports a limited set of features and permissions from AWS IAM. In most cases, warnings are logged when things the plugin comes across features it does not support.

- Only policy statements with the `Allow` effect are taken into consideration. This means that, for example, 'Deny' policies are not supported.
- Permission boundaries are not supported
- S3 Bucket Policies and Bucket ACLs are current not supported
- IMPORTANT WARNING: The plugin only recognizes a limited set of permissions and services, (currently only S3). As a result, only policies and roles encompassing these permissions will be incorporated into Raito Cloud. This presents a partial representation of the entire AWS IAM environment. It's crucial to consider this limitation when internalizing external Access Controls into Raito Cloud, as it might override or even eliminate roles, policies, or permissions in AWS IAM that the plugin doesn't recognize. Hence, it's preferable to create new Access Controls rather than internalizing existing ones. Users will receive a warning if they attempt to internalize an Access Control that could be incomplete.

