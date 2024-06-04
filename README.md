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
Over time, multiple AWS services will be supported, but at the moment only S3 is supported. The plugin can
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
Access Controls defined in Raito Cloud, are converted into IAM Roles and Policies in AWS, depending on the type of access control chosen.

At this point in time, access controls of type policy are always managed policies (not inline) and attached to the necessary users, groups and/or roles.
Access Controls of type policy that were originally imported for the inline policies of users or groups and that were now internalized in Raito Cloud, will now be created as managed policies as well. The original inline policies that created the Access Control of type policy will be removed.

Access Controls of type role are converted into IAM roles and their WHAT items are converted into inline policies attached to the IAM Role. In a later version of the plugin, this can be made more flexible to generate a combination of inline and managed policies to avoid running into the sizing limitations.

## Prerequisites
To use this plugin, you will need

1. The Raito CLI to be correctly installed. You can check out our [documentation](http://docs.raito.io/docs/cli/installation) for help on this.
2. A Raito Cloud account to synchronize your AWS account with. If you don't have this yet, visit our webpage at (https://www.raito.io/trial) and request a trial account.
3. Access to your AWS environment. Minimal required permissions still need to be defined. Right now we assume that you're set up with one of the default SDK
authentication options: https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html#credentialProviderChain. 

## Warnings and Limitations

The plugin only supports a limited set of features and permissions from AWS IAM. In most cases, warnings are logged when things the plugin comes across features it does not support.

 - Only policy statements with the `Allow` effect are taken into consideration. This means that, for example, 'Deny' policies are not supported.
 - Permission boundaries are not supported 
 - S3 Bucket Policies and Bucket ACLs are current not supported
 - IMPORTANT WARNING: The plugin only recognizes a limited set of permissions and services, (currently only S3). As a result, only policies and roles encompassing these permissions will be incorporated into Raito Cloud. This presents a partial representation of the entire AWS IAM environment. It's crucial to consider this limitation when internalizing external Access Controls into Raito Cloud, as it might override or even eliminate roles, policies, or permissions in AWS IAM that the plugin doesn't recognize. Hence, it's preferable to create new Access Controls rather than internalizing existing ones. Users will receive a warning if they attempt to internalize an Access Control that could be incomplete.

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

## To Do

* Access from Raito to AWS
  * Access-as-code
  * Limit the data we fetch and possibly don't need
  * No support for aws_sso_role yet (organization)
* Implement dynamic metadata fetching (needs configMap) for AP types, DO types, permissions ...
* Support for other AWS partitions everywhere (e.g. china and gov-cloud) (typically not working in arn matching)
* To improve: Error handling (for concurrent jobs). See 'error handling' TODOs
* How do we handle the case where the name of a policy is the same as the name of a role? This would currently create problems
* Documentation (readme and docs)
  * How role and policy inheritance is handled 'to target'
  * How inline policies are handled 'from target'

Not planned for now
* Denies as Action in policies
* Permission boundaries
* Bucket Policies
* Bucket ACLs
