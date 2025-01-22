package data_access

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/smithy-go/ptr"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_source/permissions"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	awspolicy "github.com/raito-io/cli-plugin-aws-account/aws/policy"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/golang-set/set"
)

func (a *AccessToTargetSyncer) handleAccessPoints(ctx context.Context) {
	for _, accessPoint := range a.AccessPoints {
		newName, err := a.nameGenerator.GenerateName(accessPoint, model.AccessPoint)
		if err != nil {
			logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Error while generating name for access point %q: %s", accessPoint.Name, err.Error()))
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Generated access point name %q for grant %q", newName, accessPoint.Name))

		var origName, region string

		var existingAccessPoint *model.AwsS3AccessPoint

		if accessPoint.ExternalId != nil {
			origName, region, err = extractAccessPointNameAndRegionFromArn(getNameFromExternalId(*accessPoint.ExternalId))
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to extract access point name and region from external id %q: %s", *accessPoint.ExternalId, err.Error()))
				continue
			}

			if newName != origName {
				utils.Logger.Warn(fmt.Sprintf("New name %q does not correspond with current name %q. Renaming is currently not supported, so keeping the old name.", newName, origName))
				newName = origName
			}

			existingAccessPoint, err = a.repo.GetAccessPointByNameAndRegion(ctx, origName, region)
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Error while fetching existing access point %q: %s", origName, err.Error()))
				continue
			}
		}

		if accessPoint.Delete {
			utils.Logger.Info(fmt.Sprintf("Deleting access point %s", accessPoint.Name))

			if accessPoint.ExternalId == nil {
				utils.Logger.Info(fmt.Sprintf("No external id found for access point %s. Will consider it as already deleted.", accessPoint.Name))
				continue
			}

			err = a.repo.DeleteAccessPoint(ctx, origName, region)
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to delete access point %q: %s", accessPoint.Name, err.Error()))
			}

			continue
		}

		targetPrincipals := set.NewSet[string]()

		for _, user := range accessPoint.Who.Users {
			targetPrincipals.Add(utils.GetTrustUserPolicyArn("user", user, a.accessSyncer.account).String())
		}

		groupUsers := set.NewSet[string]()
		err = a.unpackGroups(ctx, accessPoint.Who.Groups, groupUsers)

		if err != nil {
			logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Error while unpacking groups for access point %q: %s", newName, err.Error()))
			continue
		}

		for _, user := range groupUsers.Slice() {
			targetPrincipals.Add(utils.GetTrustUserPolicyArn("user", user, a.accessSyncer.account).String())
		}

		shouldSleep := false

		for _, inherited := range accessPoint.Who.InheritFrom {
			inheritedExternalId := inherited

			if strings.HasPrefix(inherited, "ID:") {
				shouldSleep = true // sleeping because this is a newly created role. See later.

				id := inherited[3:] // Cutting off the 'ID:' prefix
				if externalId, found := a.idToExternalIdMap[id]; found {
					inheritedExternalId = externalId
				} else {
					logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to attach dependency %q to access point %q", inherited, newName))
					continue
				}
			}

			if roleName, hasCut := strings.CutPrefix(inheritedExternalId, constants.RoleTypePrefix); hasCut {
				targetPrincipals.Add(utils.GetTrustUserPolicyArn("role", roleName, a.accessSyncer.account).String())
			} else if roleName, hasCut = strings.CutPrefix(inheritedExternalId, constants.SsoRoleTypePrefix); hasCut {
				role, err2 := a.repo.GetSsoRoleWithPrefix(ctx, roleName, []string{})
				if err2 != nil {
					logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to get SSO role %q to link to access point %q: %s", roleName, newName, err2.Error()))
					continue
				}

				targetPrincipals.Add(role.ARN)
			} else {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Invalid inheritFrom value %q for access point %q", inheritedExternalId, newName))
				continue
			}
		}

		// For some reason, new roles are not immediately available to link to and cause an error when creating/updating the access point.
		// So when linking to a new role, we'll sleep for a bit to make sure it's available.
		if shouldSleep {
			time.Sleep(roleDelay * time.Second)
		}

		principals := targetPrincipals.Slice()
		sort.Strings(principals)

		// Getting the what
		statements := createPolicyStatementsFromWhat(accessPoint.What, a.cfgMap)
		whatItems := make([]sync_to_target.WhatItem, 0, len(accessPoint.What))
		whatItems = append(whatItems, accessPoint.What...)

		statements = mergeStatementsOnPermissions(statements)
		filterAccessPointPermissions(statements)

		bucketName, region, err2 := extractBucketForAccessPoint(whatItems)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("failed to extract bucket name for access point %q: %s", newName, err2.Error()))
			continue
		}

		accessPointArn := fmt.Sprintf("arn:aws:s3:%s:%s:accesspoint/%s", region, a.accessSyncer.account, newName)
		convertResourceURLsForAccessPoint(statements, accessPointArn)

		if len(principals) > 0 {
			for _, statement := range statements {
				statement.Principal = map[string][]string{
					"AWS": principals,
				}
			}
		}

		var s3ApArn string

		if existingAccessPoint == nil {
			utils.Logger.Info(fmt.Sprintf("Creating access point %s", newName))

			// Create the new access point with the who
			s3ApArn, err = a.repo.CreateAccessPoint(ctx, newName, bucketName, region, statements)
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to create access point %q: %s", newName, err.Error()))
				continue
			}
		} else {
			utils.Logger.Info(fmt.Sprintf("Updating access point %s", newName))

			// Handle the who
			err = a.repo.UpdateAccessPoint(ctx, newName, region, statements)
			if err != nil {
				logFeedbackError(a.feedbackMap[accessPoint.Id], fmt.Sprintf("Failed to update access point %q: %s", newName, err.Error()))
				continue
			}
		}

		a.lock.Lock()
		a.feedbackMap[accessPoint.Id].ExternalId = ptr.String(constants.AccessPointTypePrefix + s3ApArn)
		a.feedbackMap[accessPoint.Id].ActualName = newName
		a.idToExternalIdMap[accessPoint.Id] = constants.AccessPointTypePrefix + s3ApArn
		a.lock.Unlock()
	}
}

func extractAccessPointNameAndRegionFromArn(acArn string) (string, string, error) {
	// arn:aws:s3:us-west-2:123456789012:accesspoint/mybucket
	s3apArn, err2 := arn.Parse(acArn)
	if err2 != nil {
		return "", "", fmt.Errorf("parsing access point ARN %q: %w", acArn, err2)
	}

	return s3apArn.Resource[12:], s3apArn.Region, nil
}

func filterAccessPointPermissions(statements []*awspolicy.Statement) {
	applicableActions := permissions.ApplicableS3AccessPointActions()

	for _, statement := range statements {
		actions := make([]string, 0, len(statement.Action))

		for _, action := range statement.Action {
			if applicableActions.Contains(action) {
				actions = append(actions, action)
			}
		}

		statement.Action = actions
	}
}

// convertResourceURLsForAccessPoint converts all the resource ARNs in the policy statements to the corresponding ones for the access point.
// e.g. "arn:aws:s3:::bucket/folder1" would become "arn:aws:s3:eu-central-1:077954824694:accesspoint/operations/object/folder1/*"
func convertResourceURLsForAccessPoint(statements []*awspolicy.Statement, accessPointArn string) {
	for _, statement := range statements {
		for i, resource := range statement.Resource {
			if strings.HasPrefix(resource, "arn:aws:s3:") {
				fullName := strings.Split(resource, ":")[5]
				if strings.Contains(fullName, "/") {
					fullName = fullName[strings.Index(fullName, "/")+1:]
					if !strings.HasPrefix(fullName, "*") {
						fullName += "/*"
					}

					statement.Resource[i] = fmt.Sprintf("%s/object/%s", accessPointArn, fullName)
				} else {
					statement.Resource[i] = accessPointArn
				}
			}
		}
	}
}

// extractBucketForAccessPoint extracts the bucket name and region from the policy statements of an access point.
// When there is non found or multiple buckets, an error is returned.
func extractBucketForAccessPoint(whatItems []sync_to_target.WhatItem) (string, string, error) {
	bucket := ""
	region := ""

	for _, whatItem := range whatItems {
		thisBucket := whatItem.DataObject.FullName
		if strings.Contains(thisBucket, "/") {
			thisBucket = thisBucket[:strings.Index(thisBucket, "/")] //nolint:gocritic
		}

		parts := strings.Split(thisBucket, ":")
		if len(parts) != 3 {
			return "", "", fmt.Errorf("unexpected full name for S3 object: %s", whatItem.DataObject.FullName)
		}

		thisBucketName := parts[2]
		thisBucketRegion := parts[1]

		if bucket != "" && bucket != thisBucketName {
			return "", "", fmt.Errorf("an access point can only have one bucket associated with it")
		}

		bucket = thisBucketName
		region = thisBucketRegion
	}

	if bucket == "" {
		return "", "", fmt.Errorf("unable to determine the bucket for this access point")
	}

	return bucket, region, nil
}

// mergeStatementsOnPermissions merges statements that have the same permissions.
func mergeStatementsOnPermissions(statements []*awspolicy.Statement) []*awspolicy.Statement {
	mergedStatements := make([]*awspolicy.Statement, 0, len(statements))

	permissionMap := map[string]*awspolicy.Statement{}

	for _, s := range statements {
		actionList := s.Action
		sort.Strings(actionList)
		actions := strings.Join(actionList, ",")

		if existing, f := permissionMap[actions]; f {
			existing.Resource = append(existing.Resource, s.Resource...)
		} else {
			permissionMap[actions] = s
		}
	}

	for _, s := range permissionMap {
		mergedStatements = append(mergedStatements, s)
	}

	return mergedStatements
}
