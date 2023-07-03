package aws

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	importer "github.com/raito-io/cli/base/access_provider/sync_to_target"

	aws_types "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// TODO: this is a place to group all filter functions that are used for development/demo in one file; to be thrown away later

func useBucket(bucket types.Bucket) bool {
	return true
}

func getPolicyName(ap importer.AccessProvider) string {
	name := ap.NamingHint
	name = strings.ReplaceAll(name, " ", "_")

	return name
}

func filterApImportList(importList []AccessProviderInputExtended) []AccessProviderInputExtended {
	result := []AccessProviderInputExtended{}

	devMode := true

	for _, apInput := range importList {
		// inline role policies will only be included if the parent role is actually imported
		if apInput.PolicyType == InlineRole {
			continue
		}

		if apInput.PolicyType == Role {
			result = append(result, apInput)
			continue
		}

		if devMode && strings.HasPrefix(apInput.ApInput.NamingHint, ManagedPrefix) && !strings.Contains(apInput.ApInput.Name, "Administrator") &&
			!strings.Contains(apInput.ApInput.Name, "S3") {
			continue
		}

		hasS3Actions := false

		if apInput.ApInput.What != nil && len(apInput.ApInput.What) > 0 {
			for _, whatItem := range apInput.ApInput.What {
				for _, permission := range whatItem.Permissions {
					if permission == "*" || strings.HasPrefix(permission, "s3:") {
						hasS3Actions = true
						break
					}
				}

				if hasS3Actions {
					break
				}
			}
		}

		if !hasS3Actions {
			continue
		}

		result = append(result, apInput)
	}

	return result
}

func printDebugAp(ap importer.AccessProvider) {
	logger.Info(fmt.Sprintf("=================  ap name: %v =================  ", ap.Name))

	if ap.ActualName != nil {
		logger.Info(fmt.Sprintf("=================  ap actual name: %v =================  ", *ap.ActualName))
	}

	logger.Info(fmt.Sprintf("=================  ap naming hint: %v =================  ", ap.NamingHint))
	logger.Info(fmt.Sprintf("=================  ap ID: %v =================  ", ap.Id))

	if ap.Who.Users != nil {
		logger.Info(fmt.Sprintf("AP %s users: %s", ap.Name, ap.Who.Users))
	}

	if ap.Who.Groups != nil {
		logger.Info(fmt.Sprintf("AP %s groups: %s", ap.Name, ap.Who.Groups))
	}

	if ap.Who.InheritFrom != nil {
		logger.Info(fmt.Sprintf("AP %s inherit from: %s", ap.Name, ap.Who.InheritFrom))
	}

	if ap.Who.UsersInGroups != nil {
		logger.Info(fmt.Sprintf("AP %s users in groups: %s", ap.Name, ap.Who.UsersInGroups))
	}

	if ap.Who.UsersInherited != nil {
		logger.Info(fmt.Sprintf("AP %s users inherited: %s", ap.Name, ap.Who.UsersInherited))
	}
}

func discardPolicy(policy aws_types.Policy) bool {
	if *policy.AttachmentCount == 0 && !(strings.Contains(*policy.PolicyName, "TestProvider") || strings.Contains(*policy.PolicyName, "TestFileProvider")) {
		return true
	}

	return false
}
