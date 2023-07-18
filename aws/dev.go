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

func printDebugAp(ap importer.AccessProvider) {
	logger.Debug(fmt.Sprintf("=================  ap name: %v =================  ", ap.Name))

	if ap.ActualName != nil {
		logger.Debug(fmt.Sprintf("=================  ap actual name: %v =================  ", *ap.ActualName))
	}

	logger.Debug(fmt.Sprintf("=================  ap naming hint: %v =================  ", ap.NamingHint))
	logger.Debug(fmt.Sprintf("=================  ap ID: %v =================  ", ap.Id))

	if ap.Who.Users != nil {
		logger.Debug(fmt.Sprintf("AP %s users: %s", ap.Name, ap.Who.Users))
	}

	if ap.Who.Groups != nil {
		logger.Debug(fmt.Sprintf("AP %s groups: %s", ap.Name, ap.Who.Groups))
	}

	if ap.Who.InheritFrom != nil {
		logger.Debug(fmt.Sprintf("AP %s inherit from: %s", ap.Name, ap.Who.InheritFrom))
	}

	if ap.Who.UsersInGroups != nil {
		logger.Debug(fmt.Sprintf("AP %s users in groups: %s", ap.Name, ap.Who.UsersInGroups))
	}

	if ap.Who.UsersInherited != nil {
		logger.Debug(fmt.Sprintf("AP %s users inherited: %s", ap.Name, ap.Who.UsersInherited))
	}
}

func discardPolicy(policy aws_types.Policy) bool {
	if *policy.AttachmentCount == 0 && !(strings.Contains(*policy.PolicyName, "TestProvider") || strings.Contains(*policy.PolicyName, "TestFileProvider")) {
		return true
	}

	return false
}
