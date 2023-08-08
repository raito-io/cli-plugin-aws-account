package aws

import (
	"fmt"

	importer "github.com/raito-io/cli/base/access_provider/sync_to_target"
)

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
