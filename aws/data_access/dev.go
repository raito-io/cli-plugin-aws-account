package data_access

import (
	"fmt"

	importer "github.com/raito-io/cli/base/access_provider/sync_to_target"

	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
)

func printDebugAp(ap *importer.AccessProvider) {
	utils.Logger.Debug(fmt.Sprintf("=================  ap name: %v =================  ", ap.Name))

	if ap.ActualName != nil {
		utils.Logger.Debug(fmt.Sprintf("=================  ap actual name: %v =================  ", *ap.ActualName))
	}

	if ap.ExternalId != nil {
		utils.Logger.Debug(fmt.Sprintf("=================  ap external id: %v =================  ", *ap.ExternalId))
	}

	utils.Logger.Debug(fmt.Sprintf("=================  ap naming hint: %v =================  ", ap.NamingHint))
	utils.Logger.Debug(fmt.Sprintf("=================  ap ID: %v =================  ", ap.Id))

	if ap.Who.Users != nil {
		utils.Logger.Debug(fmt.Sprintf("AP %s users: %s", ap.Name, ap.Who.Users))
	}

	if ap.Who.Groups != nil {
		utils.Logger.Debug(fmt.Sprintf("AP %s groups: %s", ap.Name, ap.Who.Groups))
	}

	if ap.Who.InheritFrom != nil {
		utils.Logger.Debug(fmt.Sprintf("AP %s inherit from: %s", ap.Name, ap.Who.InheritFrom))
	}
}
