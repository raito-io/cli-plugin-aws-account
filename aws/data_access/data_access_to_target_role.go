package data_access

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/smithy-go/ptr"
	"github.com/gammazero/workerpool"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/golang-set/set"
)

func (a *AccessToTargetSyncer) handleRole(ctx context.Context, role *sync_to_target.AccessProvider, name string) {
	if role.ExternalId != nil {
		origName := getNameFromExternalId(*role.ExternalId) // Parsing the name out of the external ID

		if name != origName {
			utils.Logger.Warn(fmt.Sprintf("New name %q does not correspond with current name %q. Renaming is currently not supported, so keeping the old name.", name, origName))
			name = origName
		}
	}

	if role.Delete {
		utils.Logger.Info(fmt.Sprintf("Deleting role %s", role.Name))

		err := a.repo.DeleteRole(ctx, name)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while removing role %q: %s", name, err.Error()))
		}

		return
	}

	existingRole, err := a.repo.GetRoleByName(ctx, name)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while fetching existing role %q: %s", name, err.Error()))
		return
	}

	targetUsers := set.NewSet[string]()

	for _, user := range role.Who.Users {
		targetUsers.Add(user)
	}

	err = a.unpackGroups(ctx, role.Who.Groups, targetUsers)
	if err != nil {
		logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while unpacking groups for role %q: %s", name, err.Error()))
		return
	}

	userNames := targetUsers.Slice()
	sort.Strings(userNames)

	// Getting the what
	statements := createPolicyStatementsFromWhat(role.What, a.cfgMap)

	if existingRole == nil {
		utils.Logger.Info(fmt.Sprintf("Creating role %s", name))

		created, err2 := a.repo.CreateRole(ctx, name, role.Description, userNames)
		if err2 != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to create role %q: %s", name, err2.Error()))
			return
		} else if !created {
			logFeedbackWarning(a.feedbackMap[role.Id], fmt.Sprintf("Role %q not created.", name))
			return
		}
	} else {
		utils.Logger.Info(fmt.Sprintf("Updating role %s", name))

		// Handle the who
		err = a.repo.UpdateAssumeEntities(ctx, name, userNames)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to update role %q: %s", name, err.Error()))
			return
		}

		// For roles, we always delete all the inline policies.
		// If we wouldn't do that, we would be blind on what the role actually looks like.
		// If new permissions are supported later on, we would never see them.
		err = a.repo.DeleteRoleInlinePolicies(ctx, name)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Failed to cleanup inline policies for role %q: %s", name, err.Error()))
			return
		}
	}

	a.lock.Lock()
	a.feedbackMap[role.Id].ExternalId = ptr.String(constants.RoleTypePrefix + name)
	a.feedbackMap[role.Id].ActualName = name
	a.idToExternalIdMap[role.Id] = constants.RoleTypePrefix + name
	a.lock.Unlock()

	// Handling the what of the role
	if len(statements) > 0 {
		// Create the inline policy for the what
		err = a.repo.CreateRoleInlinePolicy(ctx, name, "Raito_Inline_"+name, statements)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("failed to create inline policies for role %q: %s", name, err.Error()))
			return
		}
	}
}

func (a *AccessToTargetSyncer) handleRoles(ctx context.Context) {
	wp := workerpool.New(workerPoolSize)

	for _, role := range a.Roles {
		// Doing this synchronous as it is not thread-safe and fast enough
		name, err := a.nameGenerator.GenerateName(role, model.Role)
		if err != nil {
			logFeedbackError(a.feedbackMap[role.Id], fmt.Sprintf("Error while generating name for role %q: %s", role.Name, err.Error()))
			continue
		}

		utils.Logger.Info(fmt.Sprintf("Generated role name %q for grant %q", name, role.Name))

		wp.Submit(func() {
			a.handleRole(ctx, role, name)
		})
	}

	wp.StopWait()
}
