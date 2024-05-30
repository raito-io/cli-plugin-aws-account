package data_access

import (
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/model"
)

//go:generate go run github.com/raito-io/enumer -type=AccessProviderAction
type AccessProviderAction int

const (
	ActionUnknown AccessProviderAction = iota
	ActionExisting
	ActionCreate
	ActionUpdate
	ActionDelete
)

type AccessProviderDetails struct {
	ap                 *sync_to_target.AccessProvider
	name               string
	apType             model.AccessProviderType
	action             AccessProviderAction
	inheritance        map[model.AccessProviderType][]string
	inverseInheritance map[model.AccessProviderType][]string
	newBindings        set.Set[model.PolicyBinding]
	existingBindings   set.Set[model.PolicyBinding]
	apFeedback         *sync_to_target.AccessProviderSyncFeedback
}

func NewAccessProviderDetails(ap *sync_to_target.AccessProvider, t model.AccessProviderType, apFeedback *sync_to_target.AccessProviderSyncFeedback) *AccessProviderDetails {
	return &AccessProviderDetails{
		ap:                 ap,
		apType:             t,
		action:             ActionUnknown,
		inheritance:        map[model.AccessProviderType][]string{},
		inverseInheritance: map[model.AccessProviderType][]string{},
		apFeedback:         apFeedback,
	}
}

func (a *AccessProviderDetails) GetExistingOrNewBindings() set.Set[model.PolicyBinding] {
	if a.IsExternal() {
		return a.existingBindings
	}

	return a.newBindings
}

func (a *AccessProviderDetails) IsExternal() bool {
	return a.newBindings == nil
}
