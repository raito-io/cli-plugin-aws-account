package data_access

//go:generate go run github.com/raito-io/enumer -type=AccessProviderAction
type AccessProviderAction int

const (
	ActionUnknown AccessProviderAction = iota
	ActionExisting
	ActionCreate
	ActionUpdate
	ActionDelete
)
