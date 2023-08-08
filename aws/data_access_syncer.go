package aws

type AccessSyncer struct {
	repo            dataAccessRepository
	managedPolicies []PolicyEntity
	inlinePolicies  []PolicyEntity
}

func NewDataAccessSyncer() *AccessSyncer {
	return &AccessSyncer{}
}
