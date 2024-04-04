package iam

import (
	"fmt"
	"sort"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/golang-set/set"
	"github.com/stretchr/testify/assert"
)

func TestApInheritanceHandler(t *testing.T) {
	// In this test we test the following case of inheritance where all are internal APs:
	// (Policy1) - [WHO] -> (Policy2) - [WHO] -> (Role1) - [WHO] -> (Role2)

	roleInheritanceMap := map[string]set.Set[string]{
		"Role1": set.NewSet("Role2"),
	}
	policyInheritanceMap := map[string]set.Set[string]{
		"Policy1": set.NewSet("Policy2"),
		"Policy2": set.NewSet("Role1"),
	}
	newRoleWhoBindings := map[string]set.Set[model.PolicyBinding]{
		"Role1": set.NewSet(model.PolicyBinding{
			Type:         UserResourceType,
			ResourceName: "user1",
		}),
		"Role2": set.NewSet(model.PolicyBinding{
			Type:         UserResourceType,
			ResourceName: "user2",
		}),
	}
	newPolicyWhoBindings := map[string]set.Set[model.PolicyBinding]{
		"Policy1": set.NewSet(model.PolicyBinding{
			Type:         UserResourceType,
			ResourceName: "user3",
		}),
		"Policy2": set.NewSet(model.PolicyBinding{
			Type:         UserResourceType,
			ResourceName: "user4",
		}),
	}
	existingRoleWhoBindings := map[string]set.Set[model.PolicyBinding]{}
	existingPolicyWhoBindings := map[string]set.Set[model.PolicyBinding]{}

	ProcessApInheritance(roleInheritanceMap, policyInheritanceMap, newRoleWhoBindings, newPolicyWhoBindings, existingRoleWhoBindings, existingPolicyWhoBindings)

	fmt.Printf("Role1 bindings: %+v\n", newRoleWhoBindings["Role1"])
	fmt.Printf("Role2 bindings: %+v\n", newRoleWhoBindings["Role2"])
	fmt.Printf("Policy1 bindings: %+v\n", newPolicyWhoBindings["Policy1"])
	fmt.Printf("Policy2 bindings: %+v\n", newPolicyWhoBindings["Policy2"])

	compareBindings(t, set.NewSet[model.PolicyBinding]([]model.PolicyBinding{
		{
			Type:         UserResourceType,
			ResourceName: "user1",
		},
		{
			Type:         UserResourceType,
			ResourceName: "user2",
		},
	}...), newRoleWhoBindings["Role1"])

	compareBindings(t, set.NewSet[model.PolicyBinding]([]model.PolicyBinding{
		{
			Type:         UserResourceType,
			ResourceName: "user2",
		},
	}...), newRoleWhoBindings["Role2"])

	compareBindings(t, set.NewSet[model.PolicyBinding]([]model.PolicyBinding{
		{
			Type:         UserResourceType,
			ResourceName: "user3",
		},
		{
			Type:         UserResourceType,
			ResourceName: "user4",
		},
		{
			Type:         "role",
			ResourceName: "Role1",
		},
		{
			Type:         "role",
			ResourceName: "Role2",
		},
	}...), newPolicyWhoBindings["Policy1"])

	compareBindings(t, set.NewSet[model.PolicyBinding]([]model.PolicyBinding{
		{
			Type:         UserResourceType,
			ResourceName: "user4",
		},
		{
			Type:         "role",
			ResourceName: "Role1",
		},
		{
			Type:         "role",
			ResourceName: "Role2",
		},
	}...), newPolicyWhoBindings["Policy2"])
}

func TestApInheritanceHandler_WithExternals(t *testing.T) {
	// In this test we test the following case of inheritance where all are Policy2 and Role2 are external APs:
	// (Policy1) - [WHO] -> (Policy2) - [WHO] -> (Role1) - [WHO] -> (Role2)

	roleInheritanceMap := map[string]set.Set[string]{
		"Role1": set.NewSet("Role2"),
	}
	policyInheritanceMap := map[string]set.Set[string]{
		"Policy1": set.NewSet("Policy2"),
	}
	newRoleWhoBindings := map[string]set.Set[model.PolicyBinding]{
		"Role1": set.NewSet(model.PolicyBinding{
			Type:         UserResourceType,
			ResourceName: "user1",
		}),
	}
	newPolicyWhoBindings := map[string]set.Set[model.PolicyBinding]{
		"Policy1": set.NewSet(model.PolicyBinding{
			Type:         UserResourceType,
			ResourceName: "user3",
		}),
	}
	existingRoleWhoBindings := map[string]set.Set[model.PolicyBinding]{
		"Role2": set.NewSet(model.PolicyBinding{
			Type:         UserResourceType,
			ResourceName: "user2",
		}),
	}
	existingPolicyWhoBindings := map[string]set.Set[model.PolicyBinding]{
		"Policy2": set.NewSet(model.PolicyBinding{
			Type:         UserResourceType,
			ResourceName: "user4",
		}, model.PolicyBinding{
			Type:         "role",
			ResourceName: "Role1",
		}),
	}

	ProcessApInheritance(roleInheritanceMap, policyInheritanceMap, newRoleWhoBindings, newPolicyWhoBindings, existingRoleWhoBindings, existingPolicyWhoBindings)

	fmt.Printf("Role1 bindings: %+v\n", newRoleWhoBindings["Role1"])
	fmt.Printf("Role2 bindings: %+v\n", newRoleWhoBindings["Role2"])
	fmt.Printf("Policy1 bindings: %+v\n", newPolicyWhoBindings["Policy1"])
	fmt.Printf("Policy2 bindings: %+v\n", newPolicyWhoBindings["Policy2"])

	compareBindings(t, set.NewSet[model.PolicyBinding]([]model.PolicyBinding{
		{
			Type:         UserResourceType,
			ResourceName: "user1",
		},
		{
			Type:         UserResourceType,
			ResourceName: "user2",
		},
	}...), newRoleWhoBindings["Role1"])

	compareBindings(t, set.NewSet[model.PolicyBinding]([]model.PolicyBinding{
		{
			Type:         UserResourceType,
			ResourceName: "user3",
		},
		{
			Type:         UserResourceType,
			ResourceName: "user4",
		},
		{
			Type:         "role",
			ResourceName: "Role1",
		},
		{
			Type:         "role",
			ResourceName: "Role2",
		},
	}...), newPolicyWhoBindings["Policy1"])
}

func compareBindings(t *testing.T, expected set.Set[model.PolicyBinding], actual set.Set[model.PolicyBinding]) {
	if len(expected) != len(actual) {
		t.Error("Not the same number of bindings")
	}

	expectedSlice := expected.Slice()
	sort.Slice(expectedSlice, func(i, j int) bool {
		return expectedSlice[i].ResourceName < expectedSlice[j].ResourceName
	})

	actualSlice := actual.Slice()
	sort.Slice(actualSlice, func(i, j int) bool {
		return actualSlice[i].ResourceName < actualSlice[j].ResourceName
	})

	assert.Equal(t, expectedSlice, actualSlice)
}
