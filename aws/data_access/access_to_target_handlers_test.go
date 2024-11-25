package data_access

/*
func TestRoleAccessHandler_HandleInheritance(t *testing.T) {
	t.Run("InternalAps", func(t *testing.T) {
		// In this test we test the following case of inheritance where all are internal APs:
		// (Role1) - [WHO] -> (Role2)

		detailsMap := map[string]*AccessProviderDetails{
			"Role1": {
				inheritance: map[model.AccessProviderType][]string{model.Role: {"Role2"}},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user1",
				}),
			},
			"Role2": {
				inheritance: map[model.AccessProviderType][]string{},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user2",
				}),
			},
		}

		roleExecutor := roleAccessHandler{
			repo:            nil,
			getUserGroupMap: nil,
			accessProviders: &AccessProvidersByType{
				Roles: detailsMap,
			},
		}

		roleExecutor.HandleInheritance()

		compareBindings(t, set.NewSet(
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user1",
			},
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user2",
			},
		), detailsMap["Role1"].targetBindings)

		compareBindings(t, set.NewSet(
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user2",
			},
		), detailsMap["Role2"].targetBindings)
	})

	t.Run("ExternalAps", func(t *testing.T) {
		// In this test we test the following case of inheritance where all are external APs:
		// (Role1) - [WHO] ->

		detailsMap := map[string]*AccessProviderDetails{
			"Role1": {
				inheritance: map[model.AccessProviderType][]string{model.Role: {"Role2"}},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user1",
				}),
			},
			"Role2": {
				inheritance: map[model.AccessProviderType][]string{},
				existingBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user2",
				}),
			},
		}

		roleExecutor := roleAccessHandler{
			repo:            nil,
			getUserGroupMap: nil,
			accessProviders: &AccessProvidersByType{
				Roles: detailsMap,
			},
		}

		roleExecutor.HandleInheritance()

		compareBindings(t, set.NewSet(
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user1",
			},
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user2",
			},
		), detailsMap["Role1"].targetBindings)

		compareBindings(t, set.NewSet[model.PolicyBinding](), detailsMap["Role2"].targetBindings)
	})
}

func TestProcessPolicyInheritance(t *testing.T) {
	t.Run("InternalAps", func(t *testing.T) {
		// In this test we test the following case of inheritance where all are internal APs:
		// (Policy1) - [WHO] -> (Policy2) - [WHO] -> (Role1) - [WHO] -> (Role2)

		// Given
		rolesDetails := map[string]*AccessProviderDetails{
			"Role1": {
				inheritance: map[model.AccessProviderType][]string{model.Role: {"Role2"}},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user1",
				}),
				apType: model.Role,
				name:   "Role1",
			},
			"Role2": {
				inheritance: map[model.AccessProviderType][]string{},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user2",
				}),
				apType: model.Role,
				name:   "Role2",
			},
		}

		policiesDetails := map[string]*AccessProviderDetails{
			"Policy1": {
				inheritance: map[model.AccessProviderType][]string{model.Policy: {"Policy2"}},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user3",
				}),
				apType: model.Policy,
				name:   "Policy1",
			},
			"Policy2": {
				inheritance: map[model.AccessProviderType][]string{model.Role: {"Role1"}},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user4",
				}),
				apType: model.Policy,
				name:   "Policy2",
			},
		}

		roleExecutor := roleAccessHandler{
			repo:            nil,
			getUserGroupMap: nil,
			accessProviders: &AccessProvidersByType{
				Roles:    rolesDetails,
				Policies: policiesDetails,
			},
		}

		roleExecutor.HandleInheritance()

		// When
		processPolicyInheritance(policiesDetails, roleExecutor.accessProviders)

		// Then
		compareBindings(t, set.NewSet(
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user3",
			},
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user4",
			},
			model.PolicyBinding{
				Type:         iam.RoleResourceType,
				ResourceName: "Role1",
			},
			model.PolicyBinding{
				Type:         iam.RoleResourceType,
				ResourceName: "Role2",
			},
		), policiesDetails["Policy1"].targetBindings)

		compareBindings(t, set.NewSet(
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user4",
			},
			model.PolicyBinding{
				Type:         iam.RoleResourceType,
				ResourceName: "Role1",
			},
			model.PolicyBinding{
				Type:         iam.RoleResourceType,
				ResourceName: "Role2",
			},
		), policiesDetails["Policy2"].targetBindings)
	})

	t.Run("ExternalAps", func(t *testing.T) {
		// In this test we test the following case of inheritance where all are external APs:
		// (Policy1) - [WHO] -> (Policy2) - [WHO] -> (Role1) - [WHO] -> (Role2)
		rolesDetails := map[string]*AccessProviderDetails{
			"Role1": {
				inheritance: map[model.AccessProviderType][]string{model.Role: {"Role2"}},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user1",
				}),
				name:   "Role1",
				apType: model.Role,
			},
			"Role2": {
				inheritance: map[model.AccessProviderType][]string{},
				existingBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user2",
				}),
				name:   "Role2",
				apType: model.Role,
			},
		}

		policiesDetails := map[string]*AccessProviderDetails{
			"Policy1": {
				inheritance: map[model.AccessProviderType][]string{model.Policy: {"Policy2"}},
				targetBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user3",
				}),
				name:   "Policy1",
				apType: model.Policy,
			},
			"Policy2": {
				inheritance: map[model.AccessProviderType][]string{model.Role: {"Role1"}},
				existingBindings: set.NewSet(model.PolicyBinding{
					Type:         iam.UserResourceType,
					ResourceName: "user4",
				}),
				name:   "Policy2",
				apType: model.Policy,
			},
		}

		roleExecutor := roleAccessHandler{
			repo:            nil,
			getUserGroupMap: nil,
			accessProviders: &AccessProvidersByType{
				Roles:    rolesDetails,
				Policies: policiesDetails,
			},
		}

		roleExecutor.HandleInheritance()

		// When
		processPolicyInheritance(policiesDetails, roleExecutor.accessProviders)

		// Then
		compareBindings(t, set.NewSet(
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user3",
			},
			model.PolicyBinding{
				Type:         iam.UserResourceType,
				ResourceName: "user4",
			},
			model.PolicyBinding{
				Type:         iam.RoleResourceType,
				ResourceName: "Role1",
			},
			model.PolicyBinding{
				Type:         iam.RoleResourceType,
				ResourceName: "Role2",
			},
		), policiesDetails["Policy1"].targetBindings)
	})
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

func Test_unpackGroups(t *testing.T) {
	type args struct {
		ctx             context.Context
		groups          []string
		getUserGroupMap func(ctx context.Context) (map[string][]string, error)
	}
	tests := []struct {
		name    string
		args    args
		want    set.Set[model.PolicyBinding]
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "No users in group",
			args: args{
				ctx:    context.Background(),
				groups: []string{"group1", "group2"},
				getUserGroupMap: func(ctx context.Context) (map[string][]string, error) {
					return map[string][]string{}, nil
				},
			},
			want:    set.NewSet[model.PolicyBinding](),
			wantErr: assert.NoError,
		},
		{
			name: "No groups",
			args: args{
				ctx:    context.Background(),
				groups: []string{},
				getUserGroupMap: func(ctx context.Context) (map[string][]string, error) {
					return map[string][]string{"group1": {"user1", "user2"}}, nil
				},
			},
			want:    set.NewSet[model.PolicyBinding](),
			wantErr: assert.NoError,
		},
		{
			name: "Users in group",
			args: args{
				ctx:    context.Background(),
				groups: []string{"group1", "group2"},
				getUserGroupMap: func(ctx context.Context) (map[string][]string, error) {
					return map[string][]string{
						"group1": {"user1", "user2"},
						"group2": {"user2", "user3"},
					}, nil
				},
			},
			want: set.NewSet[model.PolicyBinding](
				model.PolicyBinding{Type: iam.UserResourceType, ResourceName: "user1"},
				model.PolicyBinding{Type: iam.UserResourceType, ResourceName: "user2"},
				model.PolicyBinding{Type: iam.UserResourceType, ResourceName: "user3"},
			),
			wantErr: assert.NoError,
		},
		{
			name: "Error getting user group map",
			args: args{
				ctx:    context.Background(),
				groups: []string{"group1", "group2"},
				getUserGroupMap: func(ctx context.Context) (map[string][]string, error) {
					return nil, fmt.Errorf("error")
				},
			},
			want:    nil,
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unpackGroups(tt.args.ctx, tt.args.groups, tt.args.getUserGroupMap)
			if !tt.wantErr(t, err, fmt.Sprintf("unpackGroups(%v, %v, f())", tt.args.ctx, tt.args.groups)) {
				return
			}
			assert.Equalf(t, tt.want, got, "unpackGroups(%v, %v, f())", tt.args.ctx, tt.args.groups)
		})
	}
}
*/
