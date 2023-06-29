// Code generated by mockery v2.23.1. DO NOT EDIT.

package aws

import (
	context "context"

	config "github.com/raito-io/cli/base/util/config"

	mock "github.com/stretchr/testify/mock"
)

// mockIdentityStoreRepository is an autogenerated mock type for the identityStoreRepository type
type mockIdentityStoreRepository struct {
	mock.Mock
}

type mockIdentityStoreRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *mockIdentityStoreRepository) EXPECT() *mockIdentityStoreRepository_Expecter {
	return &mockIdentityStoreRepository_Expecter{mock: &_m.Mock}
}

// GetGroups provides a mock function with given fields: ctx, configMap, withDetails
func (_m *mockIdentityStoreRepository) GetGroups(ctx context.Context, configMap *config.ConfigMap, withDetails bool) ([]GroupEntity, error) {
	ret := _m.Called(ctx, configMap, withDetails)

	var r0 []GroupEntity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *config.ConfigMap, bool) ([]GroupEntity, error)); ok {
		return rf(ctx, configMap, withDetails)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *config.ConfigMap, bool) []GroupEntity); ok {
		r0 = rf(ctx, configMap, withDetails)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]GroupEntity)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *config.ConfigMap, bool) error); ok {
		r1 = rf(ctx, configMap, withDetails)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockIdentityStoreRepository_GetGroups_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetGroups'
type mockIdentityStoreRepository_GetGroups_Call struct {
	*mock.Call
}

// GetGroups is a helper method to define mock.On call
//   - ctx context.Context
//   - configMap *config.ConfigMap
//   - withDetails bool
func (_e *mockIdentityStoreRepository_Expecter) GetGroups(ctx interface{}, configMap interface{}, withDetails interface{}) *mockIdentityStoreRepository_GetGroups_Call {
	return &mockIdentityStoreRepository_GetGroups_Call{Call: _e.mock.On("GetGroups", ctx, configMap, withDetails)}
}

func (_c *mockIdentityStoreRepository_GetGroups_Call) Run(run func(ctx context.Context, configMap *config.ConfigMap, withDetails bool)) *mockIdentityStoreRepository_GetGroups_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*config.ConfigMap), args[2].(bool))
	})
	return _c
}

func (_c *mockIdentityStoreRepository_GetGroups_Call) Return(_a0 []GroupEntity, _a1 error) *mockIdentityStoreRepository_GetGroups_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockIdentityStoreRepository_GetGroups_Call) RunAndReturn(run func(context.Context, *config.ConfigMap, bool) ([]GroupEntity, error)) *mockIdentityStoreRepository_GetGroups_Call {
	_c.Call.Return(run)
	return _c
}

// GetRoles provides a mock function with given fields: ctx, configMap
func (_m *mockIdentityStoreRepository) GetRoles(ctx context.Context, configMap *config.ConfigMap) ([]RoleEntity, error) {
	ret := _m.Called(ctx, configMap)

	var r0 []RoleEntity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *config.ConfigMap) ([]RoleEntity, error)); ok {
		return rf(ctx, configMap)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *config.ConfigMap) []RoleEntity); ok {
		r0 = rf(ctx, configMap)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]RoleEntity)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *config.ConfigMap) error); ok {
		r1 = rf(ctx, configMap)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockIdentityStoreRepository_GetRoles_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRoles'
type mockIdentityStoreRepository_GetRoles_Call struct {
	*mock.Call
}

// GetRoles is a helper method to define mock.On call
//   - ctx context.Context
//   - configMap *config.ConfigMap
func (_e *mockIdentityStoreRepository_Expecter) GetRoles(ctx interface{}, configMap interface{}) *mockIdentityStoreRepository_GetRoles_Call {
	return &mockIdentityStoreRepository_GetRoles_Call{Call: _e.mock.On("GetRoles", ctx, configMap)}
}

func (_c *mockIdentityStoreRepository_GetRoles_Call) Run(run func(ctx context.Context, configMap *config.ConfigMap)) *mockIdentityStoreRepository_GetRoles_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*config.ConfigMap))
	})
	return _c
}

func (_c *mockIdentityStoreRepository_GetRoles_Call) Return(_a0 []RoleEntity, _a1 error) *mockIdentityStoreRepository_GetRoles_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockIdentityStoreRepository_GetRoles_Call) RunAndReturn(run func(context.Context, *config.ConfigMap) ([]RoleEntity, error)) *mockIdentityStoreRepository_GetRoles_Call {
	_c.Call.Return(run)
	return _c
}

// GetUsers provides a mock function with given fields: ctx, configMap, withDetails
func (_m *mockIdentityStoreRepository) GetUsers(ctx context.Context, configMap *config.ConfigMap, withDetails bool) ([]UserEntity, error) {
	ret := _m.Called(ctx, configMap, withDetails)

	var r0 []UserEntity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *config.ConfigMap, bool) ([]UserEntity, error)); ok {
		return rf(ctx, configMap, withDetails)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *config.ConfigMap, bool) []UserEntity); ok {
		r0 = rf(ctx, configMap, withDetails)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]UserEntity)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *config.ConfigMap, bool) error); ok {
		r1 = rf(ctx, configMap, withDetails)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockIdentityStoreRepository_GetUsers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUsers'
type mockIdentityStoreRepository_GetUsers_Call struct {
	*mock.Call
}

// GetUsers is a helper method to define mock.On call
//   - ctx context.Context
//   - configMap *config.ConfigMap
//   - withDetails bool
func (_e *mockIdentityStoreRepository_Expecter) GetUsers(ctx interface{}, configMap interface{}, withDetails interface{}) *mockIdentityStoreRepository_GetUsers_Call {
	return &mockIdentityStoreRepository_GetUsers_Call{Call: _e.mock.On("GetUsers", ctx, configMap, withDetails)}
}

func (_c *mockIdentityStoreRepository_GetUsers_Call) Run(run func(ctx context.Context, configMap *config.ConfigMap, withDetails bool)) *mockIdentityStoreRepository_GetUsers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*config.ConfigMap), args[2].(bool))
	})
	return _c
}

func (_c *mockIdentityStoreRepository_GetUsers_Call) Return(_a0 []UserEntity, _a1 error) *mockIdentityStoreRepository_GetUsers_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockIdentityStoreRepository_GetUsers_Call) RunAndReturn(run func(context.Context, *config.ConfigMap, bool) ([]UserEntity, error)) *mockIdentityStoreRepository_GetUsers_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTnewMockIdentityStoreRepository interface {
	mock.TestingT
	Cleanup(func())
}

// newMockIdentityStoreRepository creates a new instance of mockIdentityStoreRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func newMockIdentityStoreRepository(t mockConstructorTestingTnewMockIdentityStoreRepository) *mockIdentityStoreRepository {
	mock := &mockIdentityStoreRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
