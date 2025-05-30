// Code generated by mockery v2.53.3. DO NOT EDIT.

package aws

import (
	context "context"

	model "github.com/raito-io/cli-plugin-aws-account/aws/model"
	mock "github.com/stretchr/testify/mock"
)

// MockidentityStoreRepository is an autogenerated mock type for the identityStoreRepository type
type MockidentityStoreRepository struct {
	mock.Mock
}

type MockidentityStoreRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *MockidentityStoreRepository) EXPECT() *MockidentityStoreRepository_Expecter {
	return &MockidentityStoreRepository_Expecter{mock: &_m.Mock}
}

// GetGroups provides a mock function with given fields: ctx
func (_m *MockidentityStoreRepository) GetGroups(ctx context.Context) ([]model.GroupEntity, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetGroups")
	}

	var r0 []model.GroupEntity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]model.GroupEntity, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []model.GroupEntity); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.GroupEntity)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockidentityStoreRepository_GetGroups_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetGroups'
type MockidentityStoreRepository_GetGroups_Call struct {
	*mock.Call
}

// GetGroups is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockidentityStoreRepository_Expecter) GetGroups(ctx interface{}) *MockidentityStoreRepository_GetGroups_Call {
	return &MockidentityStoreRepository_GetGroups_Call{Call: _e.mock.On("GetGroups", ctx)}
}

func (_c *MockidentityStoreRepository_GetGroups_Call) Run(run func(ctx context.Context)) *MockidentityStoreRepository_GetGroups_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockidentityStoreRepository_GetGroups_Call) Return(_a0 []model.GroupEntity, _a1 error) *MockidentityStoreRepository_GetGroups_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockidentityStoreRepository_GetGroups_Call) RunAndReturn(run func(context.Context) ([]model.GroupEntity, error)) *MockidentityStoreRepository_GetGroups_Call {
	_c.Call.Return(run)
	return _c
}

// GetUsers provides a mock function with given fields: ctx, withDetails
func (_m *MockidentityStoreRepository) GetUsers(ctx context.Context, withDetails bool) ([]model.UserEntity, error) {
	ret := _m.Called(ctx, withDetails)

	if len(ret) == 0 {
		panic("no return value specified for GetUsers")
	}

	var r0 []model.UserEntity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, bool) ([]model.UserEntity, error)); ok {
		return rf(ctx, withDetails)
	}
	if rf, ok := ret.Get(0).(func(context.Context, bool) []model.UserEntity); ok {
		r0 = rf(ctx, withDetails)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.UserEntity)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, bool) error); ok {
		r1 = rf(ctx, withDetails)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockidentityStoreRepository_GetUsers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUsers'
type MockidentityStoreRepository_GetUsers_Call struct {
	*mock.Call
}

// GetUsers is a helper method to define mock.On call
//   - ctx context.Context
//   - withDetails bool
func (_e *MockidentityStoreRepository_Expecter) GetUsers(ctx interface{}, withDetails interface{}) *MockidentityStoreRepository_GetUsers_Call {
	return &MockidentityStoreRepository_GetUsers_Call{Call: _e.mock.On("GetUsers", ctx, withDetails)}
}

func (_c *MockidentityStoreRepository_GetUsers_Call) Run(run func(ctx context.Context, withDetails bool)) *MockidentityStoreRepository_GetUsers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(bool))
	})
	return _c
}

func (_c *MockidentityStoreRepository_GetUsers_Call) Return(_a0 []model.UserEntity, _a1 error) *MockidentityStoreRepository_GetUsers_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockidentityStoreRepository_GetUsers_Call) RunAndReturn(run func(context.Context, bool) ([]model.UserEntity, error)) *MockidentityStoreRepository_GetUsers_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockidentityStoreRepository creates a new instance of MockidentityStoreRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockidentityStoreRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockidentityStoreRepository {
	mock := &MockidentityStoreRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
