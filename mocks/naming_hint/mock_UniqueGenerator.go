// Code generated by mockery v2.50.0. DO NOT EDIT.

package naming_hint

import (
	mock "github.com/stretchr/testify/mock"

	sync_to_target "github.com/raito-io/cli/base/access_provider/sync_to_target"
)

// MockUniqueGenerator is an autogenerated mock type for the UniqueGenerator type
type MockUniqueGenerator struct {
	mock.Mock
}

type MockUniqueGenerator_Expecter struct {
	mock *mock.Mock
}

func (_m *MockUniqueGenerator) EXPECT() *MockUniqueGenerator_Expecter {
	return &MockUniqueGenerator_Expecter{mock: &_m.Mock}
}

// Generate provides a mock function with given fields: ap
func (_m *MockUniqueGenerator) Generate(ap *sync_to_target.AccessProvider) (string, error) {
	ret := _m.Called(ap)

	if len(ret) == 0 {
		panic("no return value specified for Generate")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(*sync_to_target.AccessProvider) (string, error)); ok {
		return rf(ap)
	}
	if rf, ok := ret.Get(0).(func(*sync_to_target.AccessProvider) string); ok {
		r0 = rf(ap)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(*sync_to_target.AccessProvider) error); ok {
		r1 = rf(ap)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockUniqueGenerator_Generate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Generate'
type MockUniqueGenerator_Generate_Call struct {
	*mock.Call
}

// Generate is a helper method to define mock.On call
//   - ap *sync_to_target.AccessProvider
func (_e *MockUniqueGenerator_Expecter) Generate(ap interface{}) *MockUniqueGenerator_Generate_Call {
	return &MockUniqueGenerator_Generate_Call{Call: _e.mock.On("Generate", ap)}
}

func (_c *MockUniqueGenerator_Generate_Call) Run(run func(ap *sync_to_target.AccessProvider)) *MockUniqueGenerator_Generate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*sync_to_target.AccessProvider))
	})
	return _c
}

func (_c *MockUniqueGenerator_Generate_Call) Return(_a0 string, _a1 error) *MockUniqueGenerator_Generate_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockUniqueGenerator_Generate_Call) RunAndReturn(run func(*sync_to_target.AccessProvider) (string, error)) *MockUniqueGenerator_Generate_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockUniqueGenerator creates a new instance of MockUniqueGenerator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockUniqueGenerator(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockUniqueGenerator {
	mock := &MockUniqueGenerator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
