// Code generated by mockery v2.42.1. DO NOT EDIT.

package aws

import (
	context "context"

	model "github.com/raito-io/cli-plugin-aws-account/aws/model"
	mock "github.com/stretchr/testify/mock"
)

// mockDataSourceRepository is an autogenerated mock type for the dataSourceRepository type
type mockDataSourceRepository struct {
	mock.Mock
}

type mockDataSourceRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *mockDataSourceRepository) EXPECT() *mockDataSourceRepository_Expecter {
	return &mockDataSourceRepository_Expecter{mock: &_m.Mock}
}

// ListBuckets provides a mock function with given fields: ctx
func (_m *mockDataSourceRepository) ListBuckets(ctx context.Context) ([]model.AwsS3Entity, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ListBuckets")
	}

	var r0 []model.AwsS3Entity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]model.AwsS3Entity, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []model.AwsS3Entity); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AwsS3Entity)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockDataSourceRepository_ListBuckets_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListBuckets'
type mockDataSourceRepository_ListBuckets_Call struct {
	*mock.Call
}

// ListBuckets is a helper method to define mock.On call
//   - ctx context.Context
func (_e *mockDataSourceRepository_Expecter) ListBuckets(ctx interface{}) *mockDataSourceRepository_ListBuckets_Call {
	return &mockDataSourceRepository_ListBuckets_Call{Call: _e.mock.On("ListBuckets", ctx)}
}

func (_c *mockDataSourceRepository_ListBuckets_Call) Run(run func(ctx context.Context)) *mockDataSourceRepository_ListBuckets_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *mockDataSourceRepository_ListBuckets_Call) Return(_a0 []model.AwsS3Entity, _a1 error) *mockDataSourceRepository_ListBuckets_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockDataSourceRepository_ListBuckets_Call) RunAndReturn(run func(context.Context) ([]model.AwsS3Entity, error)) *mockDataSourceRepository_ListBuckets_Call {
	_c.Call.Return(run)
	return _c
}

// ListFiles provides a mock function with given fields: ctx, bucket, prefix
func (_m *mockDataSourceRepository) ListFiles(ctx context.Context, bucket string, prefix *string) ([]model.AwsS3Entity, error) {
	ret := _m.Called(ctx, bucket, prefix)

	if len(ret) == 0 {
		panic("no return value specified for ListFiles")
	}

	var r0 []model.AwsS3Entity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *string) ([]model.AwsS3Entity, error)); ok {
		return rf(ctx, bucket, prefix)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, *string) []model.AwsS3Entity); ok {
		r0 = rf(ctx, bucket, prefix)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AwsS3Entity)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, *string) error); ok {
		r1 = rf(ctx, bucket, prefix)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockDataSourceRepository_ListFiles_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListFiles'
type mockDataSourceRepository_ListFiles_Call struct {
	*mock.Call
}

// ListFiles is a helper method to define mock.On call
//   - ctx context.Context
//   - bucket string
//   - prefix *string
func (_e *mockDataSourceRepository_Expecter) ListFiles(ctx interface{}, bucket interface{}, prefix interface{}) *mockDataSourceRepository_ListFiles_Call {
	return &mockDataSourceRepository_ListFiles_Call{Call: _e.mock.On("ListFiles", ctx, bucket, prefix)}
}

func (_c *mockDataSourceRepository_ListFiles_Call) Run(run func(ctx context.Context, bucket string, prefix *string)) *mockDataSourceRepository_ListFiles_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(*string))
	})
	return _c
}

func (_c *mockDataSourceRepository_ListFiles_Call) Return(_a0 []model.AwsS3Entity, _a1 error) *mockDataSourceRepository_ListFiles_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockDataSourceRepository_ListFiles_Call) RunAndReturn(run func(context.Context, string, *string) ([]model.AwsS3Entity, error)) *mockDataSourceRepository_ListFiles_Call {
	_c.Call.Return(run)
	return _c
}

// newMockDataSourceRepository creates a new instance of mockDataSourceRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockDataSourceRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockDataSourceRepository {
	mock := &mockDataSourceRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
