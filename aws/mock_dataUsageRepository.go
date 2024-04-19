// Code generated by mockery v2.42.2. DO NOT EDIT.

package aws

import (
	context "context"
	io "io"

	mock "github.com/stretchr/testify/mock"

	model "github.com/raito-io/cli-plugin-aws-account/aws/model"
)

// mockDataUsageRepository is an autogenerated mock type for the dataUsageRepository type
type mockDataUsageRepository struct {
	mock.Mock
}

type mockDataUsageRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *mockDataUsageRepository) EXPECT() *mockDataUsageRepository_Expecter {
	return &mockDataUsageRepository_Expecter{mock: &_m.Mock}
}

// GetFile provides a mock function with given fields: ctx, bucket, key
func (_m *mockDataUsageRepository) GetFile(ctx context.Context, bucket string, key string) (io.ReadCloser, error) {
	ret := _m.Called(ctx, bucket, key)

	if len(ret) == 0 {
		panic("no return value specified for GetFile")
	}

	var r0 io.ReadCloser
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (io.ReadCloser, error)); ok {
		return rf(ctx, bucket, key)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) io.ReadCloser); ok {
		r0 = rf(ctx, bucket, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.ReadCloser)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, bucket, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockDataUsageRepository_GetFile_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFile'
type mockDataUsageRepository_GetFile_Call struct {
	*mock.Call
}

// GetFile is a helper method to define mock.On call
//   - ctx context.Context
//   - bucket string
//   - key string
func (_e *mockDataUsageRepository_Expecter) GetFile(ctx interface{}, bucket interface{}, key interface{}) *mockDataUsageRepository_GetFile_Call {
	return &mockDataUsageRepository_GetFile_Call{Call: _e.mock.On("GetFile", ctx, bucket, key)}
}

func (_c *mockDataUsageRepository_GetFile_Call) Run(run func(ctx context.Context, bucket string, key string)) *mockDataUsageRepository_GetFile_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *mockDataUsageRepository_GetFile_Call) Return(_a0 io.ReadCloser, _a1 error) *mockDataUsageRepository_GetFile_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockDataUsageRepository_GetFile_Call) RunAndReturn(run func(context.Context, string, string) (io.ReadCloser, error)) *mockDataUsageRepository_GetFile_Call {
	_c.Call.Return(run)
	return _c
}

// ListFiles provides a mock function with given fields: ctx, bucket, prefix
func (_m *mockDataUsageRepository) ListFiles(ctx context.Context, bucket string, prefix *string) ([]model.AwsS3Entity, error) {
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

// mockDataUsageRepository_ListFiles_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListFiles'
type mockDataUsageRepository_ListFiles_Call struct {
	*mock.Call
}

// ListFiles is a helper method to define mock.On call
//   - ctx context.Context
//   - bucket string
//   - prefix *string
func (_e *mockDataUsageRepository_Expecter) ListFiles(ctx interface{}, bucket interface{}, prefix interface{}) *mockDataUsageRepository_ListFiles_Call {
	return &mockDataUsageRepository_ListFiles_Call{Call: _e.mock.On("ListFiles", ctx, bucket, prefix)}
}

func (_c *mockDataUsageRepository_ListFiles_Call) Run(run func(ctx context.Context, bucket string, prefix *string)) *mockDataUsageRepository_ListFiles_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(*string))
	})
	return _c
}

func (_c *mockDataUsageRepository_ListFiles_Call) Return(_a0 []model.AwsS3Entity, _a1 error) *mockDataUsageRepository_ListFiles_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockDataUsageRepository_ListFiles_Call) RunAndReturn(run func(context.Context, string, *string) ([]model.AwsS3Entity, error)) *mockDataUsageRepository_ListFiles_Call {
	_c.Call.Return(run)
	return _c
}

// newMockDataUsageRepository creates a new instance of mockDataUsageRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockDataUsageRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockDataUsageRepository {
	mock := &mockDataUsageRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
