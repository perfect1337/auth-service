package mocks

import (
	"context"
	"database/sql"

	"github.com/stretchr/testify/mock"
)

// MockDB is a mock implementation of the DB interface
type MockDB struct {
	mock.Mock
}

func (m *MockDB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	argsMock := m.Called(ctx, query, args)
	return argsMock.Get(0).(*sql.Rows), argsMock.Error(1)
}

func (m *MockDB) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	argsMock := m.Called(ctx, query, args)
	return argsMock.Get(0).(*sql.Row)
}

func (m *MockDB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	argsMock := m.Called(ctx, query, args)
	return argsMock.Get(0).(sql.Result), argsMock.Error(1)
}

func (m *MockDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	argsMock := m.Called(ctx, opts)
	return argsMock.Get(0).(*sql.Tx), argsMock.Error(1)
}

func (m *MockDB) PingContext(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *MockDB) Close() error {
	return m.Called().Error(0)
}
