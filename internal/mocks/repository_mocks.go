package mocks

import (
	"context"

	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/stretchr/testify/mock"
)

// MockCompositeRepository is a mock type for the CompositeRepository interface
type MockCompositeRepository struct {
	mock.Mock
}

func (m *MockCompositeRepository) CreateUser(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockCompositeRepository) GetUserByID(ctx context.Context, id int) (*entity.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockCompositeRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockCompositeRepository) GetUserByLogin(ctx context.Context, login string) (*entity.User, error) {
	args := m.Called(ctx, login)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockCompositeRepository) GetUserByCredentials(ctx context.Context, login, passwordHash string) (*entity.User, error) {
	args := m.Called(ctx, login, passwordHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockCompositeRepository) DeleteUser(ctx context.Context, id int) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockCompositeRepository) CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockCompositeRepository) GetRefreshToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.RefreshToken), args.Error(1)
}

func (m *MockCompositeRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockCompositeRepository) RunMigrations() error {
	args := m.Called()
	return args.Error(0)
}
