package mocks

import (
	"context"

	"github.com/perfect1337/auth-service/internal/usecase"
	"github.com/stretchr/testify/mock"
)

type MockAuthUseCase struct {
	mock.Mock
}

func (m *MockAuthUseCase) Register(ctx context.Context, username, email, password string) (*usecase.AuthResponse, error) {
	args := m.Called(ctx, username, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*usecase.AuthResponse), args.Error(1)
}

func (m *MockAuthUseCase) Login(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*usecase.AuthResponse), args.Error(1)
}

func (m *MockAuthUseCase) RefreshTokens(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*usecase.AuthResponse), args.Error(1)
}

func (m *MockAuthUseCase) Logout(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func (m *MockAuthUseCase) ValidateToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthUseCase) GetSecretKey() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}
