package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/perfect1337/auth-service/internal/mocks"
	user "github.com/perfect1337/auth-service/internal/proto"
	"github.com/stretchr/testify/assert"
)

func TestGetUsername_Success(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	server := NewUserServer(mockRepo)
	ctx := context.Background()
	expectedUser := &entity.User{
		ID:       1,
		Username: "testuser",
	}

	// Устанавливаем ожидания для мок-репозитория
	mockRepo.On("GetUserByID", ctx, 1).Return(expectedUser, nil)

	// Запрос для gRPC метода
	req := &user.UserRequest{UserId: 1}

	// Вызов метода
	resp, err := server.GetUsername(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.Equal(t, "testuser", resp.Username)
	mockRepo.AssertExpectations(t)
}

func TestGetUsername_UserNotFound(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	server := NewUserServer(mockRepo)
	ctx := context.Background()

	// Устанавливаем ожидания для мок-репозитория
	mockRepo.On("GetUserByID", ctx, 1).Return(nil, errors.New("user not found"))

	// Запрос для gRPC метода
	req := &user.UserRequest{UserId: 1}

	// Вызов метода
	resp, err := server.GetUsername(ctx, req)

	// Проверяем результаты
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "user not found")
	mockRepo.AssertExpectations(t)
}

func TestGetUsername_InvalidRequest(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	server := NewUserServer(mockRepo)
	ctx := context.Background()

	testCases := []struct {
		name        string
		request     *user.UserRequest
		expectedErr string
	}{
		{
			name:        "Nil request",
			request:     nil,
			expectedErr: "request cannot be nil",
		},
		{
			name:        "Zero user ID",
			request:     &user.UserRequest{UserId: 0},
			expectedErr: "invalid user ID",
		},
		{
			name:        "Negative user ID",
			request:     &user.UserRequest{UserId: -1},
			expectedErr: "invalid user ID",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := server.GetUsername(ctx, tc.request)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
			assert.Nil(t, resp)
			mockRepo.AssertNotCalled(t, "GetUserByID")
		})
	}
}
func TestNewUserServer(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	server := NewUserServer(mockRepo)

	assert.NotNil(t, server)
	assert.Equal(t, mockRepo, server.repo)
}
