package grpc

import (
	"context"
	"testing"

	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/perfect1337/auth-service/internal/mocks"
	user "github.com/perfect1337/auth-service/internal/proto"
	"github.com/stretchr/testify/assert"
)

func TestGetUsername(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	server := NewUserServer(mockRepo)
	ctx := context.Background()
	expectedUser := &entity.User{
		ID:           1,
		Username:     "testuser",
		Email:        "testuser@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	// Устанавливаем ожидания для мок-репозитория
	mockRepo.On("GetUserByID", ctx, 1).Return(expectedUser, nil)

	// Запрос для gRPC метода
	req := &user.UserRequest{UserId: 1}

	// Вызов метода
	resp, err := server.GetUsername(ctx, req)

	// Проверяем, что ошибок нет и результат соответствует ожиданиям
	assert.NoError(t, err)
	assert.Equal(t, "testuser", resp.Username)

	// Проверяем, что все ожидания были вызваны
	mockRepo.AssertExpectations(t)
}
