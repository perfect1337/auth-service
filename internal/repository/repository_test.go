package repository

import (
	"context"
	"testing"

	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/stretchr/testify/assert"
)

func TestGetUserByID(t *testing.T) {
	mockRepo := new(MockCompositeRepository)
	ctx := context.Background()

	user := &entity.User{
		ID:           1,
		Username:     "testuser",
		Email:        "testuser@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	mockRepo.On("GetUserByID", ctx, 1).Return(user, nil)

	result, err := mockRepo.GetUserByID(ctx, 1)
	assert.NoError(t, err)
	assert.Equal(t, user, result)

	mockRepo.AssertExpectations(t)
}

func TestCreateUser(t *testing.T) {
	mockRepo := new(MockCompositeRepository)
	ctx := context.Background()

	user := &entity.User{
		Username:     "newuser",
		Email:        "newuser@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	mockRepo.On("CreateUser", ctx, user).Return(nil)

	err := mockRepo.CreateUser(ctx, user)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// Add more tests for other methods similarly...
