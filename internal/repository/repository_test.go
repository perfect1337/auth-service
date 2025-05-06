package repository

import (
	"context"
	"testing"
	"time"

	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/perfect1337/auth-service/internal/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetUserByID(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
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
	mockRepo := new(mocks.MockCompositeRepository)
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
func TestGetUserByCredentials(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	ctx := context.Background()

	user := &entity.User{
		ID:           1,
		Username:     "testuser",
		Email:        "testuser@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	mockRepo.On("GetUserByCredentials", ctx, "testuser", "hashedpassword").Return(user, nil)

	result, err := mockRepo.GetUserByCredentials(ctx, "testuser", "hashedpassword")
	assert.NoError(t, err)
	assert.Equal(t, user, result)

	mockRepo.AssertExpectations(t)
}
func TestGetUserByEmail(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	ctx := context.Background()

	user := &entity.User{
		ID:           1,
		Username:     "testuser",
		Email:        "testuser@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	mockRepo.On("GetUserByEmail", ctx, "testuser@example.com").Return(user, nil)

	result, err := mockRepo.GetUserByEmail(ctx, "testuser@example.com")
	assert.NoError(t, err)
	assert.Equal(t, user, result)

	mockRepo.AssertExpectations(t)
}

func TestGetUserByLogin(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	ctx := context.Background()

	user := &entity.User{
		ID:           1,
		Username:     "testuser",
		Email:        "testuser@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	mockRepo.On("GetUserByLogin", ctx, "testuser").Return(user, nil)

	result, err := mockRepo.GetUserByLogin(ctx, "testuser")
	assert.NoError(t, err)
	assert.Equal(t, user, result)

	mockRepo.AssertExpectations(t)
}
func TestDeleteUser(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	ctx := context.Background()

	mockRepo.On("DeleteUser", ctx, 1).Return(nil)

	err := mockRepo.DeleteUser(ctx, 1)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

func TestCreateRefreshToken(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	ctx := context.Background()

	expiresAt, _ := time.Parse("2006-01-02", "2023-12-31")
	token := &entity.RefreshToken{
		UserID:    1,
		Token:     "refreshtoken",
		ExpiresAt: expiresAt,
	}

	mockRepo.On("CreateRefreshToken", ctx, token).Return(nil)

	err := mockRepo.CreateRefreshToken(ctx, token)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

func TestGetRefreshToken(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	ctx := context.Background()

	expiresAt, _ := time.Parse("2006-01-02", "2023-12-31")
	token := &entity.RefreshToken{
		ID:        1,
		UserID:    1,
		Token:     "refreshtoken",
		ExpiresAt: expiresAt,
	}

	mockRepo.On("GetRefreshToken", ctx, "refreshtoken").Return(token, nil)

	result, err := mockRepo.GetRefreshToken(ctx, "refreshtoken")
	assert.NoError(t, err)
	assert.Equal(t, token, result)

	mockRepo.AssertExpectations(t)
}

func TestDeleteRefreshToken(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	ctx := context.Background()

	mockRepo.On("DeleteRefreshToken", ctx, "refreshtoken").Return(nil)

	err := mockRepo.DeleteRefreshToken(ctx, "refreshtoken")
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}
func TestRunMigrations(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)

	mockRepo.On("RunMigrations").Return(nil)

	err := mockRepo.RunMigrations()
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}
