package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/perfect1337/auth-service/internal/mocks"
	"github.com/perfect1337/auth-service/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestRegister_Success(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	// Мокируем проверку существования пользователя по email
	mockRepo.On("GetUserByEmail", mock.Anything, "test@example.com").
		Return(nil, errors.New("user not found"))

	// Мокируем проверку существования пользователя по username
	mockRepo.On("GetUserByLogin", mock.Anything, "testuser").
		Return(nil, errors.New("user not found"))

	// Мокируем создание пользователя
	mockRepo.On("CreateUser", mock.Anything, mock.AnythingOfType("*entity.User")).
		Return(nil).
		Run(func(args mock.Arguments) {
			user := args.Get(1).(*entity.User)
			user.ID = 1
		})

	// Мокируем создание refresh токена
	mockRepo.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).
		Return(nil)

	resp, err := uc.Register(context.Background(), "testuser", "test@example.com", "password")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "testuser", resp.User.Username)
	mockRepo.AssertExpectations(t)
}

func TestRegister_UserExists(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	// Мокируем проверку существования пользователя по email
	mockRepo.On("GetUserByEmail", mock.Anything, "exists@test.com").
		Return(&entity.User{
			ID:       1,
			Username: "existing",
			Email:    "exists@test.com",
		}, nil)

	resp, err := uc.Register(context.Background(), "existing", "exists@test.com", "password")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "пользователь с таким email уже существует")
	mockRepo.AssertExpectations(t)
}

func TestLogin_Success(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	// Генерируем реальный хеш пароля "password" для теста
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate password hash: %v", err)
	}

	mockRepo.On("GetUserByEmail", mock.Anything, "test@example.com").
		Return(&entity.User{
			ID:           1,
			Username:     "testuser",
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword), // Используем реальный хеш
			Role:         "user",
		}, nil)

	mockRepo.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).
		Return(nil)

	resp, err := uc.Login(context.Background(), "test@example.com", "password")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	mockRepo.AssertExpectations(t)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	mockRepo.On("GetUserByEmail", mock.Anything, "test@example.com").
		Return(&entity.User{
			ID:           1,
			Username:     "testuser",
			Email:        "test@example.com",
			PasswordHash: "$2a$10$fakehashedpassword", // Doesn't match "wrongpass"
			Role:         "user",
		}, nil)

	resp, err := uc.Login(context.Background(), "test@example.com", "wrongpass")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid password")
	mockRepo.AssertExpectations(t)
}

func TestRefreshTokens_Success(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	mockRepo.On("GetRefreshToken", mock.Anything, "valid_token").
		Return(&entity.RefreshToken{
			ID:        1,
			UserID:    1,
			Token:     "valid_token",
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil)

	mockRepo.On("GetUserByID", mock.Anything, 1).
		Return(&entity.User{
			ID:       1,
			Username: "testuser",
			Email:    "test@example.com",
			Role:     "user",
		}, nil)

	mockRepo.On("DeleteRefreshToken", mock.Anything, "valid_token").
		Return(nil)

	mockRepo.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).
		Return(nil)

	resp, err := uc.RefreshTokens(context.Background(), "valid_token")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	mockRepo.AssertExpectations(t)
}

func TestRefreshTokens_Expired(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	mockRepo.On("GetRefreshToken", mock.Anything, "expired_token").
		Return(&entity.RefreshToken{
			ID:        1,
			UserID:    1,
			Token:     "expired_token",
			ExpiresAt: time.Now().Add(-time.Hour),
		}, nil)

	resp, err := uc.RefreshTokens(context.Background(), "expired_token")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "refresh token expired")
	mockRepo.AssertExpectations(t)
}

func TestLogout_Success(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	mockRepo.On("DeleteRefreshToken", mock.Anything, "valid_token").
		Return(nil)

	err := uc.Logout(context.Background(), "valid_token")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestValidateToken_Valid(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  1,
		"username": "testuser",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("test_secret"))

	valid, err := uc.ValidateToken(context.Background(), tokenString)

	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateToken_Invalid(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	uc := usecase.NewAuthUseCase(mockRepo, "test_secret", time.Hour, 24*time.Hour)

	valid, err := uc.ValidateToken(context.Background(), "invalid.token.string")

	assert.Error(t, err)
	assert.False(t, valid)
}

func TestGetSecretKey(t *testing.T) {
	mockRepo := new(mocks.MockCompositeRepository)
	expectedKey := "test_secret_key"
	uc := usecase.NewAuthUseCase(mockRepo, expectedKey, time.Hour, 24*time.Hour)

	key, err := uc.GetSecretKey()

	assert.NoError(t, err)
	assert.Equal(t, expectedKey, key)
}
