package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/perfect1337/auth-service/internal/config"
	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/stretchr/testify/assert"
)

func setupTestDB() (*Postgres, error) {
	cfg := &config.Config{
		Postgres: config.PostgresConfig{
			Host:     "localhost",
			Port:     "5432",
			User:     "postgres",
			Password: "postgres",
			DBName:   "PG",
			SSLMode:  "disable",
		},
	}

	repo, err := NewPostgres(cfg)
	if err != nil {
		return nil, err
	}

	return repo, nil
}

func TestGetUserByID(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	// Создайте тестового пользователя с уникальным именем
	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &entity.User{
		Username:     "testuser" + uniqueSuffix,
		Email:        "testuser" + uniqueSuffix + "@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Получите пользователя по ID
	result, err := repo.GetUserByID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, user.Username, result.Username)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, user.PasswordHash, result.PasswordHash)
	assert.Equal(t, user.Role, result.Role)

	// Удалите тестового пользователя
	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}

func TestCreateUser(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	user := &entity.User{
		Username:     "newuser",
		Email:        "newuser@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	assert.NoError(t, err)

	// Удалите тестового пользователя
	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}

func TestGetUserByCredentials(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	// Создайте тестового пользователя с уникальным именем
	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &entity.User{
		Username:     "testuser" + uniqueSuffix,
		Email:        "testuser" + uniqueSuffix + "@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Получите пользователя по учетным данным
	result, err := repo.GetUserByCredentials(ctx, user.Username, "hashedpassword")
	assert.NoError(t, err)
	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, user.Username, result.Username)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, user.PasswordHash, result.PasswordHash)
	assert.Equal(t, user.Role, result.Role)

	// Удалите тестового пользователя
	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}
func TestGetUserByEmail(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	// Создайте тестового пользователя с уникальным именем
	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &entity.User{
		Username:     "testuser" + uniqueSuffix,
		Email:        "testuser" + uniqueSuffix + "@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Получите пользователя по email
	result, err := repo.GetUserByEmail(ctx, user.Email)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, user.Username, result.Username)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, user.PasswordHash, result.PasswordHash)
	assert.Equal(t, user.Role, result.Role)

	// Удалите тестового пользователя
	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}

func TestGetUserByLogin(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	// Создайте тестового пользователя с уникальным именем
	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &entity.User{
		Username:     "testuser" + uniqueSuffix,
		Email:        "testuser" + uniqueSuffix + "@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Получите пользователя по логину
	result, err := repo.GetUserByLogin(ctx, user.Username)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, user.Username, result.Username)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, user.PasswordHash, result.PasswordHash)
	assert.Equal(t, user.Role, result.Role)

	// Удалите тестового пользователя
	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}

func TestDeleteUser(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	// Создайте тестового пользователя с уникальным именем
	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &entity.User{
		Username:     "testuser" + uniqueSuffix,
		Email:        "testuser" + uniqueSuffix + "@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Удалите тестового пользователя
	err = repo.DeleteUser(ctx, user.ID)
	assert.NoError(t, err)
}

func TestCreateRefreshToken(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	// Создайте тестового пользователя с уникальным именем
	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &entity.User{
		Username:     "testuser" + uniqueSuffix,
		Email:        "testuser" + uniqueSuffix + "@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Создайте тестовый токен
	expiresAt, _ := time.Parse("2006-01-02", "2023-12-31")
	token := &entity.RefreshToken{
		UserID:    user.ID,
		Token:     "refreshtoken" + uniqueSuffix,
		ExpiresAt: expiresAt,
	}

	err = repo.CreateRefreshToken(ctx, token)
	assert.NoError(t, err)

	// Удалите тестового пользователя
	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}

func TestGetRefreshToken(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	// Создайте тестового пользователя с уникальным именем
	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &entity.User{
		Username:     "testuser" + uniqueSuffix,
		Email:        "testuser" + uniqueSuffix + "@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Создайте тестовый токен
	expiresAt, _ := time.Parse("2006-01-02", "2023-12-31")
	token := &entity.RefreshToken{
		UserID:    user.ID,
		Token:     "refreshtoken" + uniqueSuffix,
		ExpiresAt: expiresAt,
	}

	err = repo.CreateRefreshToken(ctx, token)
	if err != nil {
		t.Fatalf("Failed to create test refresh token: %v", err)
	}

	// Получите токен
	result, err := repo.GetRefreshToken(ctx, token.Token)
	assert.NoError(t, err)
	assert.Equal(t, token.UserID, result.UserID)
	assert.Equal(t, token.Token, result.Token)
	assert.True(t, token.ExpiresAt.Equal(result.ExpiresAt), "Times should be equal")

	// Удалите тестового пользователя
	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}
func TestDeleteRefreshToken(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	ctx := context.Background()

	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &entity.User{
		Username:     "testuser" + uniqueSuffix,
		Email:        "testuser" + uniqueSuffix + "@example.com",
		PasswordHash: "hashedpassword",
		Role:         "user",
	}

	err = repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	expiresAt, _ := time.Parse("2006-01-02", "2023-12-31")
	token := &entity.RefreshToken{
		UserID:    user.ID,
		Token:     "refreshtoken" + uniqueSuffix,
		ExpiresAt: expiresAt,
	}

	err = repo.CreateRefreshToken(ctx, token)
	if err != nil {
		t.Fatalf("Failed to create test refresh token: %v", err)
	}

	err = repo.DeleteRefreshToken(ctx, token.Token)
	assert.NoError(t, err)

	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}

func TestRunMigrations(t *testing.T) {
	repo, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}

	err = repo.RunMigrations()
	assert.NoError(t, err)
}
