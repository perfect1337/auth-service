package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/perfect1337/auth-service/internal/repository"
	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
)

type AuthUseCase struct {
	repo       repository.CompositeRepository
	SecretKey  string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewAuthUseCase(repo repository.CompositeRepository, secretKey string, accessTTL, refreshTTL time.Duration) *AuthUseCase {
	return &AuthUseCase{
		repo:       repo,
		SecretKey:  secretKey,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}
func (uc *AuthUseCase) Register(ctx context.Context, username, email, password string) (*entity.AuthResponse, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &entity.User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		Role:         "user",
	}

	err = uc.repo.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return uc.generateAuthResponse(ctx, user)
}

func (uc *AuthUseCase) Login(ctx context.Context, email, password string) (*entity.AuthResponse, error) {
	log.Printf("Looking for user with email: %s", email)

	user, err := uc.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("User not found: %v", err)
		return nil, fmt.Errorf("user not found")
	}

	log.Printf("Found user: %s", user.Username)

	// Проверка пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		log.Printf("Password mismatch for user %s", user.Email)
		return nil, fmt.Errorf("invalid password")
	}

	// Генерация токенов
	accessToken, err := uc.generateAccessToken(user)
	if err != nil {
		log.Printf("Failed to generate access token: %v", err)
		return nil, fmt.Errorf("failed to generate token")
	}

	refreshToken, expiresAt, err := uc.generateRefreshToken()
	if err != nil {
		log.Printf("Failed to generate refresh token: %v", err)
		return nil, fmt.Errorf("failed to generate refresh token")
	}

	// Сохранение refresh токена
	if err := uc.repo.CreateRefreshToken(ctx, &entity.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: expiresAt,
	}); err != nil {
		log.Printf("Failed to save refresh token: %v", err)
		return nil, fmt.Errorf("failed to save refresh token")
	}

	return &entity.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         *user,
	}, nil
}
func (uc *AuthUseCase) RefreshTokens(ctx context.Context, refreshToken string) (*entity.AuthResponse, error) {
	token, err := uc.repo.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}

	user, err := uc.repo.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Delete old refresh token
	err = uc.repo.DeleteRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return uc.generateAuthResponse(ctx, user)
}

func (uc *AuthUseCase) Logout(ctx context.Context, refreshToken string) error {
	return uc.repo.DeleteRefreshToken(ctx, refreshToken)
}

func (uc *AuthUseCase) generateAuthResponse(ctx context.Context, user *entity.User) (*entity.AuthResponse, error) {
	accessToken, err := uc.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, expiresAt, err := uc.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	err = uc.repo.CreateRefreshToken(ctx, &entity.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &entity.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         *user,
	}, nil
}

func (uc *AuthUseCase) generateAccessToken(user *entity.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(uc.accessTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(uc.SecretKey))
}

func (uc *AuthUseCase) generateRefreshToken() (string, time.Time, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", time.Time{}, err
	}

	token := base64.URLEncoding.EncodeToString(b)
	expiresAt := time.Now().Add(uc.refreshTTL)

	return token, expiresAt, nil
}
