package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/perfect1337/auth-service/internal/entity"
	"github.com/perfect1337/auth-service/internal/repository"
	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
)

type AuthUseCase struct {
	repo       repository.UserRepository
	secretKey  string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewAuthUseCase(repo repository.UserRepository, secretKey string, accessTTL, refreshTTL time.Duration) *AuthUseCase {
	return &AuthUseCase{
		repo:       repo,
		secretKey:  secretKey,
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

func (uc *AuthUseCase) Login(ctx context.Context, login, password string) (*entity.AuthResponse, error) {
	user, err := uc.repo.GetUserByCredentials(ctx, login, password)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	return uc.generateAuthResponse(ctx, user)
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
	return token.SignedString([]byte(uc.secretKey))
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
