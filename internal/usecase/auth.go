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

type AuthUseCase interface {
	Register(ctx context.Context, username, email, password string) (*AuthResponse, error)
	Login(ctx context.Context, email, password string) (*AuthResponse, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*AuthResponse, error)
	Logout(ctx context.Context, refreshToken string) error
	ValidateToken(ctx context.Context, token string) (bool, error)
	GetSecretKey() (string, error)
}

type AuthResponse struct {
	AccessToken  string
	RefreshToken string
	User         entity.User
}

type authUseCase struct {
	repo       repository.CompositeRepository
	SecretKey  string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewAuthUseCase(repo repository.CompositeRepository, secretKey string, accessTTL, refreshTTL time.Duration) AuthUseCase {
	return &authUseCase{
		repo:       repo,
		SecretKey:  secretKey,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (uc *authUseCase) Register(ctx context.Context, username, email, password string) (*AuthResponse, error) {
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
func (uc *authUseCase) GetSecretKey() (string, error) {
	return uc.SecretKey, nil
}
func (uc *authUseCase) Login(ctx context.Context, email, password string) (*AuthResponse, error) {
	log.Printf("Looking for user with email: %s", email)

	user, err := uc.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("User not found: %v", err)
		return nil, fmt.Errorf("user not found")
	}

	log.Printf("Found user: %s", user.Username)

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		log.Printf("Password mismatch for user %s", user.Email)
		return nil, fmt.Errorf("invalid password")
	}

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

	if err := uc.repo.CreateRefreshToken(ctx, &entity.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: expiresAt,
	}); err != nil {
		log.Printf("Failed to save refresh token: %v", err)
		return nil, fmt.Errorf("failed to save refresh token")
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         *user,
	}, nil
}

func (uc *authUseCase) RefreshTokens(ctx context.Context, refreshToken string) (*AuthResponse, error) {
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

	err = uc.repo.DeleteRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return uc.generateAuthResponse(ctx, user)
}

func (uc *authUseCase) Logout(ctx context.Context, refreshToken string) error {
	return uc.repo.DeleteRefreshToken(ctx, refreshToken)
}

func (uc *authUseCase) ValidateToken(ctx context.Context, token string) (bool, error) {
	// Реализация проверки токена
	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(uc.SecretKey), nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (uc *authUseCase) generateAuthResponse(ctx context.Context, user *entity.User) (*AuthResponse, error) {
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

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         *user,
	}, nil
}

func (uc *authUseCase) generateAccessToken(user *entity.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(uc.accessTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(uc.SecretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}
func (uc *authUseCase) generateRefreshToken() (string, time.Time, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", time.Time{}, err
	}

	token := base64.URLEncoding.EncodeToString(b)
	expiresAt := time.Now().Add(uc.refreshTTL)

	return token, expiresAt, nil
}
