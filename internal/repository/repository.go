package repository

import (
	"context"

	"github.com/perfect1337/auth-service/internal/entity"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *entity.User) error
	GetUserByCredentials(ctx context.Context, login, passwordHash string) (*entity.User, error)
	GetUserByID(ctx context.Context, id int) (*entity.User, error)
	GetUserByLogin(ctx context.Context, login string) (*entity.User, error)
	CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*entity.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
}
