package repository

import (
	"context"

	"github.com/perfect1337/auth-service/internal/entity"
)

// UserRepository отвечает за операции с пользователями
type UserRepository interface {
	CreateUser(ctx context.Context, user *entity.User) error
	GetUserByID(ctx context.Context, id int) (*entity.User, error)
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
	GetUserByLogin(ctx context.Context, login string) (*entity.User, error)
	GetUserByCredentials(ctx context.Context, login, passwordHash string) (*entity.User, error)
	DeleteUser(ctx context.Context, id int) error
}

// TokenRepository отвечает за операции с токенами
type TokenRepository interface {
	CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*entity.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
}

// MigrationManager отвечает за управление миграциями
type MigrationManager interface {
	RunMigrations() error
}

// CompositeRepository объединяет все репозитории
type CompositeRepository interface {
	UserRepository
	TokenRepository
	MigrationManager
}
