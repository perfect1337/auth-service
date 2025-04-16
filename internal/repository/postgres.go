package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/perfect1337/auth-service/internal/entity"
)

type Postgres struct {
	db *sql.DB
}

var migrationsFS embed.FS

func (p *Postgres) RunMigrations() error {
	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create iofs: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", d,
		fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
			p.cfg.Postgres.User,
			p.cfg.Postgres.Password,
			p.cfg.Postgres.Host,
			p.cfg.Postgres.Port,
			p.cfg.Postgres.DBName,
			p.cfg.Postgres.SSLMode,
		))
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	log.Printf("Migrations applied. Current version: %d, dirty: %v", version, dirty)
	return nil
}
func NewPostgres(cfg *config.Config) (*Postgres, error) {
	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.User,
		cfg.Postgres.Password,
		cfg.Postgres.DBName,
		cfg.Postgres.SSLMode,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping db: %w", err)
	}

	return &Postgres{db: db}, nil
}

func (p *Postgres) CreateUser(ctx context.Context, user *entity.User) error {
	query := `INSERT INTO users (username, email, password_hash, role) 
	          VALUES ($1, $2, $3, $4) RETURNING id`

	err := p.db.QueryRowContext(ctx, query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.Role,
	).Scan(&user.ID)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (p *Postgres) GetUserByCredentials(ctx context.Context, login, passwordHash string) (*entity.User, error) {
	query := `SELECT id, username, email, password_hash, role 
	          FROM users 
	          WHERE (username = $1 OR email = $1) AND password_hash = $2`

	var user entity.User
	err := p.db.QueryRowContext(ctx, query, login, passwordHash).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (p *Postgres) CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (user_id, token, expires_at) 
	          VALUES ($1, $2, $3)`

	_, err := p.db.ExecContext(ctx, query,
		token.UserID,
		token.Token,
		token.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}

	return nil
}

func (p *Postgres) GetRefreshToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	query := `SELECT id, user_id, token, expires_at 
	          FROM refresh_tokens 
	          WHERE token = $1`

	var rt entity.RefreshToken
	err := p.db.QueryRowContext(ctx, query, token).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.ExpiresAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token not found")
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	return &rt, nil
}

func (p *Postgres) DeleteRefreshToken(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = $1`

	_, err := p.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}
