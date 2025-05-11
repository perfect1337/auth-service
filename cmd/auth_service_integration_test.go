package main

import (
	"fmt"

	"github.com/perfect1337/auth-service/internal/config"
	"github.com/perfect1337/auth-service/internal/repository"
)

func setupTestDB() (*repository.Postgres, error) {
	cfg := &config.Config{
		Postgres: config.PostgresConfig{
			Host:     "localhost",
			Port:     "5432",
			User:     "postgres",
			Password: "postgres",
			DBName:   "PG", // Use a dedicated test database
			SSLMode:  "disable",
		},
	}

	repo, err := repository.NewPostgres(cfg)
	if err != nil {
		return nil, err
	}

	// Run migrations to ensure test DB is in correct state
	if err := repo.RunMigrations(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return repo, nil
}
