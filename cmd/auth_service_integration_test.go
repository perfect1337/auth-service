package main

import "github.com/perfect1337/auth-service/internal/config"
"github.com/perfect1337/auth-service/internal/repository"

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
