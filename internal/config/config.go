package config

import (
	"time"

	"github.com/perfect1337/logger"
)

// PostgresConfig содержит конфигурацию для подключения к PostgreSQL
type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// Config содержит общую конфигурацию приложения
type Config struct {
	Postgres PostgresConfig
	Server   struct {
		Port string `yaml:"port"`
	} `yaml:"server"`

	Auth struct {
		AccessTokenDuration  time.Duration
		RefreshTokenDuration time.Duration
		SecretKey            string
	}
	Migrations struct {
		Enable bool
	}
	Logger logger.Config `yaml:"logger"`
	GRPC   struct {
		Port string `yaml:"port"`
	} `yaml:"grpc"`
}

func Load() *Config {
	cfg := &Config{}

	// Postgres
	cfg.Postgres.Host = "localhost"
	cfg.Postgres.Port = "5432"
	cfg.Postgres.User = "postgres"
	cfg.Postgres.Password = "postgres"
	cfg.Postgres.DBName = "PG"
	cfg.Postgres.SSLMode = "disable"

	// Server
	cfg.Server.Port = "8080"

	// Auth
	cfg.Auth.AccessTokenDuration = 15 * time.Minute
	cfg.Auth.RefreshTokenDuration = 360 * time.Hour
	cfg.Auth.SecretKey = "your-secret-key"

	// Logger
	cfg.Logger = logger.Config{
		LogLevel:    "debug",
		Development: true,
		Encoding:    "console",
		OutputPaths: []string{"stdout"},
	}

	// GRPC
	cfg.GRPC.Port = "50051"

	cfg.Migrations.Enable = false

	return cfg
}
