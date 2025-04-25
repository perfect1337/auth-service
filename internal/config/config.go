package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server struct {
		Port string
	}
	Postgres struct {
		Host     string
		Port     string
		User     string
		Password string
		DBName   string
		SSLMode  string
	}
	Auth struct {
		SecretKey            string
		AccessTokenDuration  time.Duration
		RefreshTokenDuration time.Duration
	}
	GRPC struct {
		Port string
	}
}

func Load() *Config {
	_ = godotenv.Load()

	cfg := &Config{}

	// Server
	cfg.Server.Port = getEnv("SERVER_PORT", "8081")

	// Postgres
	cfg.Postgres.Host = getEnv("DB_HOST", "localhost")
	cfg.Postgres.Port = getEnv("DB_PORT", "5432")
	cfg.Postgres.User = getEnv("DB_USER", "postgres")
	cfg.Postgres.Password = getEnv("DB_PASSWORD", "postgres")
	cfg.Postgres.DBName = getEnv("DB_NAME", "auth_service")
	cfg.Postgres.SSLMode = getEnv("DB_SSLMODE", "disable")

	// Auth
	cfg.Auth.SecretKey = getEnv("AUTH_SECRET_KEY", "secret-key")
	cfg.Auth.AccessTokenDuration = getEnvAsDuration("ACCESS_TOKEN_DURATION", 15*time.Minute)
	cfg.Auth.RefreshTokenDuration = getEnvAsDuration("REFRESH_TOKEN_DURATION", 24*time.Hour)

	// GRPC
	cfg.GRPC.Port = getEnv("GRPC_PORT", "50051")

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsDuration(name string, defaultVal time.Duration) time.Duration {
	valueStr := getEnv(name, "")
	if value, err := time.ParseDuration(valueStr); err == nil {
		return value
	}
	return defaultVal
}
