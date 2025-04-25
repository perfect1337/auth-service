package main

import (
	"log"
	"net"

	"github.com/perfect1337/auth-service/config"
	"github.com/perfect1337/auth-service/internal/delivery"
	"github.com/perfect1337/auth-service/internal/repository/postgres"
	"github.com/perfect1337/auth-service/internal/usecase"
	"github.com/perfect1337/auth-service/proto"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.Load()

	// Initialize repository
	repo, err := postgres.NewPostgresRepository(cfg)
	if err != nil {
		log.Fatalf("failed to initialize repository: %v", err)
	}

	// Run migrations
	if err := repo.RunMigrations(); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	// Initialize usecase
	authUC := usecase.NewAuthUseCase(
		repo,
		cfg.Auth.SecretKey,
		cfg.Auth.AccessTokenDuration,
		cfg.Auth.RefreshTokenDuration,
	)

	// Initialize gRPC server
	lis, err := net.Listen("tcp", ":"+cfg.GRPC.Port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	proto.RegisterAuthServiceServer(grpcServer, delivery.NewAuthServer(authUC))

	log.Printf("gRPC server listening on %s", cfg.GRPC.Port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
