package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/perfect1337/auth-service/internal/config"
	grpchandler "github.com/perfect1337/auth-service/internal/delivery/grpc"
	delivery "github.com/perfect1337/auth-service/internal/delivery/http"
	user "github.com/perfect1337/auth-service/internal/proto"
	"github.com/perfect1337/auth-service/internal/repository"
	"github.com/perfect1337/auth-service/internal/usecase"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.Load()

	// Initialize repository
	repo, err := repository.NewPostgres(cfg)
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
	grpcServer := grpc.NewServer()
	user.RegisterUserServiceServer(
		grpcServer,
		grpchandler.NewUserServer(repo), // Передаем repo вместо authUC
	)

	// Start gRPC server in goroutine
	go func() {
		grpcPort := os.Getenv("GRPC_PORT")
		if grpcPort == "" {
			grpcPort = "50051" // Значение по умолчанию
		}

		lis, err := net.Listen("tcp", ":"+grpcPort)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		log.Printf("gRPC server listening on :%s", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// Initialize HTTP server
	router := gin.Default()
	router.Use(func(c *gin.Context) {
		log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	})

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Initialize handlers
	authHandler := delivery.NewAuthHandler(authUC)

	// Routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	auth := router.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.GET("/validate", authHandler.ValidateToken)
		auth.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "auth ok"})
		})

		protected := auth.Group("")
		protected.Use(delivery.AuthMiddleware(cfg))
		{
			protected.POST("/refresh", authHandler.Refresh)
			protected.POST("/logout", authHandler.Logout)
		}
	}

	log.Printf("HTTP server is running on port %s", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
