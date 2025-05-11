package main

import (
	"net"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/perfect1337/auth-service/internal/config"
	grpchandler "github.com/perfect1337/auth-service/internal/delivery/grpc"
	delivery "github.com/perfect1337/auth-service/internal/delivery/http"
	"github.com/perfect1337/auth-service/internal/logger"
	user "github.com/perfect1337/auth-service/internal/proto"
	"github.com/perfect1337/auth-service/internal/repository"
	"github.com/perfect1337/auth-service/internal/usecase"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.Load()

	log, err := logger.New(cfg.Logger)
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
	defer log.Sync()

	// Тестовые сообщения для проверки работы логгера
	log.Info("Starting auth service...")
	log.Infow("Loaded configuration",
		"server_port", cfg.Server.Port,
		"grpc_port", cfg.GRPC.Port,
		"log_level", cfg.Logger.LogLevel,
	)

	repo, err := repository.NewPostgres(cfg)
	if err != nil {
		log.Fatalw("failed to initialize repository", "error", err)
	}

	if err := repo.RunMigrations(); err != nil {
		log.Fatalw("failed to run migrations", "error", err)
	}

	authUC := usecase.NewAuthUseCase(
		repo,
		cfg.Auth.SecretKey,
		cfg.Auth.AccessTokenDuration,
		cfg.Auth.RefreshTokenDuration,
	)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(logger.GRPCLoggingInterceptor(log)),
	)
	user.RegisterUserServiceServer(
		grpcServer,
		grpchandler.NewUserServer(repo),
	)

	go func() {
		grpcPort := cfg.GRPC.Port
		if grpcPort == "" {
			grpcPort = "50051"
		}

		lis, err := net.Listen("tcp", ":"+grpcPort)
		if err != nil {
			log.Fatalw("failed to listen gRPC", "port", grpcPort, "error", err)
		}

		log.Infow("gRPC server started", "port", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalw("gRPC server failed", "error", err)
		}
	}()

	router := gin.New()
	router.Use(
		logger.GinLogger(log),
		gin.Recovery(),
	)

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	authHandler := delivery.NewAuthHandler(authUC)

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

	log.Infow("HTTP server starting", "port", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalw("HTTP server failed", "error", err)
	}
}
