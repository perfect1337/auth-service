package main

import (
	"net"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/perfect1337/auth-service/docs"
	"github.com/perfect1337/auth-service/internal/config"
	grpchandler "github.com/perfect1337/auth-service/internal/delivery/grpc"
	delivery "github.com/perfect1337/auth-service/internal/delivery/http"
	user "github.com/perfect1337/auth-service/internal/proto"
	"github.com/perfect1337/auth-service/internal/repository"
	
	"github.com/perfect1337/auth-service/internal/usecase"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"google.golang.org/grpc"
	logg "github.com/perfect1337/logger"
)

// @title Auth Service API
// @version 1.0
// @description API для аутентификации и управления пользователями

// @contact.name API Support
// @contact.url https://github.com/perfect1337/auth-service/issues
// @contact.email support@auth-service.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /
// @schemes http

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT token для авторизации. Используйте "Bearer" перед токеном

func main() {
	cfg := config.Load()

	log, err := logg.New(cfg.Logger)
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
	defer log.Sync()

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
		grpc.UnaryInterceptor(logg.GRPCLoggingInterceptor(log)),
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
		logg.GinLogger(log),
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

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

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
