package main

import (
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/perfect1337/auth-service/internal/config"
	"github.com/perfect1337/auth-service/internal/delivery"
	"github.com/perfect1337/auth-service/internal/repository"
	"github.com/perfect1337/auth-service/internal/usecase"
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

	// Initialize HTTP server
	router := gin.Default()

	// Request logging middleware
	router.Use(func(c *gin.Context) {
		log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	})

	// CORS configuration
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

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Auth routes
	auth := router.Group("/auth")
	{
		// Public routes
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.GET("/validate", authHandler.ValidateToken)
		auth.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "auth ok"})
		})

		// Protected routes (require authentication)
		protected := auth.Group("")
		protected.Use(delivery.AuthMiddleware(cfg))
		{
			protected.POST("/refresh", authHandler.Refresh)
			protected.POST("/logout", authHandler.Logout)
		}
	}

	// Start server
	log.Printf("Server is running on port %s", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
