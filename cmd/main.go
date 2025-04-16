package main

import (
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/perfect1337/auth-service/internal/config"
	http "github.com/perfect1337/auth-service/internal/delivery"
	"github.com/perfect1337/auth-service/internal/repository"
	"github.com/perfect1337/auth-service/internal/usecase"
)

func main() {
	cfg := config.Load()

	// Инициализация репозитория
	repo, err := repository.NewPostgres(cfg)
	if err != nil {
		log.Fatalf("failed to initialize repository: %v", err)
	}

	// Инициализация usecase
	authUC := usecase.NewAuthUseCase(
		repo,
		cfg.Auth.SecretKey,
		cfg.Auth.AccessTokenDuration,
		cfg.Auth.RefreshTokenDuration,
	)

	// Инициализация HTTP сервера
	router := gin.Default()

	// Логирование запросов (должно быть первым middleware)
	router.Use(func(c *gin.Context) {
		log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	})

	// Настройка CORS (должно быть перед обработчиками маршрутов)
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Инициализация обработчиков
	authHandler := http.NewAuthHandler(authUC)

	// Основной health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Группа аутентификации
	auth := router.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout)
		auth.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "auth ok"})
		})
	}

	// Запуск сервера (должен быть последним)
	log.Printf("Server is running on port %s", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
