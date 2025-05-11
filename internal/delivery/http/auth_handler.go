package delivery

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/perfect1337/auth-service/internal/config"
	"github.com/perfect1337/auth-service/internal/usecase"
)

type AuthHandler struct {
	uc usecase.AuthUseCase
}

func NewAuthHandler(uc usecase.AuthUseCase) *AuthHandler { // Убрали указатель *
	return &AuthHandler{uc: uc}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required,min=3,max=20"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authResponse, err := h.uc.Register(c.Request.Context(), req.Username, req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, authResponse)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authResponse, err := h.uc.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(
		"refresh_token",
		authResponse.RefreshToken,
		int(15*24*time.Hour/time.Second),
		"/",
		"",
		false,
		true,
	)

	// Возвращаем полную структуру AuthResponse
	c.JSON(http.StatusOK, gin.H{
		"AccessToken":  authResponse.AccessToken,
		"RefreshToken": authResponse.RefreshToken,
		"User": gin.H{
			"ID":       authResponse.User.ID,
			"Username": authResponse.User.Username,
			"Email":    authResponse.User.Email,
			"Role":     authResponse.User.Role,
		},
	})
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token required"})
		return
	}

	authResponse, err := h.uc.RefreshTokens(c.Request.Context(), refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.SetCookie(
		"refresh_token",
		authResponse.RefreshToken,
		int(15*24*time.Hour/time.Second),
		"/",
		"",
		false,
		true,
	)

	c.JSON(http.StatusOK, authResponse)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "already logged out"})
		return
	}

	err = h.uc.Logout(c.Request.Context(), refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		"",
		false,
		true,
	)

	c.JSON(http.StatusOK, gin.H{"message": "successfully logged out"})
}

func extractToken(c *gin.Context) string {
	// 1. Проверяем Authorization header
	tokenString := c.GetHeader("Authorization")
	if tokenString != "" {
		return strings.Replace(tokenString, "Bearer ", "", 1)
	}

	// 2. Проверяем cookie
	tokenString, _ = c.Cookie("access_token")
	if tokenString != "" {
		return tokenString
	}

	// 3. Проверяем query parameter
	tokenString = c.Query("token")
	return tokenString
}
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := extractToken(c)
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization token required"})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(cfg.Auth.SecretKey), nil
		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid token",
				"details": err.Error(), // Add this for debugging
			})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Add proper type assertions
			c.Set("user_id", claims["user_id"])
			c.Set("username", claims["username"].(string))

			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
		}
	}
}

func (h *AuthHandler) ValidateToken(c *gin.Context) {
	tokenString := c.Query("token")
	if tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": "token parameter is required"})
		return
	}

	valid, err := h.uc.ValidateToken(c.Request.Context(), tokenString)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"valid": false,
			"error": "failed to validate token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": valid})
}
