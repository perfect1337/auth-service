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

// AuthHandler представляет обработчик для аутентификации
type AuthHandler struct {
	uc usecase.AuthUseCase
}

// NewAuthHandler создает новый экземпляр AuthHandler
// @Summary Создает новый обработчик аутентификации
func NewAuthHandler(uc usecase.AuthUseCase) *AuthHandler {
	return &AuthHandler{uc: uc}
}

// Register регистрирует нового пользователя
// @Summary Регистрация нового пользователя
// @Tags Auth
// @Accept json
// @Produce json
//
//	@Param input body struct {
//		Username string `json:"username" binding:"required,min=3,max=20"`
//		Email    string `json:"email" binding:"required,email"`
//		Password string `json:"password" binding:"required,min=6"`
//	} true "Данные для регистрации"
//
// @Success 201 {object} usercase.AuthResponse
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /auth/register [post]
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

// Login выполняет вход пользователя
// @Summary Вход в систему
// @Tags Auth
// @Accept json
// @Produce json
//
//	@Param input body struct {
//		Email    string `json:"email" binding:"required,email"`
//		Password string `json:"password" binding:"required,min=6"`
//	} true "Учетные данные"
//
// @Success 200 {object} usercase.AuthResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/login [post]
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

// Refresh обновляет токены доступа
// @Summary Обновление токенов
// @Tags Auth
// @Produce json
// @Success 200 {object} usercase.AuthResponse
// @Failure 401 {object} map[string]string
// @Router /auth/refresh [post]
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

// Logout выполняет выход пользователя
// @Summary Выход из системы
// @Tags Auth
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /auth/logout [post]
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

// ValidateToken проверяет валидность токена
// @Summary Проверка токена
// @Tags Auth
// @Produce json
// @Param token query string true "Токен для проверки"
// @Success 200 {object} map[string]interface{} "valid: boolean"
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /auth/validate [get]
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

// AuthMiddleware middleware для проверки аутентификации
// @Security ApiKeyAuth
// @Param Authorization header string true "Bearer {token}"
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
				"details": err.Error(),
			})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("user_id", claims["user_id"])
			c.Set("username", claims["username"].(string))
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
		}
	}
}

func extractToken(c *gin.Context) string {
	tokenString := c.GetHeader("Authorization")
	if tokenString != "" {
		return strings.Replace(tokenString, "Bearer ", "", 1)
	}

	tokenString, _ = c.Cookie("access_token")
	if tokenString != "" {
		return tokenString
	}

	return c.Query("token")
}
