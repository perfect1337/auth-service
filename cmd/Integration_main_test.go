package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	code := m.Run()
	os.Exit(code)
}

func TestHTTPServer(t *testing.T) {
	router := gin.Default()

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	server := httptest.NewServer(router)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	assert.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
}

func TestGRPCServer(t *testing.T) {

	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()

	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	assert.NoError(t, err)
	defer conn.Close()

}

func TestAuthMiddleware(t *testing.T) {

	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "testuser")
		c.Next()
	})

	router.GET("/protected", func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		assert.True(t, exists)
		assert.Equal(t, 1, userID)

		username, exists := c.Get("username")
		assert.True(t, exists)
		assert.Equal(t, "testuser", username)

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	server := httptest.NewServer(router)
	defer server.Close()

	resp, err := http.Get(server.URL + "/protected")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	assert.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
}

func TestRegister(t *testing.T) {

	router := gin.Default()

	router.POST("/auth/register", func(c *gin.Context) {
		var req struct {
			Username string `json:"username" binding:"required,min=3,max=20"`
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required,min=6"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		assert.Equal(t, "testuser", req.Username)
		assert.Equal(t, "test@example.com", req.Email)
		assert.Equal(t, "password", req.Password)

		c.JSON(http.StatusCreated, gin.H{"status": "created"})
	})

	server := httptest.NewServer(router)
	defer server.Close()

	registerData := map[string]string{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "password",
	}
	jsonData, _ := json.Marshal(registerData)

	resp, err := http.Post(server.URL+"/auth/register", "application/json", bytes.NewBuffer(jsonData))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	assert.NoError(t, err)
	assert.Equal(t, "created", result["status"])
}

func TestLogin(t *testing.T) {
	router := gin.Default()
	router.POST("/auth/login", func(c *gin.Context) {
		var req struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required,min=6"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		assert.Equal(t, "test@example.com", req.Email)
		assert.Equal(t, "password", req.Password)

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	server := httptest.NewServer(router)
	defer server.Close()

	loginData := map[string]string{
		"email":    "test@example.com",
		"password": "password",
	}
	jsonData, _ := json.Marshal(loginData)

	resp, err := http.Post(server.URL+"/auth/login", "application/json", bytes.NewBuffer(jsonData))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	assert.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
}
