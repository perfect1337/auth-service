package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/perfect1337/auth-service/internal/mocks"
	"github.com/perfect1337/auth-service/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRegister(t *testing.T) {
	mockUC := new(mocks.MockAuthUseCase)
	handler := NewAuthHandler(mockUC)

	mockResponse := &usecase.AuthResponse{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
	}

	mockUC.On("Register", mock.Anything, "testuser", "test@example.com", "password").Return(mockResponse, nil)

	reqBody := map[string]string{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "password",
	}
	reqJSON, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(reqJSON))

	rr := httptest.NewRecorder()
	gin.SetMode(gin.TestMode)

	router := gin.Default()
	router.POST("/register", handler.Register)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var response usecase.AuthResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, mockResponse.AccessToken, response.AccessToken)
	assert.Equal(t, mockResponse.RefreshToken, response.RefreshToken)

	mockUC.AssertExpectations(t)
}

func TestLogin(t *testing.T) {
	mockUC := new(mocks.MockAuthUseCase)
	handler := NewAuthHandler(mockUC)

	mockResponse := &usecase.AuthResponse{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
	}

	mockUC.On("Login", mock.Anything, "test@example.com", "password").Return(mockResponse, nil)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "password",
	}
	reqJSON, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(reqJSON))

	rr := httptest.NewRecorder()
	gin.SetMode(gin.TestMode)

	router := gin.Default()
	router.POST("/login", handler.Login)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response usecase.AuthResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, mockResponse.AccessToken, response.AccessToken)
	assert.Equal(t, mockResponse.RefreshToken, response.RefreshToken)

	mockUC.AssertExpectations(t)
}

func TestRefresh(t *testing.T) {
	mockUC := new(mocks.MockAuthUseCase)
	handler := NewAuthHandler(mockUC)

	mockResponse := &usecase.AuthResponse{
		AccessToken:  "new_access_token",
		RefreshToken: "new_refresh_token",
	}

	mockUC.On("RefreshTokens", mock.Anything, "refresh_token").Return(mockResponse, nil)

	req, _ := http.NewRequest("POST", "/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "refresh_token",
	})

	rr := httptest.NewRecorder()
	gin.SetMode(gin.TestMode)

	router := gin.Default()
	router.POST("/refresh", handler.Refresh)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response usecase.AuthResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, mockResponse.AccessToken, response.AccessToken)
	assert.Equal(t, mockResponse.RefreshToken, response.RefreshToken)

	mockUC.AssertExpectations(t)
}

func TestLogout(t *testing.T) {
	mockUC := new(mocks.MockAuthUseCase)
	handler := NewAuthHandler(mockUC)

	mockUC.On("Logout", mock.Anything, "refresh_token").Return(nil)

	req, _ := http.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "refresh_token",
	})

	rr := httptest.NewRecorder()
	gin.SetMode(gin.TestMode)

	router := gin.Default()
	router.POST("/logout", handler.Logout)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockUC.AssertExpectations(t)
}

func TestValidateToken(t *testing.T) {
	t.Run("Valid token", func(t *testing.T) {
		mockUC := new(mocks.MockAuthUseCase)
		handler := NewAuthHandler(mockUC)

		mockUC.On("ValidateToken", mock.Anything, "valid_token").Return(true, nil)

		req, _ := http.NewRequest("GET", "/validate?token=valid_token", nil)
		rr := httptest.NewRecorder()

		router := gin.Default()
		router.GET("/validate", handler.ValidateToken)
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]bool
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response["valid"])

		mockUC.AssertExpectations(t)
	})

	t.Run("Empty token", func(t *testing.T) {
		mockUC := new(mocks.MockAuthUseCase)
		handler := NewAuthHandler(mockUC)

		req, _ := http.NewRequest("GET", "/validate", nil)
		rr := httptest.NewRecorder()

		router := gin.Default()
		router.GET("/validate", handler.ValidateToken)
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		mockUC.AssertNotCalled(t, "ValidateToken")
	})

	t.Run("Invalid token", func(t *testing.T) {
		mockUC := new(mocks.MockAuthUseCase)
		handler := NewAuthHandler(mockUC)

		mockUC.On("ValidateToken", mock.Anything, "invalid_token").Return(false, nil)

		req, _ := http.NewRequest("GET", "/validate?token=invalid_token", nil)
		rr := httptest.NewRecorder()

		router := gin.Default()
		router.GET("/validate", handler.ValidateToken)
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]bool
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.False(t, response["valid"])

		mockUC.AssertExpectations(t)
	})

	t.Run("Validation error", func(t *testing.T) {
		mockUC := new(mocks.MockAuthUseCase)
		handler := NewAuthHandler(mockUC)

		mockUC.On("ValidateToken", mock.Anything, "error_token").Return(false, errors.New("validation error"))

		req, _ := http.NewRequest("GET", "/validate?token=error_token", nil)
		rr := httptest.NewRecorder()

		router := gin.Default()
		router.GET("/validate", handler.ValidateToken)
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		mockUC.AssertExpectations(t)
	})
}

// Add these new test cases to your existing test file

func TestRegister_InvalidPayload(t *testing.T) {
	testCases := []struct {
		name     string
		payload  map[string]string
		expected int
	}{
		{"Missing username", map[string]string{"email": "test@test.com", "password": "pass"}, http.StatusBadRequest},
		{"Invalid email", map[string]string{"username": "test", "email": "bad", "password": "pass"}, http.StatusBadRequest},
		{"Short password", map[string]string{"username": "test", "email": "test@test.com", "password": "123"}, http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockUC := new(mocks.MockAuthUseCase)
			handler := NewAuthHandler(mockUC)

			reqJSON, _ := json.Marshal(tc.payload)
			req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(reqJSON))
			rr := httptest.NewRecorder()

			router := gin.Default()
			router.POST("/register", handler.Register)
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.expected, rr.Code)
		})
	}
}

func TestRegister_UseCaseError(t *testing.T) {
	mockUC := new(mocks.MockAuthUseCase)
	handler := NewAuthHandler(mockUC)

	mockUC.On("Register", mock.Anything, "test", "test@test.com", "password").
		Return(nil, errors.New("db error"))

	reqBody := map[string]string{
		"username": "test",
		"email":    "test@test.com",
		"password": "password",
	}
	reqJSON, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(reqJSON))
	rr := httptest.NewRecorder()

	router := gin.Default()
	router.POST("/register", handler.Register)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockUC.AssertExpectations(t)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	mockUC := new(mocks.MockAuthUseCase)
	handler := NewAuthHandler(mockUC)

	mockUC.On("Login", mock.Anything, "test@test.com", "wrongpass").
		Return(nil, errors.New("invalid credentials"))

	reqBody := map[string]string{
		"email":    "test@test.com",
		"password": "wrongpass",
	}
	reqJSON, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(reqJSON))
	rr := httptest.NewRecorder()

	router := gin.Default()
	router.POST("/login", handler.Login)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	mockUC.AssertExpectations(t)
}

func TestRefresh_MissingCookie(t *testing.T) {
	mockUC := new(mocks.MockAuthUseCase)
	handler := NewAuthHandler(mockUC)

	req, _ := http.NewRequest("POST", "/refresh", nil)
	rr := httptest.NewRecorder()

	router := gin.Default()
	router.POST("/refresh", handler.Refresh)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestLogout_NoCookie(t *testing.T) {
	mockUC := new(mocks.MockAuthUseCase)
	handler := NewAuthHandler(mockUC)

	req, _ := http.NewRequest("POST", "/logout", nil)
	rr := httptest.NewRecorder()

	router := gin.Default()
	router.POST("/logout", handler.Logout)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockUC.AssertNotCalled(t, "Logout")
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*http.Request)
		expect string
	}{
		{
			"From Authorization Header",
			func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer token123")
			},
			"token123",
		},
		{
			"From Cookie",
			func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie123"})
			},
			"cookie123",
		},
		{
			"From Query Param",
			func(r *http.Request) {
				q := r.URL.Query()
				q.Add("token", "query123")
				r.URL.RawQuery = q.Encode()
			},
			"query123",
		},
		{
			"No Token",
			func(r *http.Request) {},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/test", nil)
			tt.setup(req)

			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = req

			token := extractToken(c)
			assert.Equal(t, tt.expect, token)
		})
	}
}
