package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

func setupAuthHTTPTest(t *testing.T) (*gin.Engine, *db.Database) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "auth-http.db"))
	if err != nil {
		t.Fatal(err)
	}

	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	hash, err := auth.HashPassword("CorrectPassword123!")
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "testadmin",
		PasswordHash: hash,
	}
	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	handlers := NewHandlers(database, nil)

	router := gin.New()
	router.POST("/api/auth/login", handlers.LoginAdmin)

	return router, database
}

func TestHTTPLoginSuccess(t *testing.T) {
	router, database := setupAuthHTTPTest(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		strings.NewReader(`{"username":"testadmin","password":"CorrectPassword123!"}`),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	var body struct {
		Authenticated bool `json:"authenticated"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Authenticated {
		t.Fatal("login response did not indicate authentication")
	}

	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}

	cookie := cookies[0]

	if cookie.Name != sessionCookieName {
		t.Fatalf("unexpected cookie name: %s", cookie.Name)
	}
	if !cookie.Secure || !cookie.HttpOnly {
		t.Fatal("session cookie must be Secure and HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie must use SameSite=Strict")
	}
	if cookie.Path != "/" || cookie.Domain != "" {
		t.Fatal("session cookie must be host-only with Path=/")
	}
	if cookie.MaxAge != int(auth.SessionDuration.Seconds()) {
		t.Fatal("session cookie expiration does not match session duration")
	}

	admin, err := auth.ValidateSession(database.DB, cookie.Value)
	if err != nil {
		t.Fatalf("cookie did not contain a valid session: %v", err)
	}
	if admin.Username != "testadmin" {
		t.Fatalf("unexpected authenticated administrator: %s", admin.Username)
	}

	if strings.Contains(response.Body.String(), cookie.Value) {
		t.Fatal("session token leaked into JSON response")
	}
}

func TestHTTPLoginInvalidCredentials(t *testing.T) {
	router, database := setupAuthHTTPTest(t)

	for _, payload := range []string{
		`{"username":"testadmin","password":"WrongPassword123!"}`,
		`{"username":"missingadmin","password":"CorrectPassword123!"}`,
	} {
		request := httptest.NewRequest(
			http.MethodPost,
			"/api/auth/login",
			strings.NewReader(payload),
		)
		request.Header.Set("Content-Type", "application/json")

		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d: %s", response.Code, response.Body.String())
		}
		if len(response.Result().Cookies()) != 0 {
			t.Fatal("failed login issued a cookie")
		}
	}

	var sessions int64
	if err := database.DB.Model(&db.AdminSession{}).Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("failed logins created %d sessions", sessions)
	}
}

func TestHTTPLoginMalformedRequest(t *testing.T) {
	router, _ := setupAuthHTTPTest(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		strings.NewReader(`{"username":"testadmin"}`),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.Code)
	}
	if len(response.Result().Cookies()) != 0 {
		t.Fatal("malformed request issued a cookie")
	}
}
