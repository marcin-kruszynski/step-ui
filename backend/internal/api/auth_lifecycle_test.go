package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/db"
)

func TestHTTPAuthenticationLifecycle(t *testing.T) {
	_, database := setupAuthHTTPTest(t)

	handlers := NewHandlers(database, nil)

	router := gin.New()
	router.POST("/api/auth/login", handlers.LoginAdmin)

	protected := router.Group("/api/auth")
	protected.Use(handlers.RequireAdmin())
	protected.GET("/me", handlers.GetCurrentAdmin)
	protected.POST("/logout", handlers.LogoutAdmin)

	// 1. Unauthenticated requests must be rejected.
	meRequest := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meResponse := httptest.NewRecorder()
	router.ServeHTTP(meResponse, meRequest)

	if meResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me: expected 401, got %d", meResponse.Code)
	}

	// 2. Authenticate.
	loginRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		strings.NewReader(`{"username":"testadmin","password":"CorrectPassword123!"}`),
	)
	loginRequest.Header.Set("Content-Type", "application/json")

	loginResponse := httptest.NewRecorder()
	router.ServeHTTP(loginResponse, loginRequest)

	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s",
			loginResponse.Code, loginResponse.Body.String())
	}

	cookies := loginResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}

	sessionCookie := cookies[0]

	// 3. The authenticated administrator should be identifiable.
	meRequest = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meRequest.AddCookie(sessionCookie)

	meResponse = httptest.NewRecorder()
	router.ServeHTTP(meResponse, meRequest)

	if meResponse.Code != http.StatusOK {
		t.Fatalf("authenticated /me: expected 200, got %d", meResponse.Code)
	}

	if !strings.Contains(meResponse.Body.String(), `"username":"testadmin"`) {
		t.Fatalf("unexpected /me response: %s", meResponse.Body.String())
	}

	if strings.Contains(meResponse.Body.String(), "PasswordHash") ||
		strings.Contains(meResponse.Body.String(), "password_hash") {
		t.Fatal("/me exposed password hash")
	}

	// 4. Logout should revoke the session.
	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	logoutRequest.AddCookie(sessionCookie)

	logoutResponse := httptest.NewRecorder()
	router.ServeHTTP(logoutResponse, logoutRequest)

	if logoutResponse.Code != http.StatusOK {
		t.Fatalf("logout failed: %d %s",
			logoutResponse.Code, logoutResponse.Body.String())
	}

	clearedCookies := logoutResponse.Result().Cookies()
	if len(clearedCookies) != 1 ||
		clearedCookies[0].Name != sessionCookieName ||
		clearedCookies[0].MaxAge >= 0 {
		t.Fatal("logout did not expire the session cookie")
	}

	// 5. Reusing the old cookie must fail.
	meRequest = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meRequest.AddCookie(sessionCookie)

	meResponse = httptest.NewRecorder()
	router.ServeHTTP(meResponse, meRequest)

	if meResponse.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session: expected 401, got %d", meResponse.Code)
	}

	// 6. Exactly one logout audit event must exist.
	var audits int64
	if err := database.DB.Model(&db.AuditEvent{}).
		Where("action = ? AND who = ?", "admin.logout", "testadmin").
		Count(&audits).Error; err != nil {
		t.Fatal(err)
	}

	if audits != 1 {
		t.Fatalf("expected one logout audit event, got %d", audits)
	}
}
