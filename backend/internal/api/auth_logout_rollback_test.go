package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
)

func TestHTTPLogoutAuditRollback(t *testing.T) {
	_, database := setupAuthHTTPTest(t)

	handlers := NewHandlers(database, nil)

	router := gin.New()

	protected := router.Group("/api/auth")
	protected.Use(handlers.RequireAdmin())
	protected.POST("/logout", handlers.LogoutAdmin)

	token, err := auth.CreateSession(database.DB, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate an audit persistence failure.
	if err := database.DB.Exec("DROP TABLE audit_events").Error; err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/logout",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: token,
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"expected 500 when audit logging fails, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}

	// A failed transaction must not revoke the session.
	if _, err := auth.ValidateSession(database.DB, token); err != nil {
		t.Fatalf("session was revoked despite audit rollback: %v", err)
	}

	// A failed logout must not clear the browser cookie.
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			t.Fatal("failed logout unexpectedly modified session cookie")
		}
	}
}
