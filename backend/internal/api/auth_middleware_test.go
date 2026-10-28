package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

func TestRequireAdminMiddleware(t *testing.T) {
	_, database := setupAuthHTTPTest(t)

	handlers := NewHandlers(database, nil)

	router := gin.New()
	router.GET("/protected", handlers.RequireAdmin(), func(c *gin.Context) {
		admin, ok := CurrentAdmin(c)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Administrator missing from context",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"username": admin.Username,
		})
	})

	request := func(token string) *httptest.ResponseRecorder {
		t.Helper()

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)

		if token != "" {
			req.AddCookie(&http.Cookie{
				Name:  sessionCookieName,
				Value: token,
			})
		}

		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)

		return response
	}

	t.Run("missing session", func(t *testing.T) {
		response := request("")

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", response.Code)
		}
	})

	t.Run("valid session", func(t *testing.T) {
		token, err := auth.CreateSession(database.DB, 1)
		if err != nil {
			t.Fatal(err)
		}

		response := request(token)

		if response.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s",
				response.Code, response.Body.String())
		}

		if err := auth.RevokeSession(database.DB, token); err != nil {
			t.Fatal(err)
		}

		response = request(token)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("revoked session: expected 401, got %d",
				response.Code)
		}
	})

	t.Run("expired session", func(t *testing.T) {
		token, err := auth.CreateSession(database.DB, 1)
		if err != nil {
			t.Fatal(err)
		}

		if err := database.DB.Model(&db.AdminSession{}).
			Where("token_hash = ?", sessionHashForTest(token)).
			Update("expires_at", time.Now().UTC().Add(-time.Hour)).
			Error; err != nil {
			t.Fatal(err)
		}

		response := request(token)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expired session: expected 401, got %d",
				response.Code)
		}
	})
}

func sessionHashForTest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
