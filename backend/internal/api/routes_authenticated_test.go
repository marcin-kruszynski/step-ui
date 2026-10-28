package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
)

func TestAuthenticatedProductionRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const trustedOrigin = "https://step-ui.mjm.internal"

	// Reuse the disposable database and administrator from
	// the existing HTTP authentication tests.
	_, database := setupAuthHTTPTest(t)

	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}

	SetupRoutes(router, NewHandlers(database, nil), trustedOrigin)

	var adminID uint
	if err := database.DB.
		Table("admin_users").
		Select("id").
		Where("username = ?", "testadmin").
		Scan(&adminID).Error; err != nil {
		t.Fatal(err)
	}
	if adminID == 0 {
		t.Fatal("test administrator not found")
	}

	token, err := auth.CreateSession(database.DB, adminID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	request := func(method, path, origin string) *httptest.ResponseRecorder {
		t.Helper()

		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(&http.Cookie{
			Name:  sessionCookieName,
			Value: token,
		})

		if origin != "" {
			req.Header.Set("Origin", origin)
		}

		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	t.Run("authenticated administrator", func(t *testing.T) {
		response := request(http.MethodGet, "/api/auth/me", "")

		if response.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s",
				response.Code, response.Body.String())
		}

		var body struct {
			Authenticated bool `json:"authenticated"`
			Admin         struct {
				ID       uint   `json:"id"`
				Username string `json:"username"`
			} `json:"admin"`
		}

		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}

		if !body.Authenticated ||
			body.Admin.ID != adminID ||
			body.Admin.Username != "testadmin" {
			t.Fatalf("unexpected administrator response: %+v", body)
		}

		for _, secret := range []string{
			token,
			"password_hash",
			"PasswordHash",
			"token_hash",
		} {
			if strings.Contains(response.Body.String(), secret) {
				t.Fatalf("sensitive field appeared in response: %s", secret)
			}
		}
	})

	t.Run("cross-origin logout rejected", func(t *testing.T) {
		response := request(
			http.MethodPost,
			"/api/auth/logout",
			"https://attacker.example",
		)

		if response.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", response.Code)
		}

		// A rejected cross-origin request must not revoke the session.
		if _, err := auth.ValidateSession(database.DB, token); err != nil {
			t.Fatalf("cross-origin request revoked session: %v", err)
		}
	})

	t.Run("legitimate logout", func(t *testing.T) {
		response := request(
			http.MethodPost,
			"/api/auth/logout",
			trustedOrigin,
		)

		if response.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s",
				response.Code, response.Body.String())
		}

		if _, err := auth.ValidateSession(database.DB, token); err == nil {
			t.Fatal("session remained valid after logout")
		}
	})

	t.Run("revoked session rejected", func(t *testing.T) {
		response := request(http.MethodGet, "/api/auth/me", "")

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", response.Code)
		}
	})
}
