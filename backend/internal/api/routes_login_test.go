package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

func TestProductionRouterLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const trustedOrigin = "https://step-ui.mjm.internal"

	_, database := setupAuthHTTPTest(t)

	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}

	SetupRoutes(router, NewHandlers(database, nil), trustedOrigin)

	login := func(origin, referer, password string) *httptest.ResponseRecorder {
		t.Helper()

		body := `{"username":"testadmin","password":"` + password + `"}`

		req := httptest.NewRequest(
			http.MethodPost,
			"/api/auth/login",
			strings.NewReader(body),
		)

		req.Header.Set("Content-Type", "application/json")

		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if referer != "" {
			req.Header.Set("Referer", referer)
		}

		req.RemoteAddr = "192.0.2.10:12345"

		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)

		return response
	}

	// These requests must be rejected before reaching the limiter.
	for i := 0; i < 20; i++ {
		response := login(
			"https://attacker.example",
			"",
			"CorrectPassword123!",
		)

		if response.Code != http.StatusForbidden {
			t.Fatalf(
				"cross-origin request %d returned %d, want 403",
				i+1,
				response.Code,
			)
		}

		if len(response.Result().Cookies()) != 0 {
			t.Fatal("cross-origin request issued a cookie")
		}
	}

	missingOrigin := login("", "", "CorrectPassword123!")
	if missingOrigin.Code != http.StatusForbidden {
		t.Fatalf(
			"missing Origin returned %d, want 403",
			missingOrigin.Code,
		)
	}

	// A legitimate request must still work after the rejected
	// cross-origin requests.
	success := login(trustedOrigin, "", "CorrectPassword123!")

	if success.Code != http.StatusOK {
		t.Fatalf(
			"valid login returned %d, want 200: %s",
			success.Code,
			success.Body.String(),
		)
	}

	var sessionCookie *http.Cookie

	for _, cookie := range success.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
		}
	}

	if sessionCookie == nil {
		t.Fatal("successful login did not issue session cookie")
	}

	if !sessionCookie.Secure ||
		!sessionCookie.HttpOnly ||
		sessionCookie.SameSite != http.SameSiteStrictMode ||
		sessionCookie.Path != "/" ||
		sessionCookie.Domain != "" {
		t.Fatal("session cookie security attributes are incorrect")
	}

	if _, err := auth.ValidateSession(
		database.DB,
		sessionCookie.Value,
	); err != nil {
		t.Fatalf("login session invalid: %v", err)
	}

	if strings.Contains(success.Body.String(), sessionCookie.Value) ||
		strings.Contains(success.Body.String(), "password_hash") {
		t.Fatal("login response exposed authentication secrets")
	}

	// One successful request consumed one limiter slot.
	// Nine invalid requests should consume the remaining slots.
	for i := 0; i < loginPeerLimit-1; i++ {
		response := login(
			trustedOrigin,
			"",
			"WrongPassword123!",
		)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf(
				"invalid login %d returned %d, want 401",
				i+1,
				response.Code,
			)
		}

		if len(response.Result().Cookies()) != 0 {
			t.Fatal("invalid login issued a cookie")
		}
	}

	// The eleventh same-peer request must be rejected
	// before password verification.
	throttled := login(
		trustedOrigin,
		"",
		"CorrectPassword123!",
	)

	if throttled.Code != http.StatusTooManyRequests {
		t.Fatalf(
			"throttled login returned %d, want 429",
			throttled.Code,
		)
	}

	retry, err := strconv.Atoi(
		throttled.Header().Get("Retry-After"),
	)

	if err != nil || retry < 1 || retry > 60 {
		t.Fatalf("invalid Retry-After value: %d (%v)", retry, err)
	}

	// Only the successful login should have created a session.
	var sessions int64

	if err := database.DB.
		Model(&db.AdminSession{}).
		Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}

	if sessions != 1 {
		t.Fatalf("expected one session, found %d", sessions)
	}
}
