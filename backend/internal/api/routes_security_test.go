package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestProtectedRoutesRejectAnonymousRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const trustedOrigin = "https://step-ui.mjm.internal"

	// These requests must be rejected by authentication middleware
	// before reaching any handler or database operation.
	router := gin.New()

	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}

	handlers := &Handlers{}
	SetupRoutes(router, handlers, trustedOrigin)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"list certificates", http.MethodGet, "/api/certs"},
		{"archived certificates", http.MethodGet, "/api/certs/archived"},
		{"certificate details", http.MethodGet, "/api/certs/example"},
		{"CA settings", http.MethodGet, "/api/settings/ca"},
		{"issue certificate", http.MethodPost, "/api/certs/issue"},
		{"sign CSR", http.MethodPost, "/api/certs/sign-csr"},
		{"renew certificate", http.MethodPost, "/api/certs/example/renew"},
		{"revoke certificate", http.MethodPost, "/api/certs/example/revoke"},
		{"archive certificate", http.MethodPost, "/api/certs/example/archive"},
		{"restore certificate", http.MethodPost, "/api/certs/example/restore"},
		{"update CA settings", http.MethodPut, "/api/settings/ca"},
		{"current administrator", http.MethodGet, "/api/auth/me"},
		{"logout", http.MethodPost, "/api/auth/logout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)

			if tt.method != http.MethodGet {
				req.Header.Set("Origin", trustedOrigin)
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf(
					"%s %s returned %d, want 401",
					tt.method,
					tt.path,
					recorder.Code,
				)
			}
		})
	}
}

func TestProtectedRoutesRejectCrossOriginMutations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	SetupRoutes(
		router,
		&Handlers{},
		"https://step-ui.mjm.internal",
	)

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/certs/issue",
		nil,
	)
	req.Header.Set("Origin", "https://attacker.example")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf(
			"cross-origin mutation returned %d, want 403",
			recorder.Code,
		)
	}
}
