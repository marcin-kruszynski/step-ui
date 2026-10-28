package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequireSameOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const trusted = "https://step-ui.mjm.internal"

	router := gin.New()
	router.Use(RequireSameOrigin(trusted))

	router.Any("/test", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	tests := []struct {
		name    string
		method  string
		origin  string
		referer string
		host    string
		want    int
	}{
		{
			name:   "same-origin POST",
			method: http.MethodPost,
			origin: trusted,
			want:   http.StatusNoContent,
		},
		{
			name:   "cross-origin POST",
			method: http.MethodPost,
			origin: "https://attacker.example",
			want:   http.StatusForbidden,
		},
		{
			name:   "deceptive hostname",
			method: http.MethodPost,
			origin: trusted + ".attacker.example",
			want:   http.StatusForbidden,
		},
		{
			name:   "missing origin and referer",
			method: http.MethodPost,
			want:   http.StatusForbidden,
		},
		{
			name:   "null origin",
			method: http.MethodPost,
			origin: "null",
			want:   http.StatusForbidden,
		},
		{
			name:    "valid referer fallback",
			method:  http.MethodPost,
			referer: trusted + "/certificates",
			want:    http.StatusNoContent,
		},
		{
			name:    "malicious referer",
			method:  http.MethodPost,
			referer: trusted + ".attacker.example/path",
			want:    http.StatusForbidden,
		},
		{
			name:   "spoofed Host cannot authorize request",
			method: http.MethodPost,
			origin: "https://attacker.example",
			host:   "attacker.example",
			want:   http.StatusForbidden,
		},
		{
			name:   "origin with path rejected",
			method: http.MethodPost,
			origin: trusted + "/certificates",
			want:   http.StatusForbidden,
		},
		{
			name:   "origin with query rejected",
			method: http.MethodPost,
			origin: trusted + "?test=1",
			want:   http.StatusForbidden,
		},
		{
			name:   "origin with fragment rejected",
			method: http.MethodPost,
			origin: trusted + "#fragment",
			want:   http.StatusForbidden,
		},
		{
			name:   "origin with credentials rejected",
			method: http.MethodPost,
			origin: "https://user@step-ui.mjm.internal",
			want:   http.StatusForbidden,
		},
		{
			name:   "origin with unexpected port rejected",
			method: http.MethodPost,
			origin: trusted + ":8443",
			want:   http.StatusForbidden,
		},
		{
			name:    "invalid origin overrides valid referer",
			method:  http.MethodPost,
			origin:  "https://attacker.example",
			referer: trusted + "/certificates",
			want:    http.StatusForbidden,
		},
		{
			name:    "referer with query accepted",
			method:  http.MethodPost,
			referer: trusted + "/certificates?page=1",
			want:    http.StatusNoContent,
		},
		{
			name:   "read-only GET",
			method: http.MethodGet,
			want:   http.StatusNoContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/test", nil)

			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			if tc.host != "" {
				req.Host = tc.host
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf(
					"expected HTTP %d, got %d: %s",
					tc.want,
					rec.Code,
					rec.Body.String(),
				)
			}
		})
	}
}
