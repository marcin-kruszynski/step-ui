package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTrustedProxyClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		forwarded  string
		wantIP     string
	}{
		{
			name:       "trusted Caddy proxy",
			trusted:    []string{"172.30.50.2"},
			remoteAddr: "172.30.50.2:54321",
			forwarded:  "192.0.2.25",
			wantIP:     "192.0.2.25",
		},
		{
			name:       "untrusted container cannot spoof",
			trusted:    []string{"172.30.50.2"},
			remoteAddr: "172.30.50.3:54321",
			forwarded:  "192.0.2.25",
			wantIP:     "172.30.50.3",
		},
		{
			name:       "proxy trust disabled",
			trusted:    nil,
			remoteAddr: "172.30.50.2:54321",
			forwarded:  "192.0.2.25",
			wantIP:     "172.30.50.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()

			if err := r.SetTrustedProxies(tt.trusted); err != nil {
				t.Fatal(err)
			}

			r.GET("/ip", func(c *gin.Context) {
				c.String(http.StatusOK, c.ClientIP())
			})

			req := httptest.NewRequest(http.MethodGet, "/ip", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("X-Forwarded-For", tt.forwarded)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK || w.Body.String() != tt.wantIP {
				t.Fatalf(
					"got status=%d ip=%q; want ip=%q",
					w.Code,
					w.Body.String(),
					tt.wantIP,
				)
			}
		})
	}
}
