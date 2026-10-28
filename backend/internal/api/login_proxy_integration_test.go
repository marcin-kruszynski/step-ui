package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLoginLimiterBehindTrustedCaddy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()

	if err := router.SetTrustedProxies(
		[]string{"172.30.50.2"},
	); err != nil {
		t.Fatal(err)
	}

	limiter := NewLoginLimiter()

	router.POST("/login", limiter.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	request := func(clientIP string, remoteAddr string) int {
		t.Helper()

		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", clientIP)

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		return recorder.Code
	}

	const caddy = "172.30.50.2:54321"

	// Client A exhausts its individual allowance.
	for i := 0; i < loginPeerLimit; i++ {
		if status := request("192.0.2.10", caddy); status != http.StatusOK {
			t.Fatalf("client A attempt %d: got %d", i+1, status)
		}
	}

	if status := request("192.0.2.10", caddy); status != http.StatusTooManyRequests {
		t.Fatalf("client A should be throttled; got %d", status)
	}

	// Client B retains an independent allowance.
	for i := 0; i < loginPeerLimit; i++ {
		if status := request("192.0.2.20", caddy); status != http.StatusOK {
			t.Fatalf("client B attempt %d: got %d", i+1, status)
		}
	}

	if status := request("192.0.2.20", caddy); status != http.StatusTooManyRequests {
		t.Fatalf("client B should be throttled; got %d", status)
	}

	// Fill the remaining global allowance with distinct clients.
	for i := 0; i < loginGlobalLimit-2*loginPeerLimit; i++ {
		clientIP := "198.51.100." + strconv.Itoa(i+1)
		if status := request(clientIP, caddy); status != http.StatusOK {
			t.Fatalf("global allowance attempt %d: got %d", i+1, status)
		}
	}

	// Even a previously unseen client must now be rejected.
	if status := request("203.0.113.99", caddy); status != http.StatusTooManyRequests {
		t.Fatalf("global limit should throttle new client; got %d", status)
	}

	// An untrusted connection cannot evade its peer limit by
	// changing X-Forwarded-For between requests.
	untrustedRouter := gin.New()

	if err := untrustedRouter.SetTrustedProxies(
		[]string{"172.30.50.2"},
	); err != nil {
		t.Fatal(err)
	}

	untrustedLimiter := NewLoginLimiter()

	untrustedRouter.POST(
		"/login",
		untrustedLimiter.Middleware(),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	for i := 0; i <= loginPeerLimit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "172.30.50.3:54321"
		req.Header.Set(
			"X-Forwarded-For",
			"203.0.113."+strconv.Itoa(i+1),
		)

		recorder := httptest.NewRecorder()
		untrustedRouter.ServeHTTP(recorder, req)

		want := http.StatusOK
		if i == loginPeerLimit {
			want = http.StatusTooManyRequests
		}

		if recorder.Code != want {
			t.Fatalf(
				"untrusted request %d: got %d, want %d",
				i+1,
				recorder.Code,
				want,
			)
		}
	}
}
