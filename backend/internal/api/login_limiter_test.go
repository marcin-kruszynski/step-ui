package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newTestLoginLimiter() (*LoginLimiter, *time.Time) {
	clock := new(time.Time)
	*clock = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	limiter := NewLoginLimiter()
	limiter.now = func() time.Time { return *clock }

	return limiter, clock
}

func TestLoginLimiterPeerLimitAndRecovery(t *testing.T) {
	limiter, clock := newTestLoginLimiter()

	for i := 0; i < loginPeerLimit; i++ {
		allowed, _ := limiter.Allow("192.0.2.10")
		if !allowed {
			t.Fatalf("request %d unexpectedly rejected", i+1)
		}
	}

	allowed, retry := limiter.Allow("192.0.2.10")
	if allowed {
		t.Fatal("request beyond peer limit was allowed")
	}
	if retry != loginWindow {
		t.Fatalf("retry = %v, want %v", retry, loginWindow)
	}

	*clock = clock.Add(loginWindow)

	allowed, _ = limiter.Allow("192.0.2.10")
	if !allowed {
		t.Fatal("request rejected after window expiration")
	}
}

func TestLoginLimiterGlobalLimit(t *testing.T) {
	limiter, _ := newTestLoginLimiter()

	for i := 0; i < loginGlobalLimit; i++ {
		peer := fmt.Sprintf("192.0.2.%d", i+1)
		allowed, _ := limiter.Allow(peer)
		if !allowed {
			t.Fatalf("global request %d unexpectedly rejected", i+1)
		}
	}

	allowed, _ := limiter.Allow("198.51.100.1")
	if allowed {
		t.Fatal("request beyond global limit was allowed")
	}
}

func TestLoginLimiterConcurrentRequests(t *testing.T) {
	limiter, _ := newTestLoginLimiter()

	var allowed atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			ok, _ := limiter.Allow("192.0.2.10")
			if ok {
				allowed.Add(1)
			}
		}()
	}

	wg.Wait()

	if got := allowed.Load(); got != loginPeerLimit {
		t.Fatalf("allowed %d requests, want %d", got, loginPeerLimit)
	}
}

func TestLoginLimiterBoundedPeerTracking(t *testing.T) {
	limiter, _ := newTestLoginLimiter()

	for i := 0; i < maxTrackedPeers+100; i++ {
		limiter.Allow(fmt.Sprintf("peer-%d", i))
	}

	if got := len(limiter.peers); got > maxTrackedPeers {
		t.Fatalf("tracked %d peers, maximum %d", got, maxTrackedPeers)
	}
}

func TestLoginLimiterIgnoresSpoofedForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}

	limiter := NewLoginLimiter()

	router.POST("/login", limiter.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	for i := 0; i < loginPeerLimit+1; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "192.0.2.10:12345"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		want := http.StatusNoContent
		if i == loginPeerLimit {
			want = http.StatusTooManyRequests
		}

		if recorder.Code != want {
			t.Fatalf(
				"request %d returned %d, want %d",
				i+1,
				recorder.Code,
				want,
			)
		}

		if want == http.StatusTooManyRequests {
			value := recorder.Header().Get("Retry-After")
			seconds, err := strconv.Atoi(value)
			if err != nil || seconds < 1 {
				t.Fatalf("invalid Retry-After header: %q", value)
			}
		}
	}
}
