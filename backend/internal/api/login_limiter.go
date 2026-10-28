package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	loginPeerLimit   = 10
	loginGlobalLimit = 60
	loginWindow      = time.Minute
	maxTrackedPeers  = 1024
)

type loginBucket struct {
	count   int
	resetAt time.Time
}

type LoginLimiter struct {
	mu     sync.Mutex
	global loginBucket
	peers  map[string]loginBucket
	now    func() time.Time
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		peers: make(map[string]loginBucket),
		now:   time.Now,
	}
}

func (l *LoginLimiter) Allow(peer string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	if !now.Before(l.global.resetAt) {
		l.global = loginBucket{resetAt: now.Add(loginWindow)}
	}

	// Remove expired entries to bound memory use.
	for key, bucket := range l.peers {
		if !now.Before(bucket.resetAt) {
			delete(l.peers, key)
		}
	}

	bucket, exists := l.peers[peer]
	if !exists {
		if len(l.peers) >= maxTrackedPeers {
			return false, loginWindow
		}
		bucket = loginBucket{resetAt: now.Add(loginWindow)}
	}

	if l.global.count >= loginGlobalLimit {
		return false, l.global.resetAt.Sub(now)
	}

	if bucket.count >= loginPeerLimit {
		return false, bucket.resetAt.Sub(now)
	}

	l.global.count++
	bucket.count++
	l.peers[peer] = bucket

	return true, 0
}

// Middleware limits login attempts before expensive password verification.
func (l *LoginLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		allowed, retry := l.Allow(c.ClientIP())
		if !allowed {
			// Round up so Retry-After never understates the wait.
			seconds := int((retry + time.Second - 1) / time.Second)
			if seconds < 1 {
				seconds = 1
			}

			c.Header("Retry-After", strconv.Itoa(seconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many login attempts. Please try again later.",
			})
			return
		}

		c.Next()
	}
}
