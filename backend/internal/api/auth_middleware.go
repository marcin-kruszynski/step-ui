package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

const authenticatedAdminKey = "authenticatedAdmin"

// RequireAdmin validates the session cookie before allowing access
// to protected API endpoints.
func (h *Handlers) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Request.Cookie(sessionCookieName)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			return
		}

		admin, err := auth.ValidateSession(h.db.DB, cookie.Value)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired session",
			})
			return
		}

		c.Set(authenticatedAdminKey, admin)
		c.Next()
	}
}

// CurrentAdmin retrieves the administrator authenticated
// by RequireAdmin middleware.
func CurrentAdmin(c *gin.Context) (*db.AdminUser, bool) {
	value, exists := c.Get(authenticatedAdminKey)
	if !exists {
		return nil, false
	}

	admin, ok := value.(*db.AdminUser)
	return admin, ok && admin != nil
}
