package api

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// RequireSameOrigin rejects state-changing browser requests unless
// Origin or Referer matches the explicitly configured HTTPS origin.
//
// This middleware must be applied to all state-changing API routes,
// including login and logout.
func RequireSameOrigin(trustedOrigin string) gin.HandlerFunc {
	expected, err := url.Parse(trustedOrigin)
	if err != nil ||
		expected.Scheme != "https" ||
		expected.Host == "" ||
		expected.User != nil ||
		expected.Path != "" ||
		expected.RawQuery != "" ||
		expected.Fragment != "" {
		panic("CSRF protection requires a valid HTTPS origin")
	}

	matches := func(raw string, isOrigin bool) bool {
		parsed, err := url.Parse(raw)
		if err != nil {
			return false
		}

		if parsed.Scheme != expected.Scheme ||
			parsed.Host != expected.Host ||
			parsed.User != nil ||
			parsed.Opaque != "" ||
			parsed.Fragment != "" {
			return false
		}

		// Origin must contain only scheme and authority.
		if isOrigin && (parsed.Path != "" ||
			parsed.RawPath != "" ||
			parsed.RawQuery != "" ||
			parsed.ForceQuery) {
			return false
		}

		return true
	}

	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}

		origin := c.GetHeader("Origin")

		if origin != "" {
			if !matches(origin, true) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Cross-origin request rejected",
				})
				return
			}
		} else {
			referer := c.GetHeader("Referer")

			if referer == "" || !matches(referer, false) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Request origin verification required",
				})
				return
			}
		}

		c.Next()
	}
}
