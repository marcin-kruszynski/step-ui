package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

const sessionCookieName = "__Host-step_ui_session"

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginAdmin authenticates an administrator and issues a secure,
// host-only session cookie.
func (h *Handlers) LoginAdmin(c *gin.Context) {
	var request loginRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid login request",
		})
		return
	}

	request.Username = strings.TrimSpace(request.Username)

	if request.Username == "" || request.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid login request",
		})
		return
	}

	token, err := auth.Login(h.db.DB, request.Username, request.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid username or password",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Authentication temporarily unavailable",
		})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(auth.SessionDuration.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
	})
}

// GetCurrentAdmin returns the authenticated administrator's
// public identity. RequireAdmin must run before this handler.
func (h *Handlers) GetCurrentAdmin(c *gin.Context) {
	admin, ok := CurrentAdmin(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"admin": gin.H{
			"id":       admin.ID,
			"username": admin.Username,
		},
	})
}

// LogoutAdmin revokes the authenticated session and clears its cookie.
// RequireAdmin must run before this handler.
func (h *Handlers) LogoutAdmin(c *gin.Context) {
	admin, ok := CurrentAdmin(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
		})
		return
	}

	token, err := c.Cookie(sessionCookieName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
		})
		return
	}

	err = h.db.DB.Transaction(func(tx *gorm.DB) error {
		if err := auth.RevokeSession(tx, token); err != nil {
			return err
		}

		return tx.Create(&db.AuditEvent{
			Who:       admin.Username,
			Action:    "admin.logout",
			Details:   "Administrator logged out",
			Timestamp: time.Now().UTC(),
		}).Error
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Logout temporarily unavailable",
		})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	c.JSON(http.StatusOK, gin.H{
		"authenticated": false,
	})
}
