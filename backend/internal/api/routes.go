package api

import (
	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine, handlers *Handlers, trustedOrigin string) {
	// Health check
	r.GET("/health", handlers.Health)

	// Every API request passes through the same-origin CSRF boundary.
	api := r.Group("/api")
	api.Use(RequireSameOrigin(trustedOrigin))

	// Login is public, but protected against excessive attempts.
	limiter := NewLoginLimiter()
	api.POST("/auth/login", limiter.Middleware(), handlers.LoginAdmin)

	// All remaining API routes require an authenticated administrator.
	protected := api.Group("")
	protected.Use(handlers.RequireAdmin())
	{
		protected.GET("/auth/me", handlers.GetCurrentAdmin)
		protected.POST("/auth/logout", handlers.LogoutAdmin)

		// Certificate operations
		protected.POST("/certs/issue", handlers.IssueCertificate)
		protected.POST("/certs/sign-csr", handlers.SignCSR)
		protected.GET("/certs", handlers.ListCertificates)

		// 2026-10-24: Manual certificate archive and restore.
		protected.GET("/certs/archived", handlers.ListArchivedCertificates)
		protected.GET("/certs/:id", handlers.GetCertificate)
		protected.POST("/certs/:id/renew", handlers.RenewCertificate)
		protected.POST("/certs/:id/revoke", handlers.RevokeCertificate)
		protected.POST("/certs/:id/archive", handlers.ArchiveCertificate)
		protected.POST("/certs/:id/restore", handlers.RestoreCertificate)

		// Settings
		protected.GET("/settings/ca", handlers.GetCASettings)
		protected.PUT("/settings/ca", handlers.UpdateCASettings)
	}
}
