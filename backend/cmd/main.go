package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"step-ca-webui/internal/api"
	"step-ca-webui/internal/config"
	"step-ca-webui/internal/db"
	"step-ca-webui/internal/step"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Administrator CLI commands run independently of the HTTP server
	// and do not require a connection to Step CA.
	if len(os.Args) > 1 {
		if os.Args[1] != "admin" {
			log.Fatal("Unknown command. Available command: admin")
		}
		if err := runAdminCLI(os.Args[2:]); err != nil {
			log.Fatalf("Administrator command failed: %v", err)
		}
		return
	}

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Load configuration
	cfg := config.Load()

	// DEBUG: Print configuration at startup
	log.Printf("=== CONFIGURATION ===")
	log.Printf("CA_URL: %s", cfg.CAURL)
	log.Printf("CA_ROOT_FINGERPRINT: %s", cfg.CARootFingerprint)
	log.Printf("PROVISIONER_NAME: %s", cfg.ProvisionerName)
	log.Printf("====================")

	// Initialize database
	database, err := db.NewDatabase(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize step client
	stepClient := step.NewStepClient(
		cfg.CAURL,
		cfg.CARootFingerprint,
		cfg.ProvisionerName,
		cfg.ProvisionerPassword,
	)

	log.Printf("StepClient initialized with fingerprint: %s", stepClient.CARootFingerprint)

	// Initialize handlers
	handlers := api.NewHandlers(database, stepClient)

	// Setup Gin router
	r := gin.Default()

	// Do not trust client-supplied forwarding headers.
	// Proxy trust must be explicitly configured before using
	// forwarded client addresses for security decisions.
	// Proxy headers are untrusted unless a specific proxy IP is configured.
	// The trusted address must identify Caddy's direct TCP connection.
	var trustedProxies []string

	if proxy := os.Getenv("STEP_UI_TRUSTED_PROXY"); proxy != "" {
		ip := net.ParseIP(proxy)
		if ip == nil {
			log.Fatalf("Invalid STEP_UI_TRUSTED_PROXY: expected an IP address")
		}

		trustedProxies = []string{ip.String()}
	}

	if err := r.SetTrustedProxies(trustedProxies); err != nil {
		log.Fatalf("Failed to configure trusted proxies: %v", err)
	}

	// Setup routes
	trustedOrigin := os.Getenv("STEP_UI_ORIGIN")
	if trustedOrigin == "" {
		trustedOrigin = "https://step-ui.mjm.internal"
	}
	api.SetupRoutes(r, handlers, trustedOrigin)

	// Start server
	log.Printf("Starting server on port %d", cfg.Port)
	if err := r.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
