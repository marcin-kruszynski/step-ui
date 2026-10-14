package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"step-ca-webui/internal/db"
	"step-ca-webui/internal/step"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handlers struct {
	db         *db.Database
	stepClient *step.StepClient
}

func NewHandlers(database *db.Database, stepClient *step.StepClient) *Handlers {
	return &Handlers{
		db:         database,
		stepClient: stepClient,
	}
}

type IssueRequest struct {
	CN           string   `json:"cn" binding:"required"`
	SANs         []string `json:"sans"`
	NotAfterDays int      `json:"not_after_days" binding:"required"`
	Format       string   `json:"format"` // pem, pfx
	PFXPassword  string   `json:"pfx_password,omitempty"`
}

type SignCSRRequest struct {
	CSRPEM       string `json:"csr_pem" binding:"required"`
	NotAfterDays int    `json:"not_after_days" binding:"required"`
}

type CertResponse struct {
	ID          string    `json:"id"`
	CN          string    `json:"cn"`
	SANs        []string  `json:"sans"`
	NotAfter    time.Time `json:"not_after"`
	Status      string    `json:"status"`
	KeyStrategy string    `json:"key_strategy"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type DownloadResponse struct {
	Data     []byte `json:"data"`
	Filename string `json:"filename"`
	MimeType string `json:"mime_type"`
}

// IssueCertificate issues a new certificate
func (h *Handlers) IssueCertificate(c *gin.Context) {
	var req IssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("DEBUG [Handler]: IssueCertificate handler called with CN=%s\n", req.CN)
	
	// Generate certificate using step CLI
	bundle, err := h.stepClient.IssueCertificate(req.CN, req.SANs, req.NotAfterDays)
	if err != nil {
		log.Printf("DEBUG [Handler]: IssueCertificate returned error: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to issue certificate: %v", err)})
		return
	}

	// Generate unique ID for the certificate
	certID := uuid.New().String()

	// Store certificate metadata in database
	sansJSON, _ := json.Marshal(req.SANs)
	cert := &db.Certificate{
		ID:          certID,
		CN:          req.CN,
		Serial:      bundle.Serial,
		SANs:        string(sansJSON),
		NotAfter:    bundle.NotAfter,
		Status:      "active",
		KeyStrategy: "server",
		StorageRef:  "ephemeral",
		OwnerUser:   "system", // No auth for MVP
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.db.CreateCertificate(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store certificate metadata"})
		return
	}

	// Log audit event
	auditEvent := &db.AuditEvent{
		CertID:    certID,
		Who:       "system",
		Action:    "issued",
		Details:   fmt.Sprintf("CN: %s, SANs: %v", req.CN, req.SANs),
		Timestamp: time.Now(),
	}
	h.db.LogAuditEvent(auditEvent)

	// Create download bundle
	downloadData, err := h.stepClient.CreateDownloadBundle(bundle, req.Format, req.PFXPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create download bundle"})
		return
	}

	// Return certificate info and download data
	response := CertResponse{
		ID:          certID,
		CN:          req.CN,
		SANs:        req.SANs,
		NotAfter:    bundle.NotAfter,
		Status:      "active",
		KeyStrategy: "server",
		CreatedAt:   cert.CreatedAt,
		UpdatedAt:   cert.UpdatedAt,
	}

	c.JSON(http.StatusOK, gin.H{
		"certificate": response,
		"download": gin.H{
			"data":     downloadData,
			"filename": fmt.Sprintf("%s-cert-bundle.zip", req.CN),
			"mime_type": "application/zip",
		},
	})
}

// SignCSR signs a certificate signing request
func (h *Handlers) SignCSR(c *gin.Context) {
	var req SignCSRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Sign CSR using step CLI
	bundle, err := h.stepClient.SignCSR(req.CSRPEM, req.NotAfterDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to sign CSR: %v", err)})
		return
	}

	// Generate unique ID for the certificate
	certID := uuid.New().String()

	// Parse CSR to extract CN and SANs (simplified - in real implementation, parse CSR)
	cn := "unknown" // Would need to parse CSR properly
	sans := []string{}

	// Store certificate metadata in database
	sansJSON, _ := json.Marshal(sans)
	cert := &db.Certificate{
		ID:          certID,
		CN:          cn,
		Serial:      bundle.Serial,
		SANs:        string(sansJSON),
		NotAfter:    bundle.NotAfter,
		Status:      "active",
		KeyStrategy: "csr",
		StorageRef:  "ephemeral",
		OwnerUser:   "system",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.db.CreateCertificate(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store certificate metadata"})
		return
	}

	// Log audit event
	auditEvent := &db.AuditEvent{
		CertID:    certID,
		Who:       "system",
		Action:    "signed_csr",
		Details:   fmt.Sprintf("CN: %s", cn),
		Timestamp: time.Now(),
	}
	h.db.LogAuditEvent(auditEvent)

	// Return certificate info
	response := CertResponse{
		ID:          certID,
		CN:          cn,
		SANs:        sans,
		NotAfter:    bundle.NotAfter,
		Status:      "active",
		KeyStrategy: "csr",
		CreatedAt:   cert.CreatedAt,
		UpdatedAt:   cert.UpdatedAt,
	}

	c.JSON(http.StatusOK, gin.H{
		"certificate": response,
		"cert_pem":    string(bundle.CertPEM),
		"chain_pem":   string(bundle.ChainPEM),
	})
}

// ListCertificates returns a list of certificates
func (h *Handlers) ListCertificates(c *gin.Context) {
	// Parse query parameters
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	status := c.Query("status")

	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 50
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		offset = 0
	}

	// Get certificates from database
	certs, err := h.db.ListCertificates(limit, offset, status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list certificates"})
		return
	}

	// Convert to response format
	var responses []CertResponse
	for _, cert := range certs {
		var sans []string
		json.Unmarshal([]byte(cert.SANs), &sans)
		
		responses = append(responses, CertResponse{
			ID:          cert.ID,
			CN:          cert.CN,
			SANs:        sans,
			NotAfter:    cert.NotAfter,
			Status:      cert.Status,
			KeyStrategy: cert.KeyStrategy,
			CreatedAt:   cert.CreatedAt,
			UpdatedAt:   cert.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"certificates": responses})
}

// GetCertificate returns a specific certificate
func (h *Handlers) GetCertificate(c *gin.Context) {
	certID := c.Param("id")
	
	cert, err := h.db.GetCertificate(certID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	var sans []string
	json.Unmarshal([]byte(cert.SANs), &sans)
	
	response := CertResponse{
		ID:          cert.ID,
		CN:          cert.CN,
		SANs:        sans,
		NotAfter:    cert.NotAfter,
		Status:      cert.Status,
		KeyStrategy: cert.KeyStrategy,
		CreatedAt:   cert.CreatedAt,
		UpdatedAt:   cert.UpdatedAt,
	}

	c.JSON(http.StatusOK, gin.H{"certificate": response})
}

// RenewCertificate renews a certificate
func (h *Handlers) RenewCertificate(c *gin.Context) {
	certID := c.Param("id")
	
	// Get existing certificate
	cert, err := h.db.GetCertificate(certID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	// Parse SANs
	var sans []string
	json.Unmarshal([]byte(cert.SANs), &sans)

	// Issue new certificate with same CN and SANs
	bundle, err := h.stepClient.IssueCertificate(cert.CN, sans, 90) // Default 90 days
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to renew certificate: %v", err)})
		return
	}

	// Update certificate in database
	cert.Serial = bundle.Serial
	cert.NotAfter = bundle.NotAfter
	cert.UpdatedAt = time.Now()
	if err := h.db.UpdateCertificate(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update certificate"})
		return
	}

	// Log audit event
	auditEvent := &db.AuditEvent{
		CertID:    certID,
		Who:       "system",
		Action:    "renewed",
		Details:   fmt.Sprintf("CN: %s", cert.CN),
		Timestamp: time.Now(),
	}
	h.db.LogAuditEvent(auditEvent)

	// Return new certificate info
	var responseSans []string
	json.Unmarshal([]byte(cert.SANs), &responseSans)
	
	response := CertResponse{
		ID:          cert.ID,
		CN:          cert.CN,
		SANs:        responseSans,
		NotAfter:    cert.NotAfter,
		Status:      cert.Status,
		KeyStrategy: cert.KeyStrategy,
		CreatedAt:   cert.CreatedAt,
		UpdatedAt:   cert.UpdatedAt,
	}

	c.JSON(http.StatusOK, gin.H{"certificate": response})
}

// RevokeCertificate revokes a certificate
func (h *Handlers) RevokeCertificate(c *gin.Context) {
	certID := c.Param("id")
	
	// Get certificate
	cert, err := h.db.GetCertificate(certID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	// Certificates issued before serial numbers were recorded can't be revoked
	// by serial; say so rather than silently marking them revoked.
	if cert.Serial == "" {
		c.JSON(http.StatusConflict, gin.H{"error": "No serial number on record for this certificate (issued before serial tracking); revoke it with the step CLI instead"})
		return
	}

	// Revoke at the CA first, then record it locally
	if err := h.stepClient.RevokeCertificate(cert.Serial); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to revoke certificate: %v", err)})
		return
	}

	cert.Status = "revoked"
	cert.UpdatedAt = time.Now()
	if err := h.db.UpdateCertificate(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke certificate"})
		return
	}

	// Log audit event
	auditEvent := &db.AuditEvent{
		CertID:    certID,
		Who:       "system",
		Action:    "revoked",
		Details:   fmt.Sprintf("CN: %s", cert.CN),
		Timestamp: time.Now(),
	}
	h.db.LogAuditEvent(auditEvent)

	c.JSON(http.StatusOK, gin.H{"message": "Certificate revoked successfully"})
}

// GetCASettings returns CA configuration
func (h *Handlers) GetCASettings(c *gin.Context) {
	// This would typically read from configuration
	settings := gin.H{
		"ca_url":           h.stepClient.CAURL,
		"root_fingerprint": "TODO: Calculate from CA root",
		"acme_directories": []string{
			h.stepClient.CAURL + "/acme/acme/directory",
		},
	}

	c.JSON(http.StatusOK, settings)
}

// Health check endpoint  
func (h *Handlers) Health(c *gin.Context) {
	// NEW VERSION WITH ROOT FINGERPRINT SUPPORT
	fmt.Println("=== HEALTH ENDPOINT HIT ===")
	response := map[string]interface{}{
		"status":    "healthy-NEW",
		"timestamp": time.Now().Format(time.RFC3339),
		"fingerprint_length": len(h.stepClient.CARootFingerprint),
	}
	c.JSON(http.StatusOK, response)
}
