package step

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CertBundle struct {
	CertPEM     []byte
	KeyPEM      []byte
	ChainPEM    []byte
	FullChainPEM []byte
	PFXData     []byte
	Serial      string
	NotAfter    time.Time
}

type StepClient struct {
	CAURL               string
	CARootFingerprint   string
	ProvisionerName     string
	ProvisionerPassword string
}

func NewStepClient(caURL, caRootFingerprint, provisionerName, provisionerPassword string) *StepClient {
	return &StepClient{
		CAURL:               caURL,
		CARootFingerprint:   caRootFingerprint,
		ProvisionerName:     provisionerName,
		ProvisionerPassword: provisionerPassword,
	}
}

func (s *StepClient) IssueCertificate(cn string, sans []string, notAfterDays int) (*CertBundle, error) {
	log.Printf("DEBUG: IssueCertificate called with cn=%s, sans=%v, notAfterDays=%d\n", cn, sans, notAfterDays)
	log.Printf("DEBUG: StepClient.CARootFingerprint='%s'\n", s.CARootFingerprint)
	
	// Create temporary directory for certificate files
	tempDir, err := os.MkdirTemp("", "step-cert-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "cert.key")
	passwordFile := filepath.Join(tempDir, "password.txt")
	rootPath := filepath.Join(tempDir, "root.crt")

	// Write password to file
	if err := os.WriteFile(passwordFile, []byte(s.ProvisionerPassword), 0644); err != nil {
		return nil, fmt.Errorf("failed to write password file: %w", err)
	}

	// Download root certificate
	rootArgs := []string{
		"ca", "root",
		rootPath,
		"--ca-url", s.CAURL,
	}
	if s.CARootFingerprint != "" {
		rootArgs = append(rootArgs, "--fingerprint", s.CARootFingerprint)
	}
	// DEBUG: log the command and fingerprint
	log.Printf("DEBUG [IssueCertificate]: Executing root command: step %v\n", rootArgs)
	log.Printf("DEBUG [IssueCertificate]: CARootFingerprint value: '%s'\n", s.CARootFingerprint)
	rootCmd := exec.Command("step", rootArgs...)
	rootOutput, err := rootCmd.CombinedOutput()
	if err != nil {
		log.Printf("DEBUG [IssueCertificate]: Root command FAILED: %s\n", string(rootOutput))
		return nil, fmt.Errorf("step root command failed: %s, error: %w", string(rootOutput), err)
	}
	log.Printf("DEBUG [IssueCertificate]: Root command succeeded\n")

	// First, generate a token
	// Note: --not-after for token is token validity (default 5m), not certificate validity
	tokenArgs := []string{
		"ca", "token",
		cn,
		"--ca-url", s.CAURL,
		"--root", rootPath,
		"--provisioner", s.ProvisionerName,
		"--provisioner-password-file", passwordFile,
	}

	// Add SANs to token command if provided
	for _, san := range sans {
		tokenArgs = append(tokenArgs, "--san", san)
	}

	// Execute token command
	tokenCmd := exec.Command("step", tokenArgs...)
	// DEBUG: log the command being executed
	log.Printf("DEBUG: Executing token command: step %v\n", tokenArgs)
	tokenOutput, err := tokenCmd.CombinedOutput()
	if err != nil {
		log.Printf("DEBUG: Token command FAILED: %s\n", string(tokenOutput))
		return nil, fmt.Errorf("step token command failed: %s, error: %w", string(tokenOutput), err)
	}
	log.Printf("DEBUG: Token command succeeded, output length: %d\n", len(tokenOutput))

	// Extract JWT token from output (it's the line starting with "ey")
	// The step CLI outputs colored/formatted text before the actual token
	token := ""
	for _, line := range strings.Split(string(tokenOutput), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ey") {
			token = trimmed
			break
		}
	}
	
	if token == "" {
		log.Printf("DEBUG: Could not extract token from output: %s\n", string(tokenOutput))
		return nil, fmt.Errorf("failed to extract JWT token from step ca token output")
	}
	
	log.Printf("DEBUG: Extracted token (first 20 chars): %s...\n", token[:min(20, len(token))])

	// Now use the token to issue certificate
	certArgs := []string{
		"ca", "certificate",
		cn,
		certPath,
		keyPath,
		"--token", token,
		"--ca-url", s.CAURL,
		"--root", rootPath,
		"--not-after", fmt.Sprintf("%dh", notAfterDays*24),
	}

	// Execute certificate command
	cmd := exec.Command("step", certArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("step command failed: %s, error: %w", string(output), err)
	}

	// Read certificate and key files
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Get certificate chain
	chainPEM, err := s.getChain(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain: %w", err)
	}

	// Create full chain
	fullChainPEM := append(certPEM, chainPEM...)

	// Extract serial number and expiry from certificate
	serial, notAfter, err := s.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertBundle{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		ChainPEM:     chainPEM,
		FullChainPEM: fullChainPEM,
		Serial:       serial,
		NotAfter:     notAfter,
	}, nil
}

func (s *StepClient) SignCSR(csrPEM string, notAfterDays int) (*CertBundle, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "step-csr-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	csrPath := filepath.Join(tempDir, "csr.pem")
	certPath := filepath.Join(tempDir, "cert.crt")
	passwordFile := filepath.Join(tempDir, "password.txt")
	rootPath := filepath.Join(tempDir, "root.crt")

	// Write CSR to file
	if err := os.WriteFile(csrPath, []byte(csrPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write CSR file: %w", err)
	}

	// Write password to file
	if err := os.WriteFile(passwordFile, []byte(s.ProvisionerPassword), 0644); err != nil {
		return nil, fmt.Errorf("failed to write password file: %w", err)
	}

	// Download root certificate
	rootArgs := []string{
		"ca", "root",
		rootPath,
		"--ca-url", s.CAURL,
	}
	if s.CARootFingerprint != "" {
		rootArgs = append(rootArgs, "--fingerprint", s.CARootFingerprint)
	}
	rootCmd := exec.Command("step", rootArgs...)
	rootOutput, err := rootCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("step root command failed: %s, error: %w", string(rootOutput), err)
	}

	// First, generate a token (we need to extract CN from CSR)
	// For now, use a generic subject - this could be improved by parsing the CSR
	// Note: --not-after for token is token validity (default 5m), not certificate validity
	tokenArgs := []string{
		"ca", "token",
		"csr-signing", // Generic subject for CSR signing
		"--ca-url", s.CAURL,
		"--root", rootPath,
		"--provisioner", s.ProvisionerName,
		"--provisioner-password-file", passwordFile,
	}

	// Execute token command
	tokenCmd := exec.Command("step", tokenArgs...)
	tokenOutput, err := tokenCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("step token command failed: %s, error: %w", string(tokenOutput), err)
	}

	token := strings.TrimSpace(string(tokenOutput))

	// Now use the token to sign CSR
	args := []string{
		"ca", "sign",
		csrPath,
		certPath,
		"--token", token,
		"--ca-url", s.CAURL,
		"--root", rootPath,
		"--not-after", fmt.Sprintf("%dh", notAfterDays*24),
	}

	// Execute step command
	cmd := exec.Command("step", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("step command failed: %s, error: %w", string(output), err)
	}

	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file: %w", err)
	}

	// Get certificate chain
	chainPEM, err := s.getChain(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain: %w", err)
	}

	// Create full chain
	fullChainPEM := append(certPEM, chainPEM...)

	// Extract serial number and expiry from certificate
	serial, notAfter, err := s.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertBundle{
		CertPEM:      certPEM,
		ChainPEM:     chainPEM,
		FullChainPEM: fullChainPEM,
		Serial:       serial,
		NotAfter:     notAfter,
	}, nil
}

// RevokeCertificate revokes a certificate at the CA. The serial must be in
// decimal form, which is what step-ca expects.
//
// "step ca revoke" does not accept provisioner flags itself, so a one-time
// revocation token is generated first with "step ca token --revoke" (the same
// token flow used for issuing) and then passed to "step ca revoke".
func (s *StepClient) RevokeCertificate(serial string) error {
	if serial == "" {
		return fmt.Errorf("cannot revoke: no serial number on record for this certificate")
	}

	tempDir, err := os.MkdirTemp("", "step-revoke-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	passwordFile := filepath.Join(tempDir, "password.txt")
	rootPath := filepath.Join(tempDir, "root.crt")

	if err := os.WriteFile(passwordFile, []byte(s.ProvisionerPassword), 0600); err != nil {
		return fmt.Errorf("failed to write password file: %w", err)
	}

	// Download root certificate
	rootArgs := []string{"ca", "root", rootPath, "--ca-url", s.CAURL}
	if s.CARootFingerprint != "" {
		rootArgs = append(rootArgs, "--fingerprint", s.CARootFingerprint)
	}
	if output, err := exec.Command("step", rootArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("step root command failed: %s, error: %w", string(output), err)
	}

	// Generate a revocation token
	tokenArgs := []string{
		"ca", "token",
		serial,
		"--revoke",
		"--ca-url", s.CAURL,
		"--root", rootPath,
		"--provisioner", s.ProvisionerName,
		"--provisioner-password-file", passwordFile,
	}
	tokenOutput, err := exec.Command("step", tokenArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("step token command failed: %s, error: %w", string(tokenOutput), err)
	}

	// The step CLI may print formatted text before the token; the JWT is the
	// line starting with "ey".
	token := ""
	for _, line := range strings.Split(string(tokenOutput), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ey") {
			token = trimmed
			break
		}
	}
	if token == "" {
		return fmt.Errorf("failed to extract JWT token from step ca token output")
	}

	// Revoke using the token
	args := []string{
		"ca", "revoke",
		serial,
		"--token", token,
		"--ca-url", s.CAURL,
		"--root", rootPath,
	}
	if output, err := exec.Command("step", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("step revoke failed: %s, error: %w", string(output), err)
	}

	return nil
}

func (s *StepClient) CreatePFX(certPEM, keyPEM, password string) ([]byte, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "step-pfx-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "cert.key")
	pfxPath := filepath.Join(tempDir, "cert.p12")
	passwordPath := filepath.Join(tempDir, "password.txt")

	// Write certificate and key files
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}
	if err := os.WriteFile(passwordPath, []byte(password), 0644); err != nil {
		return nil, fmt.Errorf("failed to write password file: %w", err)
	}

	// Build step command
	args := []string{
		"certificate", "p12",
		pfxPath,
		certPath,
		keyPath,
		"--password-file", passwordPath,
	}

	// Execute step command
	cmd := exec.Command("step", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("step p12 command failed: %s, error: %w", string(output), err)
	}

	// Read PFX file
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PFX file: %w", err)
	}

	return pfxData, nil
}

func (s *StepClient) getChain(certPath string) ([]byte, error) {
	// The step ca certificate command already provides the certificate
	// We need to get the CA chain (intermediate + root)
	// Download the root certificate using step ca root
	
	tempDir, err := os.MkdirTemp("", "step-chain-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	rootPath := filepath.Join(tempDir, "root.crt")

	// Download root certificate
	rootArgs := []string{
		"ca", "root",
		rootPath,
		"--ca-url", s.CAURL,
	}
	if s.CARootFingerprint != "" {
		rootArgs = append(rootArgs, "--fingerprint", s.CARootFingerprint)
	}
	rootCmd := exec.Command("step", rootArgs...)
	rootOutput, err := rootCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("step root command failed: %s, error: %w", string(rootOutput), err)
	}

	// Read the root certificate
	chainPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read root certificate: %w", err)
	}

	return chainPEM, nil
}

// parseCertificate returns the certificate's serial number in decimal form
// (the form step-ca uses when revoking by serial) and its expiry.
func (s *StepClient) parseCertificate(certPEM []byte) (string, time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", time.Time{}, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.SerialNumber.String(), cert.NotAfter, nil
}

func (s *StepClient) CreateDownloadBundle(bundle *CertBundle, format string, pfxPassword string) ([]byte, error) {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Add certificate files
	if err := s.addFileToZip(zipWriter, "cert.pem", bundle.CertPEM); err != nil {
		return nil, err
	}
	if err := s.addFileToZip(zipWriter, "chain.pem", bundle.ChainPEM); err != nil {
		return nil, err
	}
	if err := s.addFileToZip(zipWriter, "fullchain.pem", bundle.FullChainPEM); err != nil {
		return nil, err
	}

	// Add private key if available
	if len(bundle.KeyPEM) > 0 {
		if err := s.addFileToZip(zipWriter, "privkey.pem", bundle.KeyPEM); err != nil {
			return nil, err
		}
	}

	// Add PFX if requested
	if format == "pfx" && len(bundle.KeyPEM) > 0 {
		pfxData, err := s.CreatePFX(string(bundle.CertPEM), string(bundle.KeyPEM), pfxPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to create PFX: %w", err)
		}
		if err := s.addFileToZip(zipWriter, "cert.p12", pfxData); err != nil {
			return nil, err
		}
	}

	// Add README with installation instructions
	readme := s.generateReadme(format, pfxPassword)
	if err := s.addFileToZip(zipWriter, "README.txt", []byte(readme)); err != nil {
		return nil, err
	}

	if err := zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zip writer: %w", err)
	}

	return buf.Bytes(), nil
}

func (s *StepClient) addFileToZip(zipWriter *zip.Writer, filename string, data []byte) error {
	fileWriter, err := zipWriter.Create(filename)
	if err != nil {
		return err
	}
	_, err = fileWriter.Write(data)
	return err
}

func (s *StepClient) generateReadme(format, pfxPassword string) string {
	readme := "# Certificate Installation Instructions\n\n"
	readme += "## Files in this bundle:\n"
	readme += "- cert.pem: Your certificate\n"
	readme += "- chain.pem: Certificate chain (intermediate CAs)\n"
	readme += "- fullchain.pem: Certificate + chain (use this for most applications)\n"
	readme += "- privkey.pem: Private key (keep this secure!)\n"

	if format == "pfx" {
		readme += "- cert.p12: PFX/PKCS#12 bundle (password: " + pfxPassword + ")\n"
	}

	readme += "\n## Installation Instructions\n\n"
	readme += "### Linux/Ubuntu (Nginx, Apache, etc.)\n"
	readme += "```bash\n"
	readme += "# Copy files to appropriate locations\n"
	readme += "sudo cp fullchain.pem /etc/ssl/certs/your-domain.crt\n"
	readme += "sudo cp privkey.pem /etc/ssl/private/your-domain.key\n\n"
	readme += "# For Nginx, update your server block:\n"
	readme += "# ssl_certificate /etc/ssl/certs/your-domain.crt;\n"
	readme += "# ssl_certificate_key /etc/ssl/private/your-domain.key;\n\n"
	readme += "# Reload nginx\n"
	readme += "sudo nginx -s reload\n"
	readme += "```\n\n"

	readme += "### Windows (IIS)\n"
	readme += "1. Import cert.p12 into Certificate Store\n"
	readme += "2. Use IIS Manager to bind the certificate to your site\n\n"

	readme += "### Trust the CA Root\n"
	readme += "To trust this CA on client systems:\n\n"
	readme += "**Linux/Ubuntu:**\n"
	readme += "```bash\n"
	readme += "sudo cp chain.pem /usr/local/share/ca-certificates/my-ca.crt\n"
	readme += "sudo update-ca-certificates\n"
	readme += "```\n\n"

	readme += "**Windows PowerShell:**\n"
	readme += "```powershell\n"
	readme += "Import-Certificate -FilePath chain.pem -CertStoreLocation Cert:\\LocalMachine\\Root\n"
	readme += "```\n\n"

	readme += "## Verification\n"
	readme += "```bash\n"
	readme += "# Verify certificate chain\n"
	readme += "openssl verify -CAfile chain.pem cert.pem\n\n"
	readme += "# Check certificate details\n"
	readme += "openssl x509 -in cert.pem -text -noout\n\n"
	readme += "# Test SSL connection\n"
	readme += "openssl s_client -connect your-domain:443 -showcerts\n"
	readme += "```\n"

	return readme
}
