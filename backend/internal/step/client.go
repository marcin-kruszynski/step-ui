package step

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CertBundle struct {
	CertPEM      []byte
	KeyPEM       []byte
	ChainPEM     []byte
	FullChainPEM []byte
	PFXData      []byte
	Serial       string
	NotAfter     time.Time
	CN           string
	SANs         []string
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

func (s *StepClient) IssueCertificate(cn string, sans []string, notAfterDays int, keyType string) (*CertBundle, error) {
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
	if err := os.WriteFile(passwordFile, []byte(s.ProvisionerPassword), 0600); err != nil {
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
	tokenOutput, err := tokenCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("step token command failed: %w", err)
	}

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
		return nil, fmt.Errorf("failed to extract JWT token from step ca token output")
	}

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

	// Explicit key algorithm. Default to RSA-2048 for broad appliance compatibility.
	switch keyType {
	case "ec-p256":
		certArgs = append(certArgs, "--kty", "EC", "--curve", "P-256")
	case "", "rsa-2048":
		keyType = "rsa-2048"
		certArgs = append(certArgs, "--kty", "RSA", "--size", "2048")
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
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

	// step returns the leaf followed by its intermediate chain.
	// Split them so the download bundle has conventional semantics:
	// cert.pem = leaf, chain.pem = intermediates, fullchain.pem = both.
	leafPEM, chainPEM, err := splitCertificateChain(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to split certificate chain: %w", err)
	}

	fullChainPEM := append(append([]byte{}, leafPEM...), chainPEM...)

	// Extract serial number and expiry from certificate
	serial, notAfter, err := s.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertBundle{
		CertPEM:      leafPEM,
		KeyPEM:       keyPEM,
		ChainPEM:     chainPEM,
		FullChainPEM: fullChainPEM,
		Serial:       serial,
		NotAfter:     notAfter,
	}, nil
}

func (s *StepClient) SignCSR(csrPEM string, notAfterDays int) (*CertBundle, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode PEM certificate request")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate request signature: %w", err)
	}

	cn := strings.TrimSpace(csr.Subject.CommonName)
	if cn == "" {
		return nil, fmt.Errorf("certificate request CommonName is required")
	}

	sans := make([]string, 0, len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs))
	sans = append(sans, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, csr.EmailAddresses...)
	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}

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
	if err := os.WriteFile(passwordFile, []byte(s.ProvisionerPassword), 0600); err != nil {
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

	// Generate an issuance token whose subject matches the CSR CommonName.
	// Note: --not-after for token is token validity (default 5m), not certificate validity.
	tokenArgs := []string{
		"ca", "token",
		cn,
		"--ca-url", s.CAURL,
		"--root", rootPath,
		"--provisioner", s.ProvisionerName,
		"--provisioner-password-file", passwordFile,
	}
	for _, san := range sans {
		tokenArgs = append(tokenArgs, "--san", san)
	}

	// Execute token command
	tokenCmd := exec.Command("step", tokenArgs...)
	tokenOutput, err := tokenCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("step token command failed: %w", err)
	}

	// Extract the JWT from step output. The CLI may emit informational or
	// formatted text in addition to the token.
	token := ""
	for _, line := range strings.Split(string(tokenOutput), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ey") {
			token = trimmed
			break
		}
	}

	if token == "" {
		return nil, fmt.Errorf("failed to extract JWT token from step ca token output")
	}

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

	// step returns the leaf followed by its intermediate chain.
	// Split them so the download bundle has conventional semantics:
	// cert.pem = leaf, chain.pem = intermediates, fullchain.pem = both.
	leafPEM, chainPEM, err := splitCertificateChain(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to split certificate chain: %w", err)
	}

	fullChainPEM := append(append([]byte{}, leafPEM...), chainPEM...)

	// Extract serial number and expiry from certificate
	serial, notAfter, err := s.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertBundle{
		CertPEM:      leafPEM,
		ChainPEM:     chainPEM,
		FullChainPEM: fullChainPEM,
		Serial:       serial,
		NotAfter:     notAfter,
		CN:           cn,
		SANs:         sans,
	}, nil
}

// RevokeCertificate revokes a certificate at the CA.
// Revision 2026-10-24: Correct CLI argument ordering, convert OpenSSL hex
// serials to decimal, and explicitly establish CA trust.
func (s *StepClient) RevokeCertificate(serial string) error {
	// OpenSSL reports serials in hexadecimal; step-ca expects decimal.
	serialInt := new(big.Int)
	if _, ok := serialInt.SetString(strings.TrimSpace(serial), 16); !ok {
		return fmt.Errorf("invalid hexadecimal certificate serial")
	}
	decimalSerial := serialInt.String()

	tempDir, err := os.MkdirTemp("", "step-revoke-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	passwordFile := filepath.Join(tempDir, "password.txt")
	rootPath := filepath.Join(tempDir, "root.crt")
	tokenPath := filepath.Join(tempDir, "token.jwt")

	if err := os.WriteFile(passwordFile, []byte(s.ProvisionerPassword), 0600); err != nil {
		return fmt.Errorf("failed to write provisioner password file: %w", err)
	}

	rootArgs := []string{"ca", "root", rootPath, "--ca-url", s.CAURL}
	if s.CARootFingerprint != "" {
		rootArgs = append(rootArgs, "--fingerprint", s.CARootFingerprint)
	}
	rootOutput, err := exec.Command("step", rootArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to retrieve CA root: %s: %w", strings.TrimSpace(string(rootOutput)), err)
	}

	tokenArgs := []string{
		"ca", "token", decimalSerial,
		"--revoke",
		"--ca-url", s.CAURL,
		"--root", rootPath,
		"--provisioner", s.ProvisionerName,
		"--provisioner-password-file", passwordFile,
		"--output-file", tokenPath,
	}

	tokenOutput, err := exec.Command("step", tokenArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("revocation token generation failed: %s: %w", strings.TrimSpace(string(tokenOutput)), err)
	}

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("failed to read revocation token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if !strings.HasPrefix(token, "ey") {
		return fmt.Errorf("revocation token output is invalid")
	}

	revokeArgs := []string{
		"ca", "revoke", decimalSerial,
		"--token", token,
		"--ca-url", s.CAURL,
		"--root", rootPath,
	}

	revokeOutput, err := exec.Command("step", revokeArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("certificate revocation failed: %s: %w", strings.TrimSpace(string(revokeOutput)), err)
	}

	return nil
}

func (s *StepClient) CreatePFX(certPEM, keyPEM, chainPEM, password string) ([]byte, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "step-pfx-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "cert.key")
	chainPath := filepath.Join(tempDir, "chain.crt")
	pfxPath := filepath.Join(tempDir, "cert.p12")
	passwordPath := filepath.Join(tempDir, "password.txt")

	// Write certificate and key files
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}
	if err := os.WriteFile(chainPath, []byte(chainPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write chain file: %w", err)
	}
	if err := os.WriteFile(passwordPath, []byte(password), 0600); err != nil {
		return nil, fmt.Errorf("failed to write password file: %w", err)
	}

	// Build step command
	args := []string{
		"certificate", "p12",
		pfxPath,
		certPath,
		keyPath,
		"--ca", chainPath,
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

func splitCertificateChain(certPEM []byte) ([]byte, []byte, error) {
	var certificates [][]byte
	rest := certPEM

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		if block.Type != "CERTIFICATE" {
			continue
		}

		certificates = append(certificates, pem.EncodeToMemory(block))
	}

	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("certificate bundle contains no CERTIFICATE blocks")
	}

	leafPEM := certificates[0]

	var chainPEM []byte
	for _, cert := range certificates[1:] {
		chainPEM = append(chainPEM, cert...)
	}

	if len(chainPEM) == 0 {
		return nil, nil, fmt.Errorf("certificate bundle contains no intermediate certificates")
	}

	return leafPEM, chainPEM, nil
}

func (s *StepClient) parseCertificate(certPEM []byte) (string, time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", time.Time{}, fmt.Errorf("failed to decode PEM block")
	}

	// Use openssl to get certificate details
	cmd := exec.Command("openssl", "x509", "-noout", "-serial", "-enddate")
	cmd.Stdin = bytes.NewReader(certPEM)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("openssl command failed: %s, error: %w", string(output), err)
	}

	lines := strings.Split(string(output), "\n")
	var serial string
	var notAfter time.Time

	for _, line := range lines {
		if strings.HasPrefix(line, "serial=") {
			serial = strings.TrimPrefix(line, "serial=")
		} else if strings.HasPrefix(line, "notAfter=") {
			dateStr := strings.TrimPrefix(line, "notAfter=")
			notAfter, err = time.Parse("Jan 2 15:04:05 2006 MST", dateStr)
			if err != nil {
				return "", time.Time{}, fmt.Errorf("failed to parse date: %w", err)
			}
		}
	}

	return serial, notAfter, nil
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
		pfxData, err := s.CreatePFX(string(bundle.CertPEM), string(bundle.KeyPEM), string(bundle.ChainPEM), pfxPassword)
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
