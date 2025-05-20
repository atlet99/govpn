// Package auth provides authentication and security functionality for GoVPN
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	// ErrInvalidCertificate is returned when a certificate is invalid
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrInvalidKey is returned when a key is invalid
	ErrInvalidKey = errors.New("invalid key")

	// ErrCertificateNotFound is returned when a certificate file is not found
	ErrCertificateNotFound = errors.New("certificate file not found")

	// ErrKeyNotFound is returned when a key file is not found
	ErrKeyNotFound = errors.New("key file not found")
)

// CertificateManager handles certificates and keys for OpenVPN compatibility
type CertificateManager struct {
	CAPath           string // Path to CA certificate
	CertPath         string // Path to server certificate
	KeyPath          string // Path to server key
	CRLPath          string // Path to Certificate Revocation List
	DhPath           string // Path to Diffie-Hellman parameters
	TLSAuthPath      string // Path to TLS auth key
	certPool         *x509.CertPool
	serverCert       *tls.Certificate
	crl              *x509.RevocationList
	dhParams         []byte
	tlsAuthKey       []byte
	certificateCache map[string]*x509.Certificate // Cache for client certificates
}

// CertificateOption is a functional option for CertificateManager
type CertificateOption func(*CertificateManager)

// WithCAPath sets the CA path
func WithCAPath(path string) CertificateOption {
	return func(cm *CertificateManager) {
		cm.CAPath = path
	}
}

// WithCertPath sets the certificate path
func WithCertPath(path string) CertificateOption {
	return func(cm *CertificateManager) {
		cm.CertPath = path
	}
}

// WithKeyPath sets the key path
func WithKeyPath(path string) CertificateOption {
	return func(cm *CertificateManager) {
		cm.KeyPath = path
	}
}

// WithCRLPath sets the CRL path
func WithCRLPath(path string) CertificateOption {
	return func(cm *CertificateManager) {
		cm.CRLPath = path
	}
}

// WithDhPath sets the Diffie-Hellman parameters path
func WithDhPath(path string) CertificateOption {
	return func(cm *CertificateManager) {
		cm.DhPath = path
	}
}

// WithTLSAuthPath sets the TLS auth key path
func WithTLSAuthPath(path string) CertificateOption {
	return func(cm *CertificateManager) {
		cm.TLSAuthPath = path
	}
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(opts ...CertificateOption) *CertificateManager {
	cm := &CertificateManager{
		certificateCache: make(map[string]*x509.Certificate),
	}

	for _, opt := range opts {
		opt(cm)
	}

	return cm
}

// LoadCertificates loads all certificates and keys
func (cm *CertificateManager) LoadCertificates() error {
	// Load CA certificate
	if cm.CAPath != "" {
		certPool, err := loadCACertificate(cm.CAPath)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate: %w", err)
		}
		cm.certPool = certPool
	}

	// Load server certificate and key
	if cm.CertPath != "" && cm.KeyPath != "" {
		cert, err := loadCertificateAndKey(cm.CertPath, cm.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to load server certificate and key: %w", err)
		}
		cm.serverCert = cert
	}

	// Load CRL if specified
	if cm.CRLPath != "" {
		crl, err := loadCRL(cm.CRLPath)
		if err != nil {
			return fmt.Errorf("failed to load CRL: %w", err)
		}
		cm.crl = crl
	}

	// Load Diffie-Hellman parameters if specified
	if cm.DhPath != "" {
		dhParams, err := loadDhParams(cm.DhPath)
		if err != nil {
			return fmt.Errorf("failed to load Diffie-Hellman parameters: %w", err)
		}
		cm.dhParams = dhParams
	}

	// Load TLS auth key if specified
	if cm.TLSAuthPath != "" {
		tlsAuthKey, err := loadTLSAuthKey(cm.TLSAuthPath)
		if err != nil {
			return fmt.Errorf("failed to load TLS auth key: %w", err)
		}
		cm.tlsAuthKey = tlsAuthKey
	}

	return nil
}

// GetTLSConfig returns a TLS configuration for OpenVPN compatibility
func (cm *CertificateManager) GetTLSConfig() (*tls.Config, error) {
	if cm.serverCert == nil {
		return nil, ErrInvalidCertificate
	}

	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{*cm.serverCert},
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS13, // According to OWASP recommendations - minimum TLS 1.3
		PreferServerCipherSuites: true,             // Server chooses more secure cipher suites
		SessionTicketsDisabled:   true,             // Disable session tickets to protect against forward secrecy attacks
		CurvePreferences: []tls.CurveID{ // Preferred elliptic curves
			tls.X25519,
			tls.CurveP384,
			tls.CurveP256,
		},
	}

	// Set secure cipher suites according to OWASP recommendations
	tlsConfig.CipherSuites = []uint16{
		tls.TLS_AES_256_GCM_SHA384,       // Recommended for TLS 1.3
		tls.TLS_CHACHA20_POLY1305_SHA256, // Recommended for TLS 1.3
		tls.TLS_AES_128_GCM_SHA256,       // Recommended for TLS 1.3

		// Fallback cipher suites for TLS 1.2 (for compatibility)
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	if cm.certPool != nil {
		tlsConfig.ClientCAs = cm.certPool
	}

	return tlsConfig, nil
}

// VerifyClientCertificate verifies a client certificate against CA and CRL
func (cm *CertificateManager) VerifyClientCertificate(rawCerts [][]byte) error {
	if cm.certPool == nil {
		return ErrInvalidCertificate
	}

	if len(rawCerts) == 0 {
		return ErrInvalidCertificate
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create verification options
	opts := x509.VerifyOptions{
		Roots:         cm.certPool,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Add any intermediate certificates
	for i := 1; i < len(rawCerts); i++ {
		intCert, err := x509.ParseCertificate(rawCerts[i])
		if err != nil {
			return fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
		opts.Intermediates.AddCert(intCert)
	}

	// Perform verification
	_, err = cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	// Check if certificate is revoked
	if cm.crl != nil {
		for _, rev := range cm.crl.RevokedCertificateEntries {
			if rev.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("certificate has been revoked")
			}
		}
	}

	// Cache the certificate for later use
	cm.certificateCache[cert.Subject.CommonName] = cert
	return nil
}

// GetClientCommonName extracts the common name from a certificate
func (cm *CertificateManager) GetClientCommonName(rawCerts [][]byte) (string, error) {
	if len(rawCerts) == 0 {
		return "", ErrInvalidCertificate
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.Subject.CommonName, nil
}

// GetTLSAuthKey returns the TLS auth key
func (cm *CertificateManager) GetTLSAuthKey() []byte {
	return cm.tlsAuthKey
}

// Helper functions for loading certificates and keys

// loadCACertificate loads a CA certificate from a file
func loadCACertificate(caPath string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCertificateNotFound
		}
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		return nil, ErrInvalidCertificate
	}

	return certPool, nil
}

// loadCertificateAndKey loads a certificate and key from files
func loadCertificateAndKey(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			if _, err := os.Stat(certPath); os.IsNotExist(err) {
				return nil, ErrCertificateNotFound
			}
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	return &cert, nil
}

// loadCRL loads a Certificate Revocation List from file
func loadCRL(crlPath string) (*x509.RevocationList, error) {
	crlBytes, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL file: %w", err)
	}

	block, _ := pem.Decode(crlBytes)
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("failed to decode PEM block containing CRL")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return crl, nil
}

// loadDhParams loads Diffie-Hellman parameters from a file
func loadDhParams(dhPath string) ([]byte, error) {
	dhPEM, err := os.ReadFile(dhPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("Diffie-Hellman parameters file not found: %w", err)
		}
		return nil, err
	}

	return dhPEM, nil
}

// loadTLSAuthKey loads a TLS auth key from a file
func loadTLSAuthKey(tlsAuthPath string) ([]byte, error) {
	key, err := os.ReadFile(tlsAuthPath)
	if err != nil {
		if os.IsNotExist(err) {
			// TLS auth key is optional, so return nil if not found
			return nil, nil
		}
		return nil, err
	}

	return key, nil
}

// GenerateSelfSignedCertificate generates a self-signed certificate and key for testing
func GenerateSelfSignedCertificate(certPath, keyPath string) error {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create a template for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "GoVPN Test CA",
			Organization: []string{"GoVPN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// Create directories if they don't exist
	certDir := filepath.Dir(certPath)
	keyDir := filepath.Dir(keyPath)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}

	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return err
	}

	// Write the certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	// Write the private key to file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(keyOut, privBlock); err != nil {
		return err
	}

	return nil
}
