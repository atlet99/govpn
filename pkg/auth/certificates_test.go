package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCertificateManager(t *testing.T) {
	// Test creation with options
	caPath := "/path/to/ca.crt"
	certPath := "/path/to/cert.crt"
	keyPath := "/path/to/key.key"

	cm := NewCertificateManager(
		WithCAPath(caPath),
		WithCertPath(certPath),
		WithKeyPath(keyPath),
	)

	if cm.CAPath != caPath {
		t.Errorf("Expected CAPath '%s', got '%s'", caPath, cm.CAPath)
	}

	if cm.CertPath != certPath {
		t.Errorf("Expected CertPath '%s', got '%s'", certPath, cm.CertPath)
	}

	if cm.KeyPath != keyPath {
		t.Errorf("Expected KeyPath '%s', got '%s'", keyPath, cm.KeyPath)
	}

	if cm.certificateCache == nil {
		t.Error("Certificate cache should be initialized")
	}
}

func TestCertificateManagerOptions(t *testing.T) {
	cm := NewCertificateManager()

	// Test all options
	WithCRLPath("/path/to/crl.pem")(cm)
	WithDhPath("/path/to/dh.pem")(cm)
	WithTLSAuthPath("/path/to/ta.key")(cm)

	if cm.CRLPath != "/path/to/crl.pem" {
		t.Errorf("Expected CRLPath '/path/to/crl.pem', got '%s'", cm.CRLPath)
	}

	if cm.DhPath != "/path/to/dh.pem" {
		t.Errorf("Expected DhPath '/path/to/dh.pem', got '%s'", cm.DhPath)
	}

	if cm.TLSAuthPath != "/path/to/ta.key" {
		t.Errorf("Expected TLSAuthPath '/path/to/ta.key', got '%s'", cm.TLSAuthPath)
	}
}

func TestLoadCertificatesWithMissingFiles(t *testing.T) {
	cm := NewCertificateManager(
		WithCAPath("/nonexistent/ca.crt"),
		WithCertPath("/nonexistent/cert.crt"),
		WithKeyPath("/nonexistent/key.key"),
	)

	err := cm.LoadCertificates()
	if err == nil {
		t.Error("Expected error when loading non-existent certificates")
	}
}

func TestGetTLSConfigWithoutCertificate(t *testing.T) {
	cm := NewCertificateManager()

	_, err := cm.GetTLSConfig()
	if err != ErrInvalidCertificate {
		t.Errorf("Expected ErrInvalidCertificate, got %v", err)
	}
}

func TestGetTLSConfigSecurity(t *testing.T) {
	// Create temporary certificates for testing
	tempDir, err := os.MkdirTemp("", "govpn_cert_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")

	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	cm := NewCertificateManager(
		WithCertPath(certPath),
		WithKeyPath(keyPath),
	)

	if err := cm.LoadCertificates(); err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	tlsConfig, err := cm.GetTLSConfig()
	if err != nil {
		t.Fatalf("Failed to get TLS config: %v", err)
	}

	// Check security settings
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Error("Expected minimum TLS version to be 1.3")
	}

	if !tlsConfig.SessionTicketsDisabled {
		t.Error("Expected session tickets to be disabled")
	}

	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("Expected client certificate verification to be required")
	}

	// Check presence of secure cipher suites
	if len(tlsConfig.CipherSuites) == 0 {
		t.Error("Expected cipher suites to be configured")
	}

	// Check preferred curves
	expectedCurves := []tls.CurveID{tls.X25519, tls.CurveP384, tls.CurveP256}
	if len(tlsConfig.CurvePreferences) != len(expectedCurves) {
		t.Error("Expected specific curve preferences")
	}
}

func TestVerifyClientCertificateWithoutCA(t *testing.T) {
	cm := NewCertificateManager()

	// Verification attempt without CA should return error
	err := cm.VerifyClientCertificate([][]byte{{}})
	if err == nil {
		t.Error("Expected error when verifying certificate without CA")
	}
}

func TestGetClientCommonNameWithInvalidCert(t *testing.T) {
	cm := NewCertificateManager()

	// Attempt to get Common Name from invalid certificate
	_, err := cm.GetClientCommonName([][]byte{{}})
	if err == nil {
		t.Error("Expected error when getting common name from invalid certificate")
	}
}

func TestGetTLSAuthKey(t *testing.T) {
	cm := NewCertificateManager()

	// Initially key should be nil
	key := cm.GetTLSAuthKey()
	if key != nil {
		t.Error("Expected TLS auth key to be nil initially")
	}

	// Set key manually for testing
	testKey := []byte("test-tls-auth-key")
	cm.tlsAuthKey = testKey

	key = cm.GetTLSAuthKey()
	if string(key) != string(testKey) {
		t.Error("Expected TLS auth key to match set value")
	}
}

func TestLoadCACertificateInvalidFile(t *testing.T) {
	// Create temporary file with invalid content
	tempFile, err := os.CreateTemp("", "invalid_ca")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write invalid content
	if _, err := tempFile.WriteString("invalid certificate data"); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	_, err = loadCACertificate(tempFile.Name())
	if err == nil {
		t.Error("Expected error when loading invalid CA certificate")
	}
}

func TestLoadCertificateAndKeyMissingFiles(t *testing.T) {
	_, err := loadCertificateAndKey("/nonexistent/cert.crt", "/nonexistent/key.key")
	if err == nil {
		t.Error("Expected error when loading non-existent certificate and key")
	}
}

func TestGenerateSelfSignedCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "govpn_generate_cert_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "generated.crt")
	keyPath := filepath.Join(tempDir, "generated.key")

	err = GenerateSelfSignedCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Check that files were created
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Certificate file was not created")
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Check that we can load the created files
	_, err = loadCertificateAndKey(certPath, keyPath)
	if err != nil {
		t.Errorf("Failed to load generated certificate and key: %v", err)
	}
}

// Helper function to create test certificate
func generateTestCertificate(certPath, keyPath string) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Organization"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// Save certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// Save key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
}

func TestCertificateManagerEmptyPaths(t *testing.T) {
	cm := NewCertificateManager()

	// Loading with empty paths should succeed
	err := cm.LoadCertificates()
	if err != nil {
		t.Errorf("Expected no error with empty paths, got: %v", err)
	}

	// All fields should be nil/empty
	if cm.certPool != nil {
		t.Error("Expected certPool to be nil")
	}

	if cm.serverCert != nil {
		t.Error("Expected serverCert to be nil")
	}

	if cm.crl != nil {
		t.Error("Expected crl to be nil")
	}

	if cm.dhParams != nil {
		t.Error("Expected dhParams to be nil")
	}

	if cm.tlsAuthKey != nil {
		t.Error("Expected tlsAuthKey to be nil")
	}
}

func TestErrorTypes(t *testing.T) {
	// Check that errors have correct messages
	expectedErrors := map[error]string{
		ErrInvalidCertificate:  "invalid certificate",
		ErrInvalidKey:          "invalid key",
		ErrCertificateNotFound: "certificate file not found",
		ErrKeyNotFound:         "key file not found",
	}

	for err, expectedMsg := range expectedErrors {
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	}
}
