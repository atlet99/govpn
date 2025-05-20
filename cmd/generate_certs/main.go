// Package main provides a utility for generating test certificates for GoVPN
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

var (
	outputDir = flag.String("out", "certs", "Output directory for certificates")
	certDays  = flag.Int("days", 365, "Certificate validity in days")
	keySize   = flag.Int("key-size", 4096, "RSA key size in bits (recommended 4096 bits according to OWASP)")
	hostname  = flag.String("hostname", "localhost", "Server hostname")
)

func main() {
	flag.Parse()

	// Check minimum security requirements
	if *keySize < 3072 {
		log.Printf("WARNING: RSA key size less than 3072 bits is considered insecure by OWASP standards")
		log.Printf("Using at least 3072 bits is recommended")

		// Automatically adjust key size to secure minimum
		if *keySize < 3072 {
			log.Printf("Automatically increasing key size to 3072 bits")
			*keySize = 3072
		}
	}

	// Ensure output directory exists
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate CA certificate and key
	if err := generateCA(); err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Generate server certificate and key
	if err := generateServerCert(); err != nil {
		log.Fatalf("Failed to generate server certificate: %v", err)
	}

	// Generate client certificate and key
	if err := generateClientCert(); err != nil {
		log.Fatalf("Failed to generate client certificate: %v", err)
	}

	// Generate TLS auth key
	if err := generateTLSAuthKey(); err != nil {
		log.Fatalf("Failed to generate TLS auth key: %v", err)
	}

	// Generate DH parameters
	if err := generateDHParams(); err != nil {
		log.Fatalf("Failed to generate DH parameters: %v", err)
	}

	log.Println("Certificate generation complete")
}

// generateCA generates a CA certificate and key
func generateCA() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Create a template for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "GoVPN Test CA",
			Organization: []string{"GoVPN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(*certDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA512WithRSA, // Using strong signature algorithm
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write the certificate to file
	certOut, err := os.Create(filepath.Join(*outputDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("failed to create CA certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Write the private key to file with secure permissions
	keyOut, err := os.OpenFile(filepath.Join(*outputDir, "ca.key"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create CA key file: %w", err)
	}
	defer keyOut.Close()

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(keyOut, privBlock); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	log.Println("Generated CA certificate and key")
	return nil
}

// generateServerCert generates a server certificate and key
func generateServerCert() error {
	// Load the CA certificate and key
	caCertBytes, err := os.ReadFile(filepath.Join(*outputDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caKeyBytes, err := os.ReadFile(filepath.Join(*outputDir, "ca.key"))
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	// Parse the CA certificate
	caCertBlock, _ := pem.Decode(caCertBytes)
	if caCertBlock == nil {
		return fmt.Errorf("failed to parse CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse the CA key
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	if caKeyBlock == nil {
		return fmt.Errorf("failed to parse CA key")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Generate a key for the server certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create a template for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   *hostname,
			Organization: []string{"GoVPN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(*certDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{*hostname},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		SignatureAlgorithm:    x509.SHA512WithRSA, // Using strong signature algorithm
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Write the certificate to file
	certOut, err := os.Create(filepath.Join(*outputDir, "server.crt"))
	if err != nil {
		return fmt.Errorf("failed to create server certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write server certificate: %w", err)
	}

	// Write the private key to file with secure permissions
	keyOut, err := os.OpenFile(filepath.Join(*outputDir, "server.key"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create server key file: %w", err)
	}
	defer keyOut.Close()

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(keyOut, privBlock); err != nil {
		return fmt.Errorf("failed to write server key: %w", err)
	}

	log.Println("Generated server certificate and key")
	return nil
}

// generateClientCert generates a client certificate and key
func generateClientCert() error {
	// Load the CA certificate and key
	caCertBytes, err := os.ReadFile(filepath.Join(*outputDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caKeyBytes, err := os.ReadFile(filepath.Join(*outputDir, "ca.key"))
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	// Parse the CA certificate
	caCertBlock, _ := pem.Decode(caCertBytes)
	if caCertBlock == nil {
		return fmt.Errorf("failed to parse CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse the CA key
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	if caKeyBlock == nil {
		return fmt.Errorf("failed to parse CA key")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Generate a key for the client certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		return fmt.Errorf("failed to generate client key: %w", err)
	}

	// Create a template for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "client1",
			Organization: []string{"GoVPN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(*certDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.SHA512WithRSA, // Using strong signature algorithm
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Write the certificate to file
	certOut, err := os.Create(filepath.Join(*outputDir, "client.crt"))
	if err != nil {
		return fmt.Errorf("failed to create client certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write client certificate: %w", err)
	}

	// Write the private key to file with secure permissions
	keyOut, err := os.OpenFile(filepath.Join(*outputDir, "client.key"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create client key file: %w", err)
	}
	defer keyOut.Close()

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(keyOut, privBlock); err != nil {
		return fmt.Errorf("failed to write client key: %w", err)
	}

	log.Println("Generated client certificate and key")
	return nil
}

// generateTLSAuthKey generates a TLS auth key
func generateTLSAuthKey() error {
	// Generate key with increased entropy - 512 bytes instead of 256
	// for better security according to OWASP recommendations
	tlsAuthKey := make([]byte, 512)
	if _, err := rand.Read(tlsAuthKey); err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Write the key to a file in hexadecimal format with secure permissions
	file, err := os.OpenFile(filepath.Join(*outputDir, "ta.key"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create TLS auth key file: %w", err)
	}
	defer file.Close()

	if _, err := fmt.Fprintf(file, "# OpenVPN TLS Auth Key (OWASP compliant, 4096 bits)\n"); err != nil {
		return fmt.Errorf("failed to write TLS auth key header: %w", err)
	}

	for i := 0; i < len(tlsAuthKey); i += 16 {
		end := i + 16
		if end > len(tlsAuthKey) {
			end = len(tlsAuthKey)
		}

		line := tlsAuthKey[i:end]
		for j, b := range line {
			if j > 0 {
				if _, err := fmt.Fprint(file, " "); err != nil {
					return fmt.Errorf("failed to write TLS auth key: %w", err)
				}
			}
			if _, err := fmt.Fprintf(file, "%02x", b); err != nil {
				return fmt.Errorf("failed to write TLS auth key: %w", err)
			}
		}
		if _, err := fmt.Fprintln(file); err != nil {
			return fmt.Errorf("failed to write TLS auth key: %w", err)
		}
	}

	log.Println("Generated TLS auth key (4096 bits, OWASP compliant)")
	return nil
}

// generateDHParams generates Diffie-Hellman parameters
// In a real implementation, use OpenSSL to generate DH parameters
func generateDHParams() error {
	log.Println("WARNING: DH parameter generation is implemented as a placeholder")
	log.Println("In a production environment, use command: openssl dhparam -out dh4096.pem 4096")

	// For testing purposes, we'll just create a dummy placeholder file
	file, err := os.OpenFile(filepath.Join(*outputDir, "dh4096.pem"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create DH params file: %w", err)
	}
	defer file.Close()

	// Write a placeholder with security note
	if _, err := fmt.Fprintln(file, "-----BEGIN DH PARAMETERS-----"); err != nil {
		return fmt.Errorf("failed to write DH params: %w", err)
	}

	if _, err := fmt.Fprintln(file, "# This is a placeholder for DH parameters."); err != nil {
		return fmt.Errorf("failed to write DH params: %w", err)
	}

	if _, err := fmt.Fprintln(file, "# In a production environment, generate real parameters using:"); err != nil {
		return fmt.Errorf("failed to write DH params: %w", err)
	}

	if _, err := fmt.Fprintln(file, "# openssl dhparam -out dh4096.pem 4096"); err != nil {
		return fmt.Errorf("failed to write DH params: %w", err)
	}

	if _, err := fmt.Fprintln(file, "# OWASP recommends using keys of at least 3072 bits"); err != nil {
		return fmt.Errorf("failed to write DH params: %w", err)
	}

	if _, err := fmt.Fprintln(file, "# PLACEHOLDER - DO NOT USE IN PRODUCTION"); err != nil {
		return fmt.Errorf("failed to write DH params: %w", err)
	}

	if _, err := fmt.Fprintln(file, "-----END DH PARAMETERS-----"); err != nil {
		return fmt.Errorf("failed to write DH params: %w", err)
	}

	log.Println("Created placeholder for DH parameters (4096 bits recommended)")
	return nil
}
