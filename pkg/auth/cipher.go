package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"log"
)

var (
	// ErrInvalidCipherMode is returned when an invalid cipher mode is specified
	ErrInvalidCipherMode = errors.New("invalid cipher mode")

	// ErrInvalidKeySize is returned when an invalid key size is provided
	ErrInvalidKeySize = errors.New("invalid key size")

	// ErrInvalidAuthDigest is returned when an invalid authentication digest is specified
	ErrInvalidAuthDigest = errors.New("invalid authentication digest")

	// ErrInsecureMode is returned when an insecure cipher mode is requested
	ErrInsecureMode = errors.New("insecure cipher mode requested")

	// ErrInsecureDigest is returned when an insecure digest is requested
	ErrInsecureDigest = errors.New("insecure authentication digest requested")
)

// CipherMode represents the cipher mode for OpenVPN
type CipherMode string

const (
	// CipherAES128GCM represents AES-128-GCM mode
	CipherAES128GCM CipherMode = "AES-128-GCM"

	// CipherAES192GCM represents AES-192-GCM mode
	CipherAES192GCM CipherMode = "AES-192-GCM"

	// CipherAES256GCM represents AES-256-GCM mode
	CipherAES256GCM CipherMode = "AES-256-GCM"

	// CipherAES128CBC represents AES-128-CBC mode (legacy)
	CipherAES128CBC CipherMode = "AES-128-CBC"

	// CipherAES192CBC represents AES-192-CBC mode (legacy)
	CipherAES192CBC CipherMode = "AES-192-CBC"

	// CipherAES256CBC represents AES-256-CBC mode (legacy)
	CipherAES256CBC CipherMode = "AES-256-CBC"

	// CipherChacha20Poly1305 represents ChaCha20-Poly1305 mode
	CipherChacha20Poly1305 CipherMode = "CHACHA20-POLY1305"
)

// AuthDigest represents the authentication digest algorithm
type AuthDigest string

const (
	// AuthSHA256 represents SHA256 digest (recommended by OWASP)
	AuthSHA256 AuthDigest = "SHA256"

	// AuthSHA512 represents SHA512 digest (recommended by OWASP)
	AuthSHA512 AuthDigest = "SHA512"

	// AuthSHA1 represents SHA1 digest (deprecated, not recommended)
	AuthSHA1 AuthDigest = "SHA1"
)

// CipherContext holds the cipher configuration for encryption/decryption
type CipherContext struct {
	CipherMode  CipherMode
	AuthDigest  AuthDigest
	Key         []byte
	IV          []byte
	HMAC        hash.Hash
	BlockCipher cipher.Block
	GCM         cipher.AEAD
	IsGCM       bool
}

// RecommendedCipherMode returns the recommended cipher mode
func RecommendedCipherMode() CipherMode {
	return CipherAES256GCM
}

// RecommendedAuthDigest returns the recommended authentication algorithm
func RecommendedAuthDigest() AuthDigest {
	return AuthSHA512
}

// NewCipherContext creates a new cipher context with the specified mode and digest
func NewCipherContext(mode CipherMode, digest AuthDigest, key []byte) (*CipherContext, error) {
	// Output warnings about insecure algorithms
	if digest == AuthSHA1 {
		log.Printf("WARNING: SHA1 is considered insecure by OWASP standards. Use SHA256 or SHA512 instead")
	}

	if mode == CipherAES128CBC || mode == CipherAES192CBC || mode == CipherAES256CBC {
		log.Printf("WARNING: CBC modes are considered less secure than GCM according to OWASP standards")
		log.Printf("AES-256-GCM is recommended")
	}

	ctx := &CipherContext{
		CipherMode: mode,
		AuthDigest: digest,
		Key:        key,
	}

	// Validate cipher mode
	keySize := 0
	switch mode {
	case CipherAES128GCM:
		keySize = 16 // 128 bits
		ctx.IsGCM = true
	case CipherAES192GCM:
		keySize = 24 // 192 bits
		ctx.IsGCM = true
	case CipherAES256GCM:
		keySize = 32 // 256 bits
		ctx.IsGCM = true
	case CipherAES128CBC:
		keySize = 16 // 128 bits
	case CipherAES192CBC:
		keySize = 24 // 192 bits
	case CipherAES256CBC:
		keySize = 32 // 256 bits
	case CipherChacha20Poly1305:
		keySize = 32 // 256 bits
		ctx.IsGCM = true
	default:
		return nil, ErrInvalidCipherMode
	}

	// Validate key size
	if len(key) < keySize {
		return nil, fmt.Errorf("%w: got %d bytes, need %d bytes", ErrInvalidKeySize, len(key), keySize)
	}

	// Use only needed key bytes
	ctx.Key = key[:keySize]

	// Create block cipher
	var err error
	switch {
	case mode == CipherAES128GCM || mode == CipherAES192GCM || mode == CipherAES256GCM ||
		mode == CipherAES128CBC || mode == CipherAES192CBC || mode == CipherAES256CBC:
		// AES modes
		ctx.BlockCipher, err = aes.NewCipher(ctx.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}

		if ctx.IsGCM {
			ctx.GCM, err = cipher.NewGCM(ctx.BlockCipher)
			if err != nil {
				return nil, fmt.Errorf("failed to create GCM: %w", err)
			}
		}
	case mode == CipherChacha20Poly1305:
		// ChaCha20-Poly1305 is an AEAD cipher
		// TODO: Implement support for ChaCha20-Poly1305 (alternative to AES-GCM, recommended by OWASP)
		return nil, errors.New("ChaCha20-Poly1305 not implemented yet")
	}

	// Initialize HMAC for non-GCM modes
	if !ctx.IsGCM {
		switch digest {
		case AuthSHA1:
			// SHA1 is not recommended by OWASP, but kept for backward compatibility
			return nil, ErrInsecureDigest
		case AuthSHA256:
			ctx.HMAC = sha256.New()
		case AuthSHA512:
			ctx.HMAC = sha512.New()
		default:
			return nil, ErrInvalidAuthDigest
		}
	}

	return ctx, nil
}

// InitIV initializes a random IV for the cipher context
func (c *CipherContext) InitIV() error {
	ivSize := 0
	if c.IsGCM {
		ivSize = 12 // 96 bits for GCM - recommended for GCM
	} else {
		ivSize = c.BlockCipher.BlockSize()
	}

	// Use cryptographically secure PRNG for IV generation
	c.IV = make([]byte, ivSize)
	n, err := rand.Read(c.IV)
	if err != nil {
		return err
	}

	// Verify that we got the required number of random bytes
	if n != ivSize {
		return fmt.Errorf("failed to generate %d random bytes for IV, got only %d", ivSize, n)
	}

	return nil
}

// SetIV sets the IV for the cipher context
func (c *CipherContext) SetIV(iv []byte) error {
	ivSize := 0
	if c.IsGCM {
		ivSize = 12 // 96 bits for GCM
	} else {
		ivSize = c.BlockCipher.BlockSize()
	}

	if len(iv) < ivSize {
		return fmt.Errorf("invalid IV size: got %d bytes, need %d bytes", len(iv), ivSize)
	}

	c.IV = make([]byte, ivSize)
	copy(c.IV, iv[:ivSize])
	return nil
}

// Encrypt encrypts plaintext data
func (c *CipherContext) Encrypt(plaintext []byte) ([]byte, error) {
	if c.IV == nil {
		if err := c.InitIV(); err != nil {
			return nil, fmt.Errorf("failed to initialize IV: %w", err)
		}
	}

	var ciphertext []byte

	if c.IsGCM {
		// GCM mode (AES-GCM, ChaCha20-Poly1305)
		ciphertext = c.GCM.Seal(nil, c.IV, plaintext, nil)
	} else {
		// CBC mode with HMAC
		if len(plaintext)%c.BlockCipher.BlockSize() != 0 {
			// Add PKCS#7 padding
			padLen := c.BlockCipher.BlockSize() - (len(plaintext) % c.BlockCipher.BlockSize())
			padding := make([]byte, padLen)
			for i := 0; i < padLen; i++ {
				padding[i] = byte(padLen)
			}
			plaintext = append(plaintext, padding...)
		}

		ciphertext = make([]byte, len(plaintext))
		encrypter := cipher.NewCBCEncrypter(c.BlockCipher, c.IV)
		encrypter.CryptBlocks(ciphertext, plaintext)

		// Calculate HMAC
		c.HMAC.Reset()
		c.HMAC.Write(ciphertext)
		hmacSum := c.HMAC.Sum(nil)

		// Append HMAC to ciphertext
		ciphertext = append(ciphertext, hmacSum...)
	}

	// Prepend IV to ciphertext
	ciphertext = append(c.IV, ciphertext...)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext data
func (c *CipherContext) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	var ivSize int
	if c.IsGCM {
		ivSize = 12 // 96 bits for GCM
	} else {
		ivSize = c.BlockCipher.BlockSize()
	}

	if len(ciphertext) <= ivSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract IV from the beginning of ciphertext
	iv := ciphertext[:ivSize]
	ciphertext = ciphertext[ivSize:]

	// Set the IV
	if err := c.SetIV(iv); err != nil {
		return nil, err
	}

	var plaintext []byte

	if c.IsGCM {
		// GCM mode
		var err error
		plaintext, err = c.GCM.Open(nil, c.IV, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	} else {
		// CBC mode with HMAC
		hmacSize := c.HMAC.Size()
		if len(ciphertext) <= hmacSize {
			return nil, errors.New("ciphertext too short for HMAC")
		}

		// Split ciphertext and HMAC
		encryptedData := ciphertext[:len(ciphertext)-hmacSize]
		expectedHMAC := ciphertext[len(ciphertext)-hmacSize:]

		// Verify HMAC
		c.HMAC.Reset()
		c.HMAC.Write(encryptedData)
		calculatedHMAC := c.HMAC.Sum(nil)

		// Constant-time comparison to prevent timing attacks
		if !hmacEqual(calculatedHMAC, expectedHMAC) {
			return nil, errors.New("HMAC verification failed")
		}

		// Decrypt the data
		plaintext = make([]byte, len(encryptedData))
		decrypter := cipher.NewCBCDecrypter(c.BlockCipher, c.IV)
		decrypter.CryptBlocks(plaintext, encryptedData)

		// Remove PKCS#7 padding
		padLen := int(plaintext[len(plaintext)-1])
		if padLen > 0 && padLen <= c.BlockCipher.BlockSize() {
			plaintext = plaintext[:len(plaintext)-padLen]
		}
	}

	return plaintext, nil
}

// hmacEqual compares two HMACs in constant time to prevent timing attacks
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// KeyDerivation functions for OpenVPN key material

// DeriveKeys derives encryption and HMAC keys from a master secret
func DeriveKeys(masterSecret []byte, salt []byte, keySize int) (encKey, hmacKey []byte, err error) {
	// This is a simplified version of OpenVPN key derivation
	// In a real implementation, this would use HKDF or PRF from TLS
	hasher := sha256.New()

	// Key material for encryption key
	hasher.Write([]byte("OpenVPN key material encryption"))
	hasher.Write(masterSecret)
	hasher.Write(salt)
	encKey = hasher.Sum(nil)

	// Key material for HMAC key
	hasher.Reset()
	hasher.Write([]byte("OpenVPN key material authentication"))
	hasher.Write(masterSecret)
	hasher.Write(salt)
	hmacKey = hasher.Sum(nil)

	// Trim to the requested size
	if len(encKey) > keySize {
		encKey = encKey[:keySize]
	}

	if len(hmacKey) > keySize {
		hmacKey = hmacKey[:keySize]
	}

	return encKey, hmacKey, nil
}
