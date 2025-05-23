package auth

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRecommendedCipherMode(t *testing.T) {
	mode := RecommendedCipherMode()
	if mode != CipherAES256GCM {
		t.Errorf("Expected recommended cipher mode to be %s, got %s", CipherAES256GCM, mode)
	}
}

func TestRecommendedAuthDigest(t *testing.T) {
	digest := RecommendedAuthDigest()
	if digest != AuthSHA512 {
		t.Errorf("Expected recommended auth digest to be %s, got %s", AuthSHA512, digest)
	}
}

func TestNewCipherContextValidModes(t *testing.T) {
	tests := []struct {
		name      string
		mode      CipherMode
		digest    AuthDigest
		keySize   int
		shouldGCM bool
	}{
		{"AES-128-GCM", CipherAES128GCM, AuthSHA256, 16, true},
		{"AES-192-GCM", CipherAES192GCM, AuthSHA256, 24, true},
		{"AES-256-GCM", CipherAES256GCM, AuthSHA512, 32, true},
		{"ChaCha20-Poly1305", CipherChacha20Poly1305, AuthSHA256, 32, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate random key: %v", err)
			}

			ctx, err := NewCipherContext(tt.mode, tt.digest, key)
			if err != nil {
				t.Fatalf("Failed to create cipher context: %v", err)
			}

			if ctx.CipherMode != tt.mode {
				t.Errorf("Expected cipher mode %s, got %s", tt.mode, ctx.CipherMode)
			}

			if ctx.AuthDigest != tt.digest {
				t.Errorf("Expected auth digest %s, got %s", tt.digest, ctx.AuthDigest)
			}

			if ctx.IsGCM != tt.shouldGCM {
				t.Errorf("Expected IsGCM to be %v, got %v", tt.shouldGCM, ctx.IsGCM)
			}

			if len(ctx.Key) != tt.keySize {
				t.Errorf("Expected key size %d, got %d", tt.keySize, len(ctx.Key))
			}
		})
	}
}

func TestNewCipherContextInvalidMode(t *testing.T) {
	key := make([]byte, 32)
	_, err := NewCipherContext("INVALID_MODE", AuthSHA256, key)
	if err != ErrInvalidCipherMode {
		t.Errorf("Expected ErrInvalidCipherMode, got %v", err)
	}
}

func TestNewCipherContextInvalidKeySize(t *testing.T) {
	key := make([]byte, 8) // Too small for any AES mode
	_, err := NewCipherContext(CipherAES256GCM, AuthSHA256, key)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestNewCipherContextInsecureDigest(t *testing.T) {
	key := make([]byte, 32)
	_, err := NewCipherContext(CipherAES256CBC, AuthSHA1, key)
	if err != ErrInsecureDigest {
		t.Errorf("Expected ErrInsecureDigest, got %v", err)
	}
}

func TestCipherContextInitIV(t *testing.T) {
	key := make([]byte, 32)
	ctx, err := NewCipherContext(CipherAES256GCM, AuthSHA256, key)
	if err != nil {
		t.Fatalf("Failed to create cipher context: %v", err)
	}

	err = ctx.InitIV()
	if err != nil {
		t.Fatalf("Failed to initialize IV: %v", err)
	}

	// GCM should use 12-byte IV
	if len(ctx.IV) != 12 {
		t.Errorf("Expected IV length 12 for GCM, got %d", len(ctx.IV))
	}

	// IV should not be all zeros
	allZero := true
	for _, b := range ctx.IV {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("IV should not be all zeros")
	}
}

func TestCipherContextSetIV(t *testing.T) {
	key := make([]byte, 32)
	ctx, err := NewCipherContext(CipherAES256GCM, AuthSHA256, key)
	if err != nil {
		t.Fatalf("Failed to create cipher context: %v", err)
	}

	testIV := make([]byte, 12)
	for i := range testIV {
		testIV[i] = byte(i)
	}

	err = ctx.SetIV(testIV)
	if err != nil {
		t.Fatalf("Failed to set IV: %v", err)
	}

	if !bytes.Equal(ctx.IV, testIV) {
		t.Error("IV was not set correctly")
	}

	// Test with invalid IV length
	invalidIV := make([]byte, 8)
	err = ctx.SetIV(invalidIV)
	if err == nil {
		t.Error("Expected error for invalid IV length")
	}
}

func TestEncryptDecryptGCM(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	ctx, err := NewCipherContext(CipherAES256GCM, AuthSHA256, key)
	if err != nil {
		t.Fatalf("Failed to create cipher context: %v", err)
	}

	err = ctx.InitIV()
	if err != nil {
		t.Fatalf("Failed to initialize IV: %v", err)
	}

	plaintext := []byte("Hello, GoVPN World! This is a test message for encryption.")

	// Encryption
	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	// Decryption
	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match original. Expected %s, got %s", string(plaintext), string(decrypted))
	}
}

func TestEncryptDecryptChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	ctx, err := NewCipherContext(CipherChacha20Poly1305, AuthSHA256, key)
	if err != nil {
		t.Fatalf("Failed to create cipher context: %v", err)
	}

	err = ctx.InitIV()
	if err != nil {
		t.Fatalf("Failed to initialize IV: %v", err)
	}

	plaintext := []byte("ChaCha20-Poly1305 encryption test message")

	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text does not match original")
	}
}

func TestEncryptWithoutIV(t *testing.T) {
	key := make([]byte, 32)
	ctx, err := NewCipherContext(CipherAES256GCM, AuthSHA256, key)
	if err != nil {
		t.Fatalf("Failed to create cipher context: %v", err)
	}

	plaintext := []byte("test")
	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		t.Errorf("Encryption should succeed with auto-generated IV, got error: %v", err)
	}

	// IV should have been automatically generated
	if len(ctx.IV) == 0 {
		t.Error("IV should have been automatically generated")
	}

	// Check that we can decrypt
	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text does not match original")
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	ctx, err := NewCipherContext(CipherAES256GCM, AuthSHA256, key)
	if err != nil {
		t.Fatalf("Failed to create cipher context: %v", err)
	}

	err = ctx.InitIV()
	if err != nil {
		t.Fatalf("Failed to initialize IV: %v", err)
	}

	// Attempt to decrypt invalid data
	invalidCiphertext := []byte("invalid ciphertext")
	_, err = ctx.Decrypt(invalidCiphertext)
	if err == nil {
		t.Error("Expected error when decrypting invalid ciphertext")
	}
}

func TestDeriveKeys(t *testing.T) {
	masterSecret := make([]byte, 32)
	if _, err := rand.Read(masterSecret); err != nil {
		t.Fatalf("Failed to generate master secret: %v", err)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	encKey, hmacKey, err := DeriveKeys(masterSecret, salt, 32)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	if len(encKey) != 32 {
		t.Errorf("Expected encryption key length 32, got %d", len(encKey))
	}

	if len(hmacKey) != 32 {
		t.Errorf("Expected HMAC key length 32, got %d", len(hmacKey))
	}

	// Keys should not be equal
	if bytes.Equal(encKey, hmacKey) {
		t.Error("Encryption key and HMAC key should not be equal")
	}

	// Derived keys should be deterministic
	encKey2, hmacKey2, err := DeriveKeys(masterSecret, salt, 32)
	if err != nil {
		t.Fatalf("Failed to derive keys second time: %v", err)
	}

	if !bytes.Equal(encKey, encKey2) {
		t.Error("Encryption keys should be equal for same input")
	}

	if !bytes.Equal(hmacKey, hmacKey2) {
		t.Error("HMAC keys should be equal for same input")
	}
}

func TestDeriveKeysWithDifferentSalts(t *testing.T) {
	masterSecret := make([]byte, 32)
	if _, err := rand.Read(masterSecret); err != nil {
		t.Fatalf("Failed to generate master secret: %v", err)
	}

	salt1 := make([]byte, 16)
	salt2 := make([]byte, 16)
	if _, err := rand.Read(salt1); err != nil {
		t.Fatalf("Failed to generate salt1: %v", err)
	}
	if _, err := rand.Read(salt2); err != nil {
		t.Fatalf("Failed to generate salt2: %v", err)
	}

	encKey1, _, err := DeriveKeys(masterSecret, salt1, 32)
	if err != nil {
		t.Fatalf("Failed to derive keys with salt1: %v", err)
	}

	encKey2, _, err := DeriveKeys(masterSecret, salt2, 32)
	if err != nil {
		t.Fatalf("Failed to derive keys with salt2: %v", err)
	}

	// Keys with different salts should be different
	if bytes.Equal(encKey1, encKey2) {
		t.Error("Keys derived with different salts should not be equal")
	}
}

func TestCipherModeConstants(t *testing.T) {
	expectedModes := map[CipherMode]string{
		CipherAES128GCM:        "AES-128-GCM",
		CipherAES192GCM:        "AES-192-GCM",
		CipherAES256GCM:        "AES-256-GCM",
		CipherAES128CBC:        "AES-128-CBC",
		CipherAES192CBC:        "AES-192-CBC",
		CipherAES256CBC:        "AES-256-CBC",
		CipherChacha20Poly1305: "CHACHA20-POLY1305",
	}

	for mode, expected := range expectedModes {
		if string(mode) != expected {
			t.Errorf("Expected cipher mode constant %s, got %s", expected, string(mode))
		}
	}
}

func TestAuthDigestConstants(t *testing.T) {
	expectedDigests := map[AuthDigest]string{
		AuthSHA256: "SHA256",
		AuthSHA512: "SHA512",
		AuthSHA1:   "SHA1",
	}

	for digest, expected := range expectedDigests {
		if string(digest) != expected {
			t.Errorf("Expected auth digest constant %s, got %s", expected, string(digest))
		}
	}
}

func TestErrorConstants(t *testing.T) {
	expectedErrors := map[error]string{
		ErrInvalidCipherMode: "invalid cipher mode",
		ErrInvalidKeySize:    "invalid key size",
		ErrInvalidAuthDigest: "invalid authentication digest",
		ErrInsecureMode:      "insecure cipher mode requested",
		ErrInsecureDigest:    "insecure authentication digest requested",
	}

	for err, expectedMsg := range expectedErrors {
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		mode CipherMode
	}{
		{"AES-128-GCM", CipherAES128GCM},
		{"AES-192-GCM", CipherAES192GCM},
		{"AES-256-GCM", CipherAES256GCM},
		{"ChaCha20-Poly1305", CipherChacha20Poly1305},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var keySize int
			switch tc.mode {
			case CipherAES128GCM:
				keySize = 16
			case CipherAES192GCM:
				keySize = 24
			default:
				keySize = 32
			}

			key := make([]byte, keySize)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate random key: %v", err)
			}

			ctx, err := NewCipherContext(tc.mode, AuthSHA256, key)
			if err != nil {
				t.Fatalf("Failed to create cipher context: %v", err)
			}

			testMessages := []string{
				"",
				"a",
				"Hello, World!",
				"This is a longer test message with more content to encrypt and decrypt.",
			}

			for _, msg := range testMessages {
				plaintext := []byte(msg)

				err = ctx.InitIV()
				if err != nil {
					t.Fatalf("Failed to initialize IV: %v", err)
				}

				ciphertext, err := ctx.Encrypt(plaintext)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}

				decrypted, err := ctx.Decrypt(ciphertext)
				if err != nil {
					t.Fatalf("Failed to decrypt: %v", err)
				}

				if !bytes.Equal(plaintext, decrypted) {
					t.Errorf("Round trip failed for message '%s'", msg)
				}
			}
		})
	}
}
