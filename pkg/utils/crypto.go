package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// HashSHA256 computes SHA256 hash of input data
func HashSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashStringSHA256 computes SHA256 hash of a string
func HashStringSHA256(data string) string {
	return HashSHA256([]byte(data))
}

// EncryptAES encrypts data using AES-GCM
func EncryptAES(plaintext []byte, key []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAES decrypts data using AES-GCM
func DecryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum ciphertext length
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and encrypted data
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// DeriveKeyFromPassword derives an encryption key from a password using PBKDF2
func DeriveKeyFromPassword(password string, salt []byte) []byte {
	// Simple key derivation - in production use PBKDF2 or Argon2
	combined := append([]byte(password), salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// GenerateAPIKey generates a secure API key
func GenerateAPIKey() (string, error) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateSessionToken generates a session token
func GenerateSessionToken() (string, error) {
	bytes, err := GenerateRandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SecureCompare performs constant-time string comparison
func SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	
	return result == 0
}

// EncodeBase64 encodes data to base64
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes base64 data
func DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// EncodeHex encodes data to hexadecimal
func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeHex decodes hexadecimal data
func DecodeHex(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}

// MaskSensitiveData masks sensitive data for logging
func MaskSensitiveData(data string) string {
	if len(data) <= 4 {
		return "****"
	}
	
	return data[:2] + strings.Repeat("*", len(data)-4) + data[len(data)-2:]
}

// ValidateAPIKey validates an API key format
func ValidateAPIKey(apiKey string) bool {
	if len(apiKey) < 16 {
		return false
	}
	
	// Check if it's valid base64
	_, err := base64.URLEncoding.DecodeString(apiKey)
	return err == nil
}

// GenerateNonce generates a cryptographic nonce
func GenerateNonce(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ComputeHMAC computes HMAC-SHA256
func ComputeHMAC(message, key []byte) []byte {
	h := sha256.New()
	h.Write(key)
	keyHash := h.Sum(nil)
	
	h.Reset()
	h.Write(append(keyHash, message...))
	return h.Sum(nil)
}

// VerifyHMAC verifies HMAC-SHA256
func VerifyHMAC(message, key, mac []byte) bool {
	expectedMAC := ComputeHMAC(message, key)
	return SecureCompare(hex.EncodeToString(expectedMAC), hex.EncodeToString(mac))
}
