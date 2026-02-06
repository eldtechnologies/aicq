package aicq

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"crypto/sha256"
)

const (
	protocolVersion  = "aicq-dm-v1"
	ephemeralPKSize  = 32
	nonceSize        = 12
	keySize          = 32
	tagSize          = 16
	minCiphertextLen = ephemeralPKSize + nonceSize + tagSize // 60
)

// CryptoError represents an encryption/decryption error.
type CryptoError struct {
	Message string
}

func (e *CryptoError) Error() string {
	return e.Message
}

// ed25519PubToX25519 converts an Ed25519 public key to an X25519 public key.
func ed25519PubToX25519(edPub ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	return p.BytesMontgomery(), nil
}

// ed25519SeedToX25519Private converts an Ed25519 seed to an X25519 private key.
func ed25519SeedToX25519Private(seed []byte) []byte {
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return h[:32]
}

// deriveKey derives an encryption key using HKDF-SHA256.
func deriveKey(sharedSecret, ephemeralPK, recipientX25519PK []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephemeralPK)+len(recipientX25519PK))
	salt = append(salt, ephemeralPK...)
	salt = append(salt, recipientX25519PK...)

	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, []byte(protocolVersion))
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptDM encrypts a DM for a recipient using their Ed25519 public key.
// Returns the base64-encoded wire format ciphertext.
func EncryptDM(plaintext string, recipientEd25519PubB64 string) (string, error) {
	recipientEdPub, err := base64.StdEncoding.DecodeString(recipientEd25519PubB64)
	if err != nil {
		return "", &CryptoError{Message: fmt.Sprintf("invalid recipient public key: %v", err)}
	}
	if len(recipientEdPub) != ed25519.PublicKeySize {
		return "", &CryptoError{Message: fmt.Sprintf("invalid public key length: %d, expected %d", len(recipientEdPub), ed25519.PublicKeySize)}
	}

	recipientX25519Pub, err := ed25519PubToX25519(ed25519.PublicKey(recipientEdPub))
	if err != nil {
		return "", &CryptoError{Message: fmt.Sprintf("failed to convert recipient key: %v", err)}
	}

	// Generate ephemeral X25519 keypair
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return "", err
	}
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}

	// Shared secret
	sharedSecret, err := curve25519.X25519(ephPriv[:], recipientX25519Pub)
	if err != nil {
		return "", err
	}

	// Derive key
	key, err := deriveKey(sharedSecret, ephPub, recipientX25519Pub)
	if err != nil {
		return "", err
	}

	// Encrypt with ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)

	// Wire format: ephemeral_pk[32] + nonce[12] + ciphertext[N+16]
	wire := make([]byte, 0, len(ephPub)+nonceSize+len(ciphertext))
	wire = append(wire, ephPub...)
	wire = append(wire, nonce...)
	wire = append(wire, ciphertext...)

	return base64.StdEncoding.EncodeToString(wire), nil
}

// DecryptDM decrypts a DM using the recipient's Ed25519 private key.
// Returns the plaintext string.
func DecryptDM(ciphertextB64 string, privateKey ed25519.PrivateKey) (string, error) {
	wire, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", &CryptoError{Message: fmt.Sprintf("invalid base64 ciphertext: %v", err)}
	}

	if len(wire) < minCiphertextLen {
		return "", &CryptoError{Message: fmt.Sprintf("ciphertext too short: %d bytes, minimum %d", len(wire), minCiphertextLen)}
	}

	ephPK := wire[:ephemeralPKSize]
	nonce := wire[ephemeralPKSize : ephemeralPKSize+nonceSize]
	ciphertext := wire[ephemeralPKSize+nonceSize:]

	// Convert own Ed25519 key to X25519
	seed := privateKey.Seed()
	ownX25519Priv := ed25519SeedToX25519Private(seed)
	ownX25519Pub, err := curve25519.X25519(ownX25519Priv, curve25519.Basepoint)
	if err != nil {
		return "", &CryptoError{Message: fmt.Sprintf("failed to derive X25519 public key: %v", err)}
	}

	// Shared secret
	sharedSecret, err := curve25519.X25519(ownX25519Priv, ephPK)
	if err != nil {
		return "", &CryptoError{Message: "decryption failed: invalid ephemeral key"}
	}

	// Derive key
	key, err := deriveKey(sharedSecret, ephPK, ownX25519Pub)
	if err != nil {
		return "", err
	}

	// Decrypt
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", &CryptoError{Message: "decryption failed: wrong key or tampered ciphertext"}
	}

	return string(plaintext), nil
}

// ErrCrypto checks if an error is a CryptoError.
func ErrCrypto(err error) bool {
	var ce *CryptoError
	return errors.As(err, &ce)
}
