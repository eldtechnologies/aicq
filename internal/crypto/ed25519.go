package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	ErrInvalidPublicKey = errors.New("invalid Ed25519 public key")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrSignatureExpired = errors.New("signature timestamp expired")
	ErrInvalidNonce     = errors.New("invalid or reused nonce")
)

// ValidatePublicKey checks if a base64-encoded string is a valid Ed25519 public key.
func ValidatePublicKey(pubkeyB64 string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(pubkeyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 encoding", ErrInvalidPublicKey)
	}

	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidPublicKey, ed25519.PublicKeySize, len(decoded))
	}

	return ed25519.PublicKey(decoded), nil
}

// VerifySignature verifies a signed message.
func VerifySignature(pubkey ed25519.PublicKey, signedData []byte, signatureB64 string) error {
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("%w: invalid base64 encoding", ErrInvalidSignature)
	}

	if !ed25519.Verify(pubkey, signedData, signature) {
		return ErrInvalidSignature
	}

	return nil
}

// SignaturePayload creates the canonical data to sign.
// Format: body|nonce|timestamp
func SignaturePayload(body, nonce string, timestamp int64) []byte {
	return []byte(fmt.Sprintf("%s|%s|%d", body, nonce, timestamp))
}
