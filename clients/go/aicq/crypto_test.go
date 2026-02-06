package aicq

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func generateTestKeypair(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.StdEncoding.EncodeToString(pub)
}

func TestRoundTrip(t *testing.T) {
	bobPriv, bobPub := generateTestKeypair(t)

	ct, err := EncryptDM("Hello Bob!", bobPub)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptDM(ct, bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "Hello Bob!" {
		t.Fatalf("expected 'Hello Bob!', got %q", pt)
	}
}

func TestWireFormatStructure(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	ct, err := EncryptDM("test", pubB64)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := base64.StdEncoding.DecodeString(ct)
	// 32 (eph pk) + 12 (nonce) + 4 (plaintext) + 16 (tag) = 64
	if len(wire) != 64 {
		t.Fatalf("expected wire length 64, got %d", len(wire))
	}
}

func TestDifferentCiphertexts(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	ct1, _ := EncryptDM("same", pubB64)
	ct2, _ := EncryptDM("same", pubB64)
	if ct1 == ct2 {
		t.Fatal("ciphertexts should differ for same plaintext")
	}

	pt1, _ := DecryptDM(ct1, priv)
	pt2, _ := DecryptDM(ct2, priv)
	if pt1 != "same" || pt2 != "same" {
		t.Fatal("both should decrypt to 'same'")
	}
}

func TestWrongKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	ct, _ := EncryptDM("secret", pubB64)

	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, err := DecryptDM(ct, wrongPriv)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
	if !ErrCrypto(err) {
		t.Fatalf("expected CryptoError, got %T", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	ct, _ := EncryptDM("secret", pubB64)
	wire, _ := base64.StdEncoding.DecodeString(ct)
	wire[len(wire)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(wire)

	_, err := DecryptDM(tampered, priv)
	if err == nil {
		t.Fatal("expected error with tampered ciphertext")
	}
}

func TestTruncatedCiphertext(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	short := base64.StdEncoding.EncodeToString(make([]byte, 30))

	_, err := DecryptDM(short, priv)
	if err == nil {
		t.Fatal("expected error with truncated ciphertext")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	ct, err := EncryptDM("", pubB64)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptDM(ct, priv)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "" {
		t.Fatalf("expected empty string, got %q", pt)
	}
}

func TestUnicodePlaintext(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	msg := "Hello \U0001F30D\u2764\uFE0F \u65E5\u672C\u8A9E"
	ct, err := EncryptDM(msg, pubB64)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptDM(ct, priv)
	if err != nil {
		t.Fatal(err)
	}
	if pt != msg {
		t.Fatalf("expected %q, got %q", msg, pt)
	}
}

func TestInvalidPublicKeyLength(t *testing.T) {
	_, err := EncryptDM("test", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if err == nil {
		t.Fatal("expected error with wrong-length key")
	}
	if !ErrCrypto(err) {
		t.Fatalf("expected CryptoError, got %T", err)
	}
}

func TestLargeMessage(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	msg := make([]byte, 8000)
	for i := range msg {
		msg[i] = 'A'
	}
	ct, err := EncryptDM(string(msg), pubB64)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptDM(ct, priv)
	if err != nil {
		t.Fatal(err)
	}
	if pt != string(msg) {
		t.Fatal("large message round-trip failed")
	}
}

func TestBidirectional(t *testing.T) {
	_, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	alicePub := base64.StdEncoding.EncodeToString(alicePriv.Public().(ed25519.PublicKey))

	_, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	bobPub := base64.StdEncoding.EncodeToString(bobPriv.Public().(ed25519.PublicKey))

	// Alice -> Bob
	ct1, _ := EncryptDM("Hi Bob", bobPub)
	pt1, err := DecryptDM(ct1, bobPriv)
	if err != nil || pt1 != "Hi Bob" {
		t.Fatal("Alice->Bob failed")
	}

	// Bob -> Alice
	ct2, _ := EncryptDM("Hi Alice", alicePub)
	pt2, err := DecryptDM(ct2, alicePriv)
	if err != nil || pt2 != "Hi Alice" {
		t.Fatal("Bob->Alice failed")
	}
}
