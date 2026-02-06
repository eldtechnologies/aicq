"""Tests for AICQ DM encryption module."""

import base64
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aicq_crypto import (
    encrypt_dm,
    decrypt_dm,
    AICQCryptoError,
    EPHEMERAL_PK_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
)


def _make_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate Ed25519 keypair, return (private_key, public_key_b64)."""
    pk = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(pk.public_key().public_bytes_raw()).decode()
    return pk, pub_b64


class TestEncryptDecrypt(unittest.TestCase):

    def setUp(self):
        self.alice_priv, self.alice_pub = _make_keypair()
        self.bob_priv, self.bob_pub = _make_keypair()

    def test_round_trip(self):
        """Encrypt with recipient pubkey, decrypt with recipient privkey."""
        ct = encrypt_dm("Hello Bob!", self.bob_pub)
        pt = decrypt_dm(ct, self.bob_priv)
        self.assertEqual(pt, "Hello Bob!")

    def test_wire_format_structure(self):
        """Wire format: ephemeral_pk(32) + nonce(12) + ciphertext(N+16)."""
        plaintext = "test"
        ct_b64 = encrypt_dm(plaintext, self.bob_pub)
        wire = base64.b64decode(ct_b64)

        expected_min = EPHEMERAL_PK_SIZE + NONCE_SIZE + len(plaintext.encode()) + TAG_SIZE
        self.assertEqual(len(wire), expected_min)

        # First 32 bytes should be a valid X25519 public key (32 bytes)
        ephemeral_pk = wire[:EPHEMERAL_PK_SIZE]
        self.assertEqual(len(ephemeral_pk), 32)

    def test_different_ciphertexts_for_same_plaintext(self):
        """Each encryption uses a fresh ephemeral key, so ciphertexts differ."""
        ct1 = encrypt_dm("same message", self.bob_pub)
        ct2 = encrypt_dm("same message", self.bob_pub)
        self.assertNotEqual(ct1, ct2)

        # Both should decrypt to the same plaintext
        self.assertEqual(decrypt_dm(ct1, self.bob_priv), "same message")
        self.assertEqual(decrypt_dm(ct2, self.bob_priv), "same message")

    def test_wrong_key_fails(self):
        """Decrypting with wrong private key should fail."""
        ct = encrypt_dm("secret", self.bob_pub)
        with self.assertRaises(AICQCryptoError) as ctx:
            decrypt_dm(ct, self.alice_priv)
        self.assertIn("Decryption failed", str(ctx.exception))

    def test_tampered_ciphertext_fails(self):
        """Modifying ciphertext should cause decryption to fail."""
        ct_b64 = encrypt_dm("secret", self.bob_pub)
        wire = bytearray(base64.b64decode(ct_b64))
        # Flip a byte in the ciphertext portion
        wire[-1] ^= 0xFF
        tampered = base64.b64encode(bytes(wire)).decode()
        with self.assertRaises(AICQCryptoError):
            decrypt_dm(tampered, self.bob_priv)

    def test_truncated_ciphertext_fails(self):
        """Too-short ciphertext should raise error."""
        short = base64.b64encode(b"x" * 30).decode()
        with self.assertRaises(AICQCryptoError) as ctx:
            decrypt_dm(short, self.bob_priv)
        self.assertIn("too short", str(ctx.exception))

    def test_empty_plaintext(self):
        """Empty string should encrypt and decrypt correctly."""
        ct = encrypt_dm("", self.bob_pub)
        pt = decrypt_dm(ct, self.bob_priv)
        self.assertEqual(pt, "")

    def test_unicode_plaintext(self):
        """Unicode characters should round-trip correctly."""
        msg = "Hello \U0001f30d\u2764\ufe0f \u65e5\u672c\u8a9e"
        ct = encrypt_dm(msg, self.bob_pub)
        pt = decrypt_dm(ct, self.bob_priv)
        self.assertEqual(pt, msg)

    def test_invalid_public_key_base64(self):
        """Non-base64 public key should raise AICQCryptoError."""
        with self.assertRaises(AICQCryptoError) as ctx:
            encrypt_dm("test", "not-valid-base64!!!")
        self.assertIn("Invalid recipient public key", str(ctx.exception))

    def test_wrong_length_public_key(self):
        """Public key of wrong length should raise AICQCryptoError."""
        bad_key = base64.b64encode(b"x" * 16).decode()
        with self.assertRaises(AICQCryptoError) as ctx:
            encrypt_dm("test", bad_key)
        self.assertIn("Invalid public key length", str(ctx.exception))

    def test_invalid_base64_ciphertext(self):
        """Non-base64 ciphertext should raise AICQCryptoError."""
        with self.assertRaises(AICQCryptoError):
            decrypt_dm("not-valid-base64!!!", self.bob_priv)

    def test_large_message(self):
        """Large messages should work correctly."""
        msg = "A" * 8000
        ct = encrypt_dm(msg, self.bob_pub)
        pt = decrypt_dm(ct, self.bob_priv)
        self.assertEqual(pt, msg)

    def test_bidirectional(self):
        """Both parties can send and receive."""
        # Alice -> Bob
        ct1 = encrypt_dm("Hi Bob", self.bob_pub)
        self.assertEqual(decrypt_dm(ct1, self.bob_priv), "Hi Bob")

        # Bob -> Alice
        ct2 = encrypt_dm("Hi Alice", self.alice_pub)
        self.assertEqual(decrypt_dm(ct2, self.alice_priv), "Hi Alice")


if __name__ == "__main__":
    unittest.main()
