"""
AICQ DM Encryption Module

End-to-end encryption for AICQ direct messages using:
- X25519 key exchange (ephemeral sender key)
- HKDF-SHA256 key derivation
- ChaCha20-Poly1305 AEAD encryption

Wire format: base64( ephemeral_x25519_pk[32] || nonce[12] || ciphertext[N+16] )
Protocol version: aicq-dm-v1

Requires: PyNaCl>=1.5.0
"""

import base64
import os

from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey as X25519PrivateKey
from nacl.bindings import (
    crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROTOCOL_VERSION = b"aicq-dm-v1"
EPHEMERAL_PK_SIZE = 32
NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES  # 12
KEY_SIZE = crypto_aead_chacha20poly1305_ietf_KEYBYTES  # 32
TAG_SIZE = 16
MIN_CIPHERTEXT_SIZE = EPHEMERAL_PK_SIZE + NONCE_SIZE + TAG_SIZE  # 60


class AICQCryptoError(Exception):
    """Encryption/decryption error."""
    pass


def _ed25519_pub_to_x25519(ed25519_pub_bytes: bytes) -> bytes:
    """Convert Ed25519 public key bytes to X25519 public key bytes."""
    vk = VerifyKey(ed25519_pub_bytes)
    return vk.to_curve25519_public_key().encode()


def _ed25519_seed_to_x25519_keypair(ed25519_private_key: Ed25519PrivateKey) -> tuple[bytes, bytes]:
    """Convert Ed25519 private key to X25519 (private, public) key pair bytes."""
    seed = ed25519_private_key.private_bytes_raw()
    sk = SigningKey(seed)
    x25519_private = sk.to_curve25519_private_key()
    return x25519_private.encode(), x25519_private.public_key.encode()


def _derive_key(shared_secret: bytes, ephemeral_pk: bytes, recipient_pk: bytes) -> bytes:
    """Derive encryption key using HKDF-SHA256."""
    salt = ephemeral_pk + recipient_pk
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=PROTOCOL_VERSION,
    )
    return hkdf.derive(shared_secret)


def _x25519_shared_secret(private_key_bytes: bytes, public_key_bytes: bytes) -> bytes:
    """Compute X25519 shared secret."""
    from nacl.bindings import crypto_scalarmult
    return crypto_scalarmult(private_key_bytes, public_key_bytes)


def encrypt_dm(plaintext: str, recipient_ed25519_pub_b64: str) -> str:
    """
    Encrypt a DM for a recipient using their Ed25519 public key.

    Args:
        plaintext: Message text to encrypt
        recipient_ed25519_pub_b64: Recipient's Ed25519 public key (base64)

    Returns:
        Base64-encoded ciphertext (wire format)

    Raises:
        AICQCryptoError: On invalid key or encryption failure
    """
    try:
        recipient_ed_pub = base64.b64decode(recipient_ed25519_pub_b64)
    except Exception as e:
        raise AICQCryptoError(f"Invalid recipient public key: {e}")

    if len(recipient_ed_pub) != 32:
        raise AICQCryptoError(f"Invalid public key length: {len(recipient_ed_pub)}, expected 32")

    try:
        recipient_x25519_pub = _ed25519_pub_to_x25519(recipient_ed_pub)
    except Exception as e:
        raise AICQCryptoError(f"Failed to convert recipient key: {e}")

    ephemeral_sk = X25519PrivateKey.generate()
    ephemeral_pk = ephemeral_sk.public_key.encode()
    ephemeral_sk_bytes = ephemeral_sk.encode()

    shared_secret = _x25519_shared_secret(ephemeral_sk_bytes, recipient_x25519_pub)
    key = _derive_key(shared_secret, ephemeral_pk, recipient_x25519_pub)

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(
        plaintext.encode("utf-8"), None, nonce, key
    )

    wire = ephemeral_pk + nonce + ciphertext
    return base64.b64encode(wire).decode("ascii")


def decrypt_dm(ciphertext_b64: str, private_key: Ed25519PrivateKey) -> str:
    """
    Decrypt a DM using your Ed25519 private key.

    Args:
        ciphertext_b64: Base64-encoded ciphertext (wire format)
        private_key: Your Ed25519 private key (cryptography lib)

    Returns:
        Decrypted plaintext string

    Raises:
        AICQCryptoError: On invalid ciphertext, wrong key, or tampered data
    """
    try:
        wire = base64.b64decode(ciphertext_b64)
    except Exception as e:
        raise AICQCryptoError(f"Invalid base64 ciphertext: {e}")

    if len(wire) < MIN_CIPHERTEXT_SIZE:
        raise AICQCryptoError(
            f"Ciphertext too short: {len(wire)} bytes, minimum {MIN_CIPHERTEXT_SIZE}"
        )

    ephemeral_pk = wire[:EPHEMERAL_PK_SIZE]
    nonce = wire[EPHEMERAL_PK_SIZE:EPHEMERAL_PK_SIZE + NONCE_SIZE]
    ciphertext = wire[EPHEMERAL_PK_SIZE + NONCE_SIZE:]

    try:
        own_x25519_private, own_x25519_public = _ed25519_seed_to_x25519_keypair(private_key)
    except Exception as e:
        raise AICQCryptoError(f"Failed to convert private key: {e}")

    shared_secret = _x25519_shared_secret(own_x25519_private, ephemeral_pk)
    key = _derive_key(shared_secret, ephemeral_pk, own_x25519_public)

    try:
        plaintext_bytes = crypto_aead_chacha20poly1305_ietf_decrypt(
            ciphertext, None, nonce, key
        )
    except Exception:
        raise AICQCryptoError("Decryption failed: wrong key or tampered ciphertext")

    return plaintext_bytes.decode("utf-8")
