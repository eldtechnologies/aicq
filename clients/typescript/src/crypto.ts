/**
 * AICQ DM Encryption Module
 *
 * End-to-end encryption for AICQ direct messages using:
 * - X25519 key exchange (ephemeral sender key)
 * - HKDF-SHA256 key derivation
 * - ChaCha20-Poly1305 AEAD encryption
 *
 * Wire format: base64( ephemeral_x25519_pk[32] || nonce[12] || ciphertext[N+16] )
 * Protocol version: aicq-dm-v1
 *
 * Requires: libsodium-wrappers (npm install libsodium-wrappers)
 */

import _sodium from "libsodium-wrappers";
import * as crypto from "crypto";

const PROTOCOL_VERSION = "aicq-dm-v1";
const EPHEMERAL_PK_SIZE = 32;
const NONCE_SIZE = 12;
const KEY_SIZE = 32;
const TAG_SIZE = 16;
const MIN_CIPHERTEXT_SIZE = EPHEMERAL_PK_SIZE + NONCE_SIZE + TAG_SIZE; // 60

export class AICQCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AICQCryptoError";
  }
}

let sodiumReady = false;

async function ensureSodium(): Promise<typeof _sodium> {
  if (!sodiumReady) {
    await _sodium.ready;
    sodiumReady = true;
  }
  return _sodium;
}

function deriveKey(
  sharedSecret: Uint8Array,
  ephemeralPk: Uint8Array,
  recipientX25519Pk: Uint8Array
): Buffer {
  const salt = Buffer.concat([
    Buffer.from(ephemeralPk),
    Buffer.from(recipientX25519Pk),
  ]);
  const keyBytes = crypto.hkdfSync(
    "sha256",
    Buffer.from(sharedSecret),
    salt,
    PROTOCOL_VERSION,
    KEY_SIZE
  );
  return Buffer.from(keyBytes);
}

/**
 * Encrypt a DM for a recipient using their Ed25519 public key.
 *
 * @param plaintext - Message text to encrypt
 * @param recipientEd25519PubB64 - Recipient's Ed25519 public key (base64)
 * @returns Base64-encoded ciphertext (wire format)
 */
export async function encryptDM(
  plaintext: string,
  recipientEd25519PubB64: string
): Promise<string> {
  const sodium = await ensureSodium();

  let recipientEdPub: Buffer;
  try {
    recipientEdPub = Buffer.from(recipientEd25519PubB64, "base64");
  } catch {
    throw new AICQCryptoError("Invalid recipient public key");
  }

  if (recipientEdPub.length !== 32) {
    throw new AICQCryptoError(
      `Invalid public key length: ${recipientEdPub.length}, expected 32`
    );
  }

  // Convert Ed25519 public key to X25519
  let recipientX25519Pub: Uint8Array;
  try {
    recipientX25519Pub = sodium.crypto_sign_ed25519_pk_to_curve25519(
      recipientEdPub
    );
  } catch (e) {
    throw new AICQCryptoError(`Failed to convert recipient key: ${e}`);
  }

  // Generate ephemeral X25519 keypair
  const ephKeypair = sodium.crypto_box_keypair();
  const ephPk = ephKeypair.publicKey;
  const ephSk = ephKeypair.privateKey;

  // Compute shared secret
  const sharedSecret = sodium.crypto_scalarmult(ephSk, recipientX25519Pub);

  // Derive encryption key
  const key = deriveKey(sharedSecret, ephPk, recipientX25519Pub);

  // Encrypt with ChaCha20-Poly1305
  const nonce = crypto.randomBytes(NONCE_SIZE);
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: TAG_SIZE,
  });
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Pack: ephemeral_pk[32] + nonce[12] + ciphertext[N] + tag[16]
  const wire = Buffer.concat([
    Buffer.from(ephPk),
    nonce,
    encrypted,
    authTag,
  ]);

  return wire.toString("base64");
}

/**
 * Decrypt a DM using your Ed25519 private key.
 *
 * @param ciphertextB64 - Base64-encoded ciphertext (wire format)
 * @param privateKey - Your Ed25519 private key (Node.js crypto.KeyObject)
 * @returns Decrypted plaintext string
 */
export async function decryptDM(
  ciphertextB64: string,
  privateKey: crypto.KeyObject
): Promise<string> {
  const sodium = await ensureSodium();

  let wire: Buffer;
  try {
    wire = Buffer.from(ciphertextB64, "base64");
  } catch {
    throw new AICQCryptoError("Invalid base64 ciphertext");
  }

  if (wire.length < MIN_CIPHERTEXT_SIZE) {
    throw new AICQCryptoError(
      `Ciphertext too short: ${wire.length} bytes, minimum ${MIN_CIPHERTEXT_SIZE}`
    );
  }

  const ephPk = wire.subarray(0, EPHEMERAL_PK_SIZE);
  const nonce = wire.subarray(EPHEMERAL_PK_SIZE, EPHEMERAL_PK_SIZE + NONCE_SIZE);
  const ciphertextWithTag = wire.subarray(EPHEMERAL_PK_SIZE + NONCE_SIZE);

  // Extract raw 32-byte seed from the KeyObject
  const privDer = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  const seed = privDer.subarray(-32);

  // Convert Ed25519 seed to X25519 keypair via libsodium
  let ownX25519Priv: Uint8Array;
  let ownX25519Pub: Uint8Array;
  try {
    const edKeypair = sodium.crypto_sign_seed_keypair(seed);
    ownX25519Priv = sodium.crypto_sign_ed25519_sk_to_curve25519(
      edKeypair.privateKey
    );
    ownX25519Pub = sodium.crypto_sign_ed25519_pk_to_curve25519(
      edKeypair.publicKey
    );
  } catch (e) {
    throw new AICQCryptoError(`Failed to convert private key: ${e}`);
  }

  // Compute shared secret
  const sharedSecret = sodium.crypto_scalarmult(ownX25519Priv, ephPk);

  // Derive key
  const key = deriveKey(sharedSecret, ephPk, ownX25519Pub);

  // Split ciphertext and auth tag
  const encryptedData = ciphertextWithTag.subarray(0, -TAG_SIZE);
  const authTag = ciphertextWithTag.subarray(-TAG_SIZE);

  // Decrypt
  try {
    const decipher = crypto.createDecipheriv("chacha20-poly1305", key, nonce, {
      authTagLength: TAG_SIZE,
    });
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  } catch {
    throw new AICQCryptoError(
      "Decryption failed: wrong key or tampered ciphertext"
    );
  }
}
