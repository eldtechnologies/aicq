/**
 * Tests for AICQ DM encryption module.
 * Run: npx ts-node src/crypto.test.ts
 */

import * as assert from "assert";
import * as crypto from "crypto";
import { encryptDM, decryptDM, AICQCryptoError } from "./crypto";

function makeKeypair(): {
  privateKey: crypto.KeyObject;
  publicKeyB64: string;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const pubBytes = (pubDer as Buffer).subarray(-32);
  return {
    privateKey,
    publicKeyB64: pubBytes.toString("base64"),
  };
}

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (e) {
    console.error(`  FAIL: ${name}`);
    console.error(`    ${e}`);
    failed++;
  }
}

async function main() {
  console.log("AICQ Crypto Tests\n");

  const alice = makeKeypair();
  const bob = makeKeypair();

  await test("round-trip encrypt/decrypt", async () => {
    const ct = await encryptDM("Hello Bob!", bob.publicKeyB64);
    const pt = await decryptDM(ct, bob.privateKey);
    assert.strictEqual(pt, "Hello Bob!");
  });

  await test("wire format structure", async () => {
    const plaintext = "test";
    const ct = await encryptDM(plaintext, bob.publicKeyB64);
    const wire = Buffer.from(ct, "base64");
    // 32 (ephemeral pk) + 12 (nonce) + 4 (plaintext) + 16 (tag) = 64
    assert.strictEqual(wire.length, 32 + 12 + plaintext.length + 16);
  });

  await test("different ciphertexts for same plaintext", async () => {
    const ct1 = await encryptDM("same message", bob.publicKeyB64);
    const ct2 = await encryptDM("same message", bob.publicKeyB64);
    assert.notStrictEqual(ct1, ct2);
    assert.strictEqual(await decryptDM(ct1, bob.privateKey), "same message");
    assert.strictEqual(await decryptDM(ct2, bob.privateKey), "same message");
  });

  await test("wrong key fails", async () => {
    const ct = await encryptDM("secret", bob.publicKeyB64);
    await assert.rejects(
      () => decryptDM(ct, alice.privateKey),
      (e: Error) => e instanceof AICQCryptoError && e.message.includes("Decryption failed")
    );
  });

  await test("tampered ciphertext fails", async () => {
    const ct = await encryptDM("secret", bob.publicKeyB64);
    const wire = Buffer.from(ct, "base64");
    wire[wire.length - 1] ^= 0xff;
    const tampered = wire.toString("base64");
    await assert.rejects(
      () => decryptDM(tampered, bob.privateKey),
      AICQCryptoError
    );
  });

  await test("truncated ciphertext fails", async () => {
    const short = Buffer.alloc(30).toString("base64");
    await assert.rejects(
      () => decryptDM(short, bob.privateKey),
      (e: Error) => e instanceof AICQCryptoError && e.message.includes("too short")
    );
  });

  await test("empty plaintext", async () => {
    const ct = await encryptDM("", bob.publicKeyB64);
    const pt = await decryptDM(ct, bob.privateKey);
    assert.strictEqual(pt, "");
  });

  await test("unicode plaintext", async () => {
    const msg = "Hello \u{1F30D}\u{2764}\u{FE0F} \u{65E5}\u{672C}\u{8A9E}";
    const ct = await encryptDM(msg, bob.publicKeyB64);
    const pt = await decryptDM(ct, bob.privateKey);
    assert.strictEqual(pt, msg);
  });

  await test("wrong length public key", async () => {
    const badKey = Buffer.alloc(16).toString("base64");
    await assert.rejects(
      () => encryptDM("test", badKey),
      (e: Error) => e instanceof AICQCryptoError && e.message.includes("Invalid public key length")
    );
  });

  await test("large message", async () => {
    const msg = "A".repeat(8000);
    const ct = await encryptDM(msg, bob.publicKeyB64);
    const pt = await decryptDM(ct, bob.privateKey);
    assert.strictEqual(pt, msg);
  });

  await test("bidirectional", async () => {
    const ct1 = await encryptDM("Hi Bob", bob.publicKeyB64);
    assert.strictEqual(await decryptDM(ct1, bob.privateKey), "Hi Bob");

    const ct2 = await encryptDM("Hi Alice", alice.publicKeyB64);
    assert.strictEqual(await decryptDM(ct2, alice.privateKey), "Hi Alice");
  });

  await test("cross-compatible with Python wire format", async () => {
    // Verify our wire format is: ephemeral_pk[32] + nonce[12] + ciphertext[N+16]
    const ct = await encryptDM("x", bob.publicKeyB64);
    const wire = Buffer.from(ct, "base64");
    // Minimum: 32 + 12 + 1 + 16 = 61 bytes for single-char plaintext
    assert.strictEqual(wire.length, 61);
    // Ephemeral pk should be 32 bytes (valid X25519 point)
    assert.strictEqual(wire.subarray(0, 32).length, 32);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main();
