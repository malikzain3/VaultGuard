'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  deriveKey,
  encrypt,
  decrypt,
  NONCE_BYTES,
  TAG_BYTES,
} = require('../services/crypto');

test('encrypt/decrypt round-trip returns the original plaintext', () => {
  const key = crypto.randomBytes(32);
  const plaintext = Buffer.from('user@example.com: S3cure-Pass!', 'utf8');

  const { ciphertext, nonce, authTag } = encrypt(key, plaintext);
  assert.equal(nonce.length, NONCE_BYTES);
  assert.equal(authTag.length, TAG_BYTES);
  assert.notDeepEqual(ciphertext, plaintext);
  assert.deepEqual(decrypt(key, ciphertext, nonce, authTag), plaintext);
});

test('a tampered authentication tag is rejected', () => {
  const key = crypto.randomBytes(32);
  const { ciphertext, nonce, authTag } = encrypt(key, 'vaultguard');

  const tampered = Buffer.from(authTag);
  tampered[0] ^= 0x01;

  assert.throws(() => decrypt(key, ciphertext, nonce, tampered), (err) => {
    assert.equal(err.code, 'INTEGRITY_FAILED');
    assert.equal(err.message, 'Data integrity check failed');
    return true;
  });
});

test('decrypting with the wrong key is rejected', () => {
  const { ciphertext, nonce, authTag } = encrypt(crypto.randomBytes(32), 'secret value');
  const wrongKey = crypto.randomBytes(32);

  assert.throws(() => decrypt(wrongKey, ciphertext, nonce, authTag), (err) => {
    assert.equal(err.code, 'INTEGRITY_FAILED');
    return true;
  });
});

test('deriveKey is deterministic for one salt and changes with another', () => {
  const password = 'correct horse battery staple';
  const saltA = crypto.randomBytes(16);
  const saltB = crypto.randomBytes(16);

  const keyA = deriveKey(password, saltA);
  assert.equal(keyA.length, 32);
  assert.deepEqual(deriveKey(password, saltA), keyA);
  assert.notDeepEqual(deriveKey(password, saltB), keyA);
});
