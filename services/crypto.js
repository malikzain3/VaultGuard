'use strict';

const crypto = require('node:crypto');

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const SALT_BYTES = 16;
const MAXMEM = 64 * 1024 * 1024;
const CIPHER = 'chacha20-poly1305';
const MASTER_LABEL = 'vaultguard:master-verifier:v1';

// N = 2^15, r = 8, p = 1 (required for the master key).
function deriveKey(password, salt, options = {}) {
  const {
    N = 32768,
    r = 8,
    p = 1,
    keylen = KEY_BYTES,
  } = options;

  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('A password is required to derive a key.');
  }
  if (!Buffer.isBuffer(salt) || salt.length < SALT_BYTES) {
    throw new Error('A salt of at least 16 bytes is required.');
  }

  return crypto.scryptSync(password, salt, keylen, { N, r, p, maxmem: MAXMEM });
}

function encrypt(key, plaintext, nonce = crypto.randomBytes(NONCE_BYTES)) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new Error('Encryption key must be 32 bytes.');
  }
  if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_BYTES) {
    throw new Error('Nonce must be 12 bytes.');
  }

  const input = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const cipher = crypto.createCipheriv(CIPHER, key, nonce, { authTagLength: TAG_BYTES });
  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);

  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}

function integrityError() {
  const error = new Error('Data integrity check failed');
  error.code = 'INTEGRITY_FAILED';
  return error;
}

function decrypt(key, ciphertext, nonce, authTag) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) throw integrityError();
  if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_BYTES) throw integrityError();
  if (!Buffer.isBuffer(authTag) || authTag.length !== TAG_BYTES) throw integrityError();

  try {
    const decipher = crypto.createDecipheriv(CIPHER, key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    // Never return plaintext when the Poly1305 tag does not verify.
    throw integrityError();
  }
}

// Per-field subkeys let us store ONE nonce per entry while still never
// reusing the same key + nonce pair for two different messages.
function fieldKey(key, label) {
  return crypto.createHmac('sha256', key).update(`vaultguard:field:${label}:v1`).digest();
}

function createMasterVerifier(key) {
  return crypto.createHmac('sha256', key).update(MASTER_LABEL).digest();
}

function verifyMasterVerifier(key, storedHex) {
  const expected = Buffer.isBuffer(storedHex) ? storedHex : Buffer.from(String(storedHex || ''), 'hex');
  const actual = createMasterVerifier(key);
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

module.exports = {
  deriveKey,
  encrypt,
  decrypt,
  fieldKey,
  createMasterVerifier,
  verifyMasterVerifier,
  integrityError,
  KEY_BYTES,
  NONCE_BYTES,
  TAG_BYTES,
  SALT_BYTES,
};
