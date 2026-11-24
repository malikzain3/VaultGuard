'use strict';

const crypto = require('node:crypto');
const { accountsDb } = require('../db/init');
const { deriveKey, SALT_BYTES } = require('./crypto');

// Account login password hashing uses scrypt defaults (N = 2^14, r = 8, p = 1).
const PASSWORD_SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const hash = deriveKey(password, salt, PASSWORD_SCRYPT);
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}

function verifyPassword(password, saltHex, hashHex) {
  const expected = Buffer.from(String(hashHex || ''), 'hex');
  const actual = deriveKey(password, Buffer.from(String(saltHex || ''), 'hex'), PASSWORD_SCRYPT);
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

function getAccountById(id) {
  return accountsDb.prepare('SELECT * FROM accounts WHERE id = ?').get(id);
}

function getAccountByEmail(email) {
  return accountsDb.prepare('SELECT * FROM accounts WHERE email = ?').get(email);
}

/**
 * Derive a clean display name from an account record.
 * Falls back to capitalizing the local-part of the email when name is blank.
 * e.g. "zain.dev@gmail.com" → "Zain Dev"
 */
function displayName(account) {
  if (account?.name && account.name.trim()) return account.name.trim();
  const local = (account?.email || '').split('@')[0];
  return local
    .replace(/[._-]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim() || account?.email || '';
}

function createAccount(email, password, name = '') {
  const { salt, hash } = hashPassword(password);
  const trimmedName = typeof name === 'string' ? name.trim() : '';
  const info = accountsDb
    .prepare(
      'INSERT INTO accounts (email, name, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)'
    )
    .run(email, trimmedName || null, hash, salt, new Date().toISOString());
  return getAccountById(Number(info.lastInsertRowid));
}

function setMaster(accountId, saltHex, verifierHex) {
  accountsDb
    .prepare('UPDATE accounts SET master_salt = ?, master_verifier = ? WHERE id = ?')
    .run(saltHex, verifierHex, accountId);
}

module.exports = {
  hashPassword,
  verifyPassword,
  getAccountById,
  getAccountByEmail,
  createAccount,
  setMaster,
  displayName,
};
