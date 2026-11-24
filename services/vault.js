'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const Database = require('better-sqlite3');
const {
  encrypt,
  decrypt,
  fieldKey,
  integrityError,
  NONCE_BYTES,
  TAG_BYTES,
} = require('./crypto');
const { vaultDir } = require('../db/init');

const openVaults = new Map();

function openVault(accountId) {
  if (openVaults.has(accountId)) return openVaults.get(accountId);

  const db = new Database(path.join(vaultDir, `${accountId}.db`));
  db.exec(`
    CREATE TABLE IF NOT EXISTS entries (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      app_name     TEXT NOT NULL,
      username_enc BLOB NOT NULL,
      password_enc BLOB NOT NULL,
      nonce        BLOB NOT NULL,
      auth_tag     BLOB NOT NULL,
      created_at   TEXT NOT NULL
    );
  `);
  openVaults.set(accountId, db);
  return db;
}

function addEntry(accountId, key, { appName, username, password }) {
  // One random nonce per entry. Distinct HMAC-derived field keys mean the
  // key + nonce pair is never reused for two different plaintexts.
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const user = encrypt(fieldKey(key, 'username'), username, nonce);
  const pass = encrypt(fieldKey(key, 'password'), password, nonce);
  const authTag = Buffer.concat([user.authTag, pass.authTag]); // 16 + 16 bytes

  openVault(accountId)
    .prepare(`INSERT INTO entries
      (app_name, username_enc, password_enc, nonce, auth_tag, created_at)
      VALUES (?, ?, ?, ?, ?, ?)`)
    .run(appName, user.ciphertext, pass.ciphertext, nonce, authTag, new Date().toISOString());
}

function listEntries(accountId) {
  return openVault(accountId)
    .prepare('SELECT id, app_name, created_at FROM entries ORDER BY app_name COLLATE NOCASE, id')
    .all();
}

function revealEntry(accountId, key, id) {
  const row = openVault(accountId)
    .prepare('SELECT id, app_name, username_enc, password_enc, nonce, auth_tag FROM entries WHERE id = ?')
    .get(id);

  if (!row) return null;
  if (!Buffer.isBuffer(row.auth_tag) || row.auth_tag.length !== TAG_BYTES * 2) {
    throw integrityError();
  }

  const username = decrypt(
    fieldKey(key, 'username'),
    row.username_enc,
    row.nonce,
    row.auth_tag.subarray(0, TAG_BYTES)
  ).toString('utf8');

  const password = decrypt(
    fieldKey(key, 'password'),
    row.password_enc,
    row.nonce,
    row.auth_tag.subarray(TAG_BYTES)
  ).toString('utf8');

  return { id: row.id, appName: row.app_name, username, password };
}

module.exports = { openVault, addEntry, listEntries, revealEntry };
