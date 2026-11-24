'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');

const dataDir = path.join(__dirname, '..', 'data');
const vaultDir = path.join(dataDir, 'vaults');
fs.mkdirSync(vaultDir, { recursive: true });

const accountsDb = new Database(path.join(dataDir, 'accounts.db'));

// Create the table if it doesn't exist (name column included from the start)
accountsDb.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE,
    name            TEXT,
    password_hash   TEXT NOT NULL,
    password_salt   TEXT NOT NULL,
    master_salt     TEXT,
    master_verifier TEXT,
    created_at      TEXT NOT NULL
  );
`);

// Safe migration: add `name` column to existing databases that don't have it
const cols = accountsDb.prepare('PRAGMA table_info(accounts)').all();
const hasName = cols.some((c) => c.name === 'name');
if (!hasName) {
  accountsDb.exec('ALTER TABLE accounts ADD COLUMN name TEXT;');
}

module.exports = { accountsDb, dataDir, vaultDir };
