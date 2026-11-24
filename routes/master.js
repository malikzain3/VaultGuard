'use strict';

const express = require('express');
const crypto = require('node:crypto');
const { getAccountById, setMaster } = require('../services/accounts');
const {
  deriveKey,
  createMasterVerifier,
  verifyMasterVerifier,
  SALT_BYTES,
} = require('../services/crypto');
const { validMasterPassword } = require('../services/validation');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/master/setup', requireAuth, (req, res) => {
  const account = getAccountById(req.session.accountId);
  if (account.master_verifier) return res.redirect('/dashboard');

  res.render('master-setup', { title: 'Create master password', error: null });
});

router.post('/master/setup', requireAuth, (req, res) => {
  const account = getAccountById(req.session.accountId);
  if (account.master_verifier) return res.redirect('/dashboard');

  const master = typeof req.body.masterPassword === 'string' ? req.body.masterPassword : '';
  const confirm = typeof req.body.confirmPassword === 'string' ? req.body.confirmPassword : '';

  if (!validMasterPassword(master)) {
    return res.render('master-setup', {
      title: 'Create master password',
      error: 'Use a master password of at least 12 characters.',
    });
  }
  if (master !== confirm) {
    return res.render('master-setup', {
      title: 'Create master password',
      error: 'The two master passwords do not match.',
    });
  }

  const salt = crypto.randomBytes(SALT_BYTES);
  const key = deriveKey(master, salt); // N = 2^15, r = 8, p = 1
  const verifier = createMasterVerifier(key);

  setMaster(account.id, salt.toString('hex'), verifier.toString('hex'));
  req.session.key = key.toString('base64'); // key lives only in server-side session memory
  res.redirect('/dashboard');
});

router.get('/master/unlock', requireAuth, (req, res) => {
  const account = getAccountById(req.session.accountId);
  if (!account.master_verifier) return res.redirect('/master/setup');
  if (req.session.key) return res.redirect('/dashboard');

  res.render('master-unlock', { title: 'Unlock your vault', error: null, email: account.email });
});

router.post('/master/unlock', requireAuth, (req, res) => {
  const account = getAccountById(req.session.accountId);
  const master = typeof req.body.masterPassword === 'string' ? req.body.masterPassword : '';

  if (!account.master_verifier) return res.redirect('/master/setup');

  if (!master || master.length > 128) {
    return res.render('master-unlock', {
      title: 'Unlock your vault', error: 'Enter your master password.', email: account.email,
    });
  }

  const salt = Buffer.from(account.master_salt, 'hex');
  const key = deriveKey(master, salt);

  if (!verifyMasterVerifier(key, account.master_verifier)) {
    return res.render('master-unlock', {
      title: 'Unlock your vault',
      error: 'Master password verification failed. Please try again.',
      email: account.email,
    });
  }

  req.session.key = key.toString('base64');
  res.redirect('/dashboard');
});

module.exports = router;
