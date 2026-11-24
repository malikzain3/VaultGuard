'use strict';

const express = require('express');
const { getAccountByEmail, createAccount, verifyPassword } = require('../services/accounts');
const { openVault } = require('../services/vault');
const { validEmail, validPassword } = require('../services/validation');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

function regenerate(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Render auth page, preserving which tab was active and any error.
 * mode: 'signin' | 'signup'
 */
function renderAuth(res, { error = null, email = '', mode = 'signin', name = '' } = {}) {
  res.render('auth', {
    title: mode === 'signup' ? 'Create account' : 'Sign in',
    error,
    email,
    name,
    mode,
  });
}

const handleGet = (req, res) => {
  res.redirect(req.session?.accountId ? '/dashboard' : '/auth');
};

router.get('/', handleGet);

router.get('/auth', (req, res) => {
  if (req.session?.accountId) return res.redirect('/dashboard');
  const mode = req.query.mode === 'signup' ? 'signup' : 'signin';
  renderAuth(res, { mode });
});

router.post('/auth/signup', async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';

  if (!name) {
    return renderAuth(res, { error: 'Please enter your full name.', email, name, mode: 'signup' });
  }
  if (!validEmail(email) || !validPassword(password)) {
    return renderAuth(res, {
      error: 'Enter a valid email and a password of at least 8 characters.',
      email,
      name,
      mode: 'signup',
    });
  }
  if (getAccountByEmail(email)) {
    return renderAuth(res, {
      error: 'An account with that email already exists. Please sign in.',
      email,
      name,
      mode: 'signup',
    });
  }

  let account;
  try {
    account = createAccount(email, password, name);
    openVault(account.id); // create data/vaults/<id>.db immediately
  } catch (err) {
    if (String(err.code).startsWith('SQLITE_CONSTRAINT')) {
      return renderAuth(res, {
        error: 'An account with that email already exists. Please sign in.',
        email,
        name,
        mode: 'signup',
      });
    }
    throw err;
  }

  await regenerate(req);
  req.session.accountId = account.id;
  res.redirect('/master/setup');
});

router.post('/auth/login', async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!validEmail(email) || !validPassword(password)) {
    return renderAuth(res, { error: 'Enter a valid email and password.', email, mode: 'signin' });
  }

  const account = getAccountByEmail(email);
  if (!account || !verifyPassword(password, account.password_salt, account.password_hash)) {
    return renderAuth(res, { error: 'Invalid email or password.', email, mode: 'signin' });
  }

  await regenerate(req);
  req.session.accountId = account.id;
  delete req.session.key;
  res.redirect(account.master_verifier ? '/master/unlock' : '/master/setup');
});

router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect('/auth'));
});

module.exports = router;
