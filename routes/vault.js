'use strict';

const express = require('express');
const { addEntry, listEntries, revealEntry } = require('../services/vault');
const { validText } = require('../services/validation');
const { requireAuth, requireMaster } = require('../middleware/auth');

const router = express.Router();

function renderDashboard(req, res, extra = {}) {
  res.render('dashboard', {
    title: 'Your vault',
    email: res.locals.account.email,
    entries: listEntries(req.session.accountId),
    revealed: null,
    error: null,
    saved: req.query.saved === '1',
    ...extra,
  });
}

router.get('/dashboard', requireAuth, requireMaster, (req, res) => {
  renderDashboard(req, res);
});

router.post('/entries', requireAuth, requireMaster, (req, res) => {
  const appName = typeof req.body.appName === 'string' ? req.body.appName.trim() : '';
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!validText(appName, 100) || !validText(username, 200) || !validText(password, 200)) {
    return renderDashboard(req, res, {
      error: 'Fill in the application name, username and password (max 200 characters each).',
    });
  }

  const key = Buffer.from(req.session.key, 'base64');
  addEntry(req.session.accountId, key, { appName, username, password });
  res.redirect('/dashboard?saved=1');
});

router.post('/entries/:id/reveal', requireAuth, requireMaster, (req, res) => {
  if (!/^\d+$/.test(req.params.id)) {
    return renderDashboard(req, res, { error: 'Invalid entry.' });
  }

  const key = Buffer.from(req.session.key, 'base64');
  try {
    const revealed = revealEntry(req.session.accountId, key, Number(req.params.id));
    if (!revealed) return renderDashboard(req, res, { error: 'Entry not found.' });
    renderDashboard(req, res, { revealed });
  } catch (err) {
    if (err.code === 'INTEGRITY_FAILED') {
      // No plaintext is rendered when authentication fails.
      return renderDashboard(req, res, { error: 'Data integrity check failed' });
    }
    throw err;
  }
});

module.exports = router;
