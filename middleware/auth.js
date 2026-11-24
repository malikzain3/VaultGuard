'use strict';

const { getAccountById, displayName } = require('../services/accounts');

const SESSION_TIMEOUT_MS = 15 * 60 * 1000;

function enforceTimeout(req, res, next) {
  if (req.session?.accountId) {
    const now = Date.now();
    if (now - (req.session.lastActivity || now) > SESSION_TIMEOUT_MS) {
      delete req.session.key; // forget the derived master key after inactivity
    }
    req.session.lastActivity = now;
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.session?.accountId) return res.redirect('/auth');
  next();
}

function requireMaster(req, res, next) {
  const account = getAccountById(req.session.accountId);
  if (!account) {
    return req.session.destroy(() => res.redirect('/auth'));
  }
  if (!account.master_verifier) return res.redirect('/master/setup');
  if (!req.session.key) return res.redirect('/master/unlock');

  res.locals.account = {
    id: account.id,
    email: account.email,
    name: displayName(account),
  };
  next();
}

module.exports = { enforceTimeout, requireAuth, requireMaster, SESSION_TIMEOUT_MS };
