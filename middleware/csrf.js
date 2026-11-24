'use strict';

const crypto = require('node:crypto');

// Double-submit CSRF token tied to the server-side session (no extra package).
function csrf(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;

  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const supplied = typeof req.body?._csrf === 'string' ? req.body._csrf : '';
  const a = Buffer.from(supplied);
  const b = Buffer.from(req.session.csrfToken);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).render('error', {
      title: 'Request rejected',
      error: 'Your security token was missing or invalid. Please reload the page and try again.',
      back: '/dashboard',
    });
  }

  return next();
}

module.exports = csrf;
