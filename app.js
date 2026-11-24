'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');

require('./db/init');
const csrf = require('./middleware/csrf');
const { enforceTimeout, SESSION_TIMEOUT_MS } = require('./middleware/auth');
const { getAccountById, displayName } = require('./services/accounts');

const app = express();
app.disable('x-powered-by');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
  name: 'vg.sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_TIMEOUT_MS,
  },
}));
app.use(enforceTimeout);
app.use(csrf);

// Expose currentUser to all EJS templates
app.use((req, res, next) => {
  if (req.session?.accountId) {
    const account = getAccountById(req.session.accountId);
    if (account) {
      res.locals.currentUser = {
        id: account.id,
        email: account.email,
        name: displayName(account),
      };
    } else {
      res.locals.currentUser = null;
    }
  } else {
    res.locals.currentUser = null;
  }
  next();
});

app.use(require('./routes/auth'));
app.use(require('./routes/master'));
app.use(require('./routes/vault'));

app.use((req, res) => {
  res.status(404).render('error', {
    title: 'Page not found',
    error: 'That page does not exist.',
    back: '/dashboard',
  });
});

module.exports = app;
