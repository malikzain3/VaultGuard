'use strict';

function validEmail(value) {
  return typeof value === 'string' && value.trim().length <= 254
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function validPassword(value) {
  return typeof value === 'string' && value.length >= 8 && value.length <= 128;
}

function validMasterPassword(value) {
  return typeof value === 'string' && value.length >= 12 && value.length <= 128;
}

function validText(value, max = 120) {
  return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= max;
}

module.exports = { validEmail, validPassword, validMasterPassword, validText };
