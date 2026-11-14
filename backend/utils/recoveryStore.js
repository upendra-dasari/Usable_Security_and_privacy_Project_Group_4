'use strict';
require('dotenv').config();
const { v4: uuidv4 } = require('uuid');

/**
 * recoveryStore.js
 * In-memory store for single-use, short-lived recovery authorization tokens.
 * Issued after a user successfully authenticates with their backup key.
 * Required to register a replacement primary key.
 */

const RECOVERY_TTL_MS = (parseInt(process.env.RECOVERY_TOKEN_TTL_SECONDS) || 600) * 1000;
const store = new Map(); // token -> { userId, username, expiresAt, consumed }

/** Create a new recovery token for the given user. Returns the token string. */
function create(userId, username) {
  const token     = uuidv4();
  const expiresAt = Date.now() + RECOVERY_TTL_MS;
  store.set(token, { userId, username, expiresAt, consumed: false });
  return token;
}

/** Verify a token without consuming it. Returns { valid, entry, reason }. */
function verify(token) {
  if (!token) return { valid: false, reason: 'Recovery token not provided.' };
  const entry = store.get(token);
  if (!entry)         return { valid: false, reason: 'Recovery token not found or expired.' };
  if (entry.consumed) { store.delete(token); return { valid: false, reason: 'Recovery token already used (single-use).' }; }
  if (Date.now() > entry.expiresAt) { store.delete(token); return { valid: false, reason: 'Recovery token expired.' }; }
  return { valid: true, entry };
}

/** Verify and consume (single-use). Returns { valid, entry, reason }. */
function consume(token) {
  const result = verify(token);
  if (!result.valid) return result;
  store.delete(token); // remove immediately — single-use guarantee
  return { valid: true, entry: result.entry };
}

/** Periodic cleanup of stale entries. */
function cleanup() {
  const now = Date.now();
  for (const [k, v] of store.entries()) {
    if (now > v.expiresAt || v.consumed) store.delete(k);
  }
}
setInterval(cleanup, 60000);

module.exports = { create, verify, consume };
