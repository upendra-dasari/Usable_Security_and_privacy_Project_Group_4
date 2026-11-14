'use strict';
require('dotenv').config();

/**
 * challengeStore.js
 * In-memory store for pending FIDO2 challenges.
 * Each entry: { userId, challenge, expiresAt, consumed }
 * Challenges are keyed by a session key (e.g. "reg_alice" or "auth_alice").
 * They automatically expire after CHALLENGE_TTL_SECONDS seconds.
 */

const TTL_MS = (parseInt(process.env.CHALLENGE_TTL_SECONDS) || 120) * 1000;

const store = new Map();

/**
 * Store a new challenge entry under the given key.
 * Any previous entry for the same key is overwritten.
 */
function set(key, data) {
  store.set(key, { ...data, expiresAt: Date.now() + TTL_MS, consumed: false });
}

/**
 * Retrieve a challenge entry without consuming it.
 * Returns null if not found or expired.
 */
function get(key) {
  const entry = store.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    store.delete(key);
    return null;
  }
  return entry;
}

/**
 * Retrieve and consume a challenge entry (one-time use).
 * Returns null if not found, expired, or already consumed.
 * Deletes the entry from the store after consumption.
 */
function consume(key) {
  const entry = get(key);
  if (!entry) return null;
  if (entry.consumed) {
    store.delete(key);
    return null;
  }
  entry.consumed = true;
  store.delete(key); // remove immediately after consumption
  return entry;
}

/**
 * Remove all expired entries from the store.
 * Called periodically to prevent memory leaks.
 */
function cleanup() {
  const now = Date.now();
  for (const [k, v] of store.entries()) {
    if (now > v.expiresAt) store.delete(k);
  }
}

// Run cleanup every 60 seconds
setInterval(cleanup, 60000);

module.exports = { set, get, consume };
