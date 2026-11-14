'use strict';
const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();

const User           = require('../models/User');
const Credential     = require('../models/Credential');
const AuditLog       = require('../models/AuditLog');
const challengeStore = require('../utils/challengeStore');

/** SHA-256 helper */
function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

/**
 * Parse UV flag from authenticatorData.
 * authenticatorData: rpIdHash(32) | flags(1) | signCount(4) | ...
 * flags bit2 = UV (User Verified)
 */
function checkUVFlag(authenticatorDataB64) {
  try {
    const buf = Buffer.from(authenticatorDataB64, 'base64url');
    if (buf.length < 33) return false;
    return (buf[32] & 0x04) !== 0;
  } catch { return false; }
}

// ── POST /login/options ────────────────────────────────────────────────────────
// Returns a fresh challenge and all active credentials with their types (primary/backup).
router.post('/options', async (req, res) => {
  try {
    const { username, keyType } = req.body;
    if (!username) return res.status(400).json({ error: 'Username is required' });

    const uname = username.trim().toLowerCase();
    const user  = await User.findOne({ username: uname });
    if (!user) return res.status(404).json({ error: 'User not found. Please register first.' });

    // Build credential list — optionally filtered by keyType ('primary' | 'backup')
    const filter = { userId: user.userId, status: 'active' };
    if (keyType && ['primary', 'backup'].includes(keyType)) filter.type = keyType;

    const credentials = await Credential.find(filter);
    if (!credentials.length) {
      const msg = keyType
        ? `No active ${keyType} key found for this user.`
        : 'No active credentials found for this user.';
      return res.status(404).json({ error: msg });
    }

    const challenge = crypto.randomBytes(32).toString('base64url');
    challengeStore.set(`auth_${uname}`, { userId: user.userId, username: uname, challenge });

    res.json({
      challenge,
      userVerification:  'required',
      allowCredentials:  credentials.map(c => ({
        id:     c.credentialId,
        type:   'public-key',
        label:  c.label,
        credType: c.type,   // 'primary' | 'backup'
        status: c.status
      })),
      timeout: 120000
    });
  } catch (err) {
    console.error('login/options error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /login/verify ─────────────────────────────────────────────────────────
// Validates the signed assertion.
//  1. Consumes the challenge (one-time use — prevents replay attacks)
//  2. Verifies clientData type, challenge, and origin
//  3. Checks UV flag in authenticatorData (user verification required)
//  4. Looks up the credential and checks it is active
//  5. Verifies ECDSA P-256 signature against the stored public key
//  6. Creates a session on success
router.post('/verify', async (req, res) => {
  try {
    const { username, credentialId, signature, authenticatorData, clientDataJSON } = req.body;
    if (!username || !credentialId || !signature || !authenticatorData || !clientDataJSON) {
      return res.status(400).json({ error: 'Missing required authentication fields' });
    }

    const uname = username.trim().toLowerCase();

    // Consume the pending challenge — any subsequent replay will fail here
    const pending = challengeStore.consume(`auth_${uname}`);
    if (!pending) {
      return res.status(401).json({
        error: 'Authentication challenge expired or not found. Please try again.'
      });
    }

    // Parse clientDataJSON
    let clientData;
    try {
      clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'Invalid clientDataJSON' });
    }

    if (clientData.type !== 'webauthn.get') {
      return res.status(401).json({ error: 'Invalid clientData type (expected webauthn.get)' });
    }

    if (clientData.challenge !== pending.challenge) {
      return res.status(401).json({
        error: 'Challenge mismatch',
        detail: 'The response was created for a different challenge — possible replay attack detected.'
      });
    }

    const configuredOrigin = process.env.RP_ORIGIN;
    const dynamicOrigin = req.headers.origin || (req.headers.referer ? new URL(req.headers.referer).origin : null);
    const isValidOrigin = clientData.origin === configuredOrigin ||
                          clientData.origin === dynamicOrigin ||
                          clientData.origin === 'http://localhost:5173';
    if (!isValidOrigin) {
      return res.status(401).json({ error: 'Origin mismatch' });
    }

    // ── UV flag check ──────────────────────────────────────────────────────────
    // User verification is REQUIRED. Backend enforces this independently of the frontend.
    // The UV bit (bit2) must be set in the authenticatorData flags byte.
    const uvFlag = checkUVFlag(authenticatorData);
    if (!uvFlag) {
      await AuditLog.create({
        userId:   pending.userId,
        username: uname,
        action:   'LOGIN_REJECTED_NO_UV',
        credentialId,
        details:  'UV flag not set in authenticatorData — user verification required',
        success:  false
      }).catch(() => {});
      return res.status(401).json({
        error: 'User verification was required but not performed by the authenticator. ' +
               'Authentication rejected. (UV flag bit2 not set in authenticatorData)'
      });
    }

    // Look up user and credential (credential must belong to this user and be active)
    const user = await User.findOne({ username: uname });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const cred = await Credential.findOne({
      credentialId,
      userId:  user.userId,
      status: 'active'
    });
    if (!cred) {
      await AuditLog.create({
        userId:   user.userId,
        username: uname,
        action:   'LOGIN_REJECTED_BAD_CRED',
        credentialId,
        details:  'Unknown or revoked credential',
        success:  false
      }).catch(() => {});
      return res.status(401).json({ error: 'Unknown or revoked credential' });
    }

    // Reconstruct signed data: authenticatorData_bytes || sha256(clientDataJSON_bytes)
    const authDataBuf    = Buffer.from(authenticatorData, 'base64url');
    const clientDataBuf  = Buffer.from(clientDataJSON,    'base64url');
    const clientDataHash = sha256(clientDataBuf);
    const signedData     = Buffer.concat([authDataBuf, clientDataHash]);

    // Import stored public key (DER/SPKI, base64)
    const publicKey = crypto.createPublicKey({
      key:    Buffer.from(cred.publicKeySpki, 'base64'),
      format: 'der',
      type:   'spki'
    });

    const sigBuf = Buffer.from(signature, 'base64url');

    let verified = false;
    try {
      // Web Crypto produces IEEE P1363 (raw r||s, 64 bytes for P-256)
      verified = crypto.verify('SHA256', signedData,
        { key: publicKey, dsaEncoding: 'ieee-p1363' }, sigBuf);
    } catch {
      try {
        // Fallback: DER-encoded signature (some environments)
        verified = crypto.verify('SHA256', signedData, publicKey, sigBuf);
      } catch {
        verified = false;
      }
    }

    if (!verified) {
      await AuditLog.create({
        userId:   user.userId,
        username: uname,
        action:   'LOGIN_REJECTED_BAD_SIG',
        credentialId,
        credType: cred.type,
        details:  'ECDSA signature verification failed',
        success:  false
      }).catch(() => {});
      return res.status(401).json({ error: 'Signature verification failed. Invalid credential.' });
    }

    // Update lastUsedAt
    cred.lastUsedAt = new Date();
    await cred.save().catch(() => {});

    // Audit success
    await AuditLog.create({
      userId:       user.userId,
      username:     uname,
      action:       `LOGIN_${(cred.type || 'primary').toUpperCase()}`,
      credentialId,
      credType:     cred.type,
      details:      `Successful login with ${cred.label}`,
      success:      true
    }).catch(() => {});

    // Create server-side session
    req.session.userId   = user.userId;
    req.session.username = user.username;
    req.session.email    = user.email;

    res.json({
      verified: true,
      message:  'Authentication successful',
      user:     { username: user.username, email: user.email, userId: user.userId }
    });
  } catch (err) {
    console.error('login/verify error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /login/logout ──────────────────────────────────────────────────────────
router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Logged out successfully' });
  });
});

// ── GET /login/profile ─────────────────────────────────────────────────────────
// Returns the authenticated user's profile and all credentials.
router.get('/profile', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const user = await User.findOne({ userId: req.session.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const credentials = await Credential.find({ userId: user.userId });

    res.json({
      user: {
        userId:    user.userId,
        username:  user.username,
        email:     user.email,
        createdAt: user.createdAt
      },
      credentials: credentials.map(c => ({
        credentialId: c.credentialId,
        label:        c.label,
        type:         c.type || 'primary',
        status:       c.status,
        createdAt:    c.createdAt,
        lastUsedAt:   c.lastUsedAt,
        revokedAt:    c.revokedAt
      }))
    });
  } catch (err) {
    console.error('login/profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
