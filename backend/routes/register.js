'use strict';
const express = require('express');
const crypto  = require('crypto');
const { v4: uuidv4 } = require('uuid');
const router  = express.Router();

const User           = require('../models/User');
const Credential     = require('../models/Credential');
const AuditLog       = require('../models/AuditLog');
const challengeStore = require('../utils/challengeStore');

// ── UV flag helper ─────────────────────────────────────────────────────────────
/**
 * Parse the user-verification flag from authenticatorData.
 * authenticatorData structure: rpIdHash(32) | flags(1) | signCount(4) | ...
 * flags bit2 = UV (User Verified), bit0 = UP (User Present)
 */
function checkUVFlag(authenticatorDataB64) {
  try {
    const buf = Buffer.from(authenticatorDataB64, 'base64url');
    if (buf.length < 33) return false;
    return (buf[32] & 0x04) !== 0; // bit2 = UV
  } catch { return false; }
}

// ── POST /register/options ─────────────────────────────────────────────────────
// Generates a registration challenge for a brand-new user (Stage 1 — Primary key).
router.post('/options', async (req, res) => {
  try {
    const { username, email } = req.body;
    if (!username || !email) {
      return res.status(400).json({ error: 'Username and email are required' });
    }

    const uname  = username.trim().toLowerCase();
    const uemail = email.trim().toLowerCase();

    // Reject if username or email is already taken
    const existingUser = await User.findOne({ $or: [{ username: uname }, { email: uemail }] });
    if (existingUser) {
      return res.status(409).json({ error: 'Username or email already registered' });
    }

    const userId    = uuidv4();
    const challenge = crypto.randomBytes(32).toString('base64url');

    challengeStore.set(`reg_${uname}`, { userId, username: uname, email: uemail, challenge });

    res.json({
      challenge,
      userId,
      username: uname,
      rp:   { id: process.env.RP_ID || 'localhost', name: 'USAP FIDO2 Demo' },
      user: { id: userId, name: uname, displayName: uname },
      userVerification: 'required'
    });
  } catch (err) {
    console.error('register/options error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /register/verify ──────────────────────────────────────────────────────
// Validates the primary registration response and saves user + primary credential.
// Sets req.session.pendingBackupFor so the same session can register a backup key.
router.post('/verify', async (req, res) => {
  try {
    const { username, email, credentialId, publicKeySpki, clientDataJSON,
            registrationAuthData, attestationData } = req.body;

    if (!username || !credentialId || !publicKeySpki || !clientDataJSON) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const uname = username.trim().toLowerCase();

    // Consume the pending challenge
    const pending = challengeStore.consume(`reg_${uname}`);
    if (!pending) {
      return res.status(400).json({
        error: 'Registration challenge expired or not found. Please restart registration.'
      });
    }

    // Parse and validate clientDataJSON
    let clientData;
    try {
      clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'Invalid clientDataJSON' });
    }

    if (clientData.type !== 'webauthn.create') {
      return res.status(400).json({ error: 'Invalid clientData type (expected webauthn.create)' });
    }
    if (clientData.challenge !== pending.challenge) {
      return res.status(400).json({ error: 'Challenge mismatch' });
    }

    const configuredOrigin = process.env.RP_ORIGIN;
    const dynamicOrigin = req.headers.origin || (req.headers.referer ? new URL(req.headers.referer).origin : null);
    const isValidOrigin = clientData.origin === configuredOrigin ||
                          clientData.origin === dynamicOrigin ||
                          clientData.origin === 'http://localhost:5173';
    if (!isValidOrigin) {
      return res.status(400).json({
        error: `Origin mismatch — expected ${configuredOrigin || dynamicOrigin}, got ${clientData.origin}`
      });
    }

    // ── UV flag check ──────────────────────────────────────────────────────────
    // User verification is required. The authenticatorData must have UV bit set.
    if (registrationAuthData) {
      const uvFlag = checkUVFlag(registrationAuthData);
      if (!uvFlag) {
        return res.status(400).json({
          error: 'User verification was required but not performed by the authenticator. ' +
                 'Registration rejected. (UV flag not set in authenticatorData)'
        });
      }
    }

    // Ensure credential is not already registered
    const existingCred = await Credential.findOne({ credentialId });
    if (existingCred) {
      return res.status(409).json({ error: 'Credential already registered' });
    }

    // Persist user and PRIMARY credential
    const uemail = email ? email.trim().toLowerCase() : pending.email;
    const user   = new User({ userId: pending.userId, username: uname, email: uemail });
    await user.save();

    const credential = new Credential({
      userId:        pending.userId,
      credentialId,
      publicKeySpki,
      label:         'Primary YubiKey (Simulated)',
      type:          'primary',
      status:        'active'
    });
    await credential.save();

    // Allow the same session to register a backup key immediately after
    req.session.pendingBackupFor = pending.userId;
    req.session.pendingBackupUsername = uname;

    // Audit log
    await AuditLog.create({
      userId:       pending.userId,
      username:     uname,
      action:       'REGISTER_PRIMARY',
      credentialId,
      credType:     'primary',
      details:      'Primary YubiKey registered successfully',
      success:      true
    }).catch(() => {});

    res.json({
      verified:    true,
      message:     'Primary simulated YubiKey registered. This is an educational demonstration.',
      userId:      pending.userId,
      needsBackup: true  // signal to frontend to show Stage 2
    });
  } catch (err) {
    console.error('register/verify error:', err);
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Username or email already taken' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /register/backup/options ──────────────────────────────────────────────
// Generates a registration challenge for adding a backup key.
// Requires either session.pendingBackupFor (right after primary reg) OR session.userId (logged-in user).
router.post('/backup/options', async (req, res) => {
  try {
    // Allow from: (a) post-primary-registration session, (b) logged-in user
    const userId   = req.session.pendingBackupFor || req.session.userId;
    const username = req.session.pendingBackupUsername || req.session.username;

    if (!userId) {
      return res.status(401).json({
        error: 'Not authorized to register a backup key. Please complete primary registration or log in first.'
      });
    }

    // Check no active backup already exists for this user (unless overriding a revoked one)
    const existingBackup = await Credential.findOne({ userId, type: 'backup', status: 'active' });
    if (existingBackup) {
      return res.status(409).json({
        error: 'An active backup key is already registered. Revoke the existing backup key first.'
      });
    }

    const challenge = crypto.randomBytes(32).toString('base64url');
    challengeStore.set(`backup_${userId}`, { userId, username, challenge });

    res.json({
      challenge,
      userId,
      rp:   { id: process.env.RP_ID || 'localhost', name: 'USAP FIDO2 Demo' },
      user: { id: userId, name: username, displayName: username },
      userVerification: 'required'
    });
  } catch (err) {
    console.error('register/backup/options error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /register/backup/verify ───────────────────────────────────────────────
// Validates backup registration and saves backup credential.
router.post('/backup/verify', async (req, res) => {
  try {
    const { credentialId, publicKeySpki, clientDataJSON, registrationAuthData } = req.body;

    const userId   = req.session.pendingBackupFor || req.session.userId;
    const username = req.session.pendingBackupUsername || req.session.username;

    if (!userId) {
      return res.status(401).json({ error: 'Not authorized to register a backup key.' });
    }
    if (!credentialId || !publicKeySpki || !clientDataJSON) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const pending = challengeStore.consume(`backup_${userId}`);
    if (!pending) {
      return res.status(400).json({
        error: 'Backup registration challenge expired or not found. Please restart.'
      });
    }

    // Parse and validate clientDataJSON
    let clientData;
    try {
      clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'Invalid clientDataJSON' });
    }

    if (clientData.type !== 'webauthn.create') {
      return res.status(400).json({ error: 'Invalid clientData type (expected webauthn.create)' });
    }
    if (clientData.challenge !== pending.challenge) {
      return res.status(400).json({ error: 'Backup registration challenge mismatch' });
    }

    const configuredOrigin = process.env.RP_ORIGIN;
    const dynamicOrigin = req.headers.origin || (req.headers.referer ? new URL(req.headers.referer).origin : null);
    const isValidOrigin = clientData.origin === configuredOrigin ||
                          clientData.origin === dynamicOrigin ||
                          clientData.origin === 'http://localhost:5173';
    if (!isValidOrigin) {
      return res.status(400).json({ error: `Origin mismatch — expected ${configuredOrigin || dynamicOrigin}` });
    }

    // UV flag check
    if (registrationAuthData) {
      const uvFlag = checkUVFlag(registrationAuthData);
      if (!uvFlag) {
        return res.status(400).json({
          error: 'User verification was required but not performed for backup key registration.'
        });
      }
    }

    // Credential must be unique
    const existingCred = await Credential.findOne({ credentialId });
    if (existingCred) {
      return res.status(409).json({ error: 'This credential ID is already registered' });
    }

    const credential = new Credential({
      userId,
      credentialId,
      publicKeySpki,
      label:  'Backup YubiKey (Simulated)',
      type:   'backup',
      status: 'active'
    });
    await credential.save();

    // Clear the pending backup session
    delete req.session.pendingBackupFor;
    delete req.session.pendingBackupUsername;

    await AuditLog.create({
      userId,
      username: username || '',
      action:       'REGISTER_BACKUP',
      credentialId,
      credType:     'backup',
      details:      'Backup YubiKey registered successfully',
      success:      true
    }).catch(() => {});

    res.json({
      verified: true,
      message:  'Backup YubiKey registered successfully. Your account now has two-key protection.'
    });
  } catch (err) {
    console.error('register/backup/verify error:', err);
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Credential already registered' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
