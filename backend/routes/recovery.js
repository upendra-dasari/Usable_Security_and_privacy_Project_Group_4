'use strict';
const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();

const User           = require('../models/User');
const Credential     = require('../models/Credential');
const AuditLog       = require('../models/AuditLog');
const challengeStore = require('../utils/challengeStore');
const recoveryStore  = require('../utils/recoveryStore');

/** SHA-256 helper */
function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

/** Check UV flag in authenticatorData (bit2 of flags byte at offset 32) */
function checkUVFlag(b64) {
  try {
    const buf = Buffer.from(b64, 'base64url');
    return buf.length >= 33 && (buf[32] & 0x04) !== 0;
  } catch { return false; }
}

/** Verify an ECDSA P-256 signature — tries IEEE P1363 then DER encoding */
function verifySignature(publicKeySpkiB64, signedData, sigBuf) {
  const publicKey = crypto.createPublicKey({
    key:    Buffer.from(publicKeySpkiB64, 'base64'),
    format: 'der',
    type:   'spki'
  });
  try {
    return crypto.verify('SHA256', signedData,
      { key: publicKey, dsaEncoding: 'ieee-p1363' }, sigBuf);
  } catch {
    try { return crypto.verify('SHA256', signedData, publicKey, sigBuf); }
    catch { return false; }
  }
}

// ── POST /recovery/options ─────────────────────────────────────────────────────
// Step 1 of recovery: generate a challenge for backup-key authentication.
// The user proves they own the backup key before they can register a replacement primary.
router.post('/options', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username is required' });

    const uname = username.trim().toLowerCase();
    const user  = await User.findOne({ username: uname });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Must have an active backup key to initiate recovery
    const backupCred = await Credential.findOne({ userId: user.userId, type: 'backup', status: 'active' });
    if (!backupCred) {
      return res.status(404).json({
        error: 'No active backup key is registered for this account. ' +
               'Recovery is not possible without a registered backup key.'
      });
    }

    const challenge = crypto.randomBytes(32).toString('base64url');
    challengeStore.set(`recovery_auth_${uname}`, {
      userId:   user.userId,
      username: uname,
      challenge
    });

    res.json({
      challenge,
      userVerification:  'required',
      backupCredentialId: backupCred.credentialId,
      allowCredentials: [{
        id:     backupCred.credentialId,
        type:   'public-key',
        label:  backupCred.label
      }],
      timeout: 120000
    });
  } catch (err) {
    console.error('recovery/options error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /recovery/verify ──────────────────────────────────────────────────────
// Step 2 of recovery: verify the backup-key signature.
// On success, issues a short-lived single-use recovery token (NOT a full session).
// The user must use this token to register a replacement primary key.
router.post('/verify', async (req, res) => {
  try {
    const { username, credentialId, signature, authenticatorData, clientDataJSON } = req.body;
    if (!username || !credentialId || !signature || !authenticatorData || !clientDataJSON) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const uname = username.trim().toLowerCase();

    const pending = challengeStore.consume(`recovery_auth_${uname}`);
    if (!pending) {
      return res.status(401).json({ error: 'Recovery challenge expired or not found. Please start again.' });
    }

    // Validate clientDataJSON
    let clientData;
    try {
      clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'Invalid clientDataJSON' });
    }

    if (clientData.type !== 'webauthn.get') {
      return res.status(401).json({ error: 'Invalid clientData type' });
    }
    if (clientData.challenge !== pending.challenge) {
      return res.status(401).json({ error: 'Challenge mismatch during recovery' });
    }

    const configuredOrigin = process.env.RP_ORIGIN;
    const dynamicOrigin = req.headers.origin || (req.headers.referer ? new URL(req.headers.referer).origin : null);
    const isValidOrigin = clientData.origin === configuredOrigin ||
                          clientData.origin === dynamicOrigin ||
                          clientData.origin === 'http://localhost:5173';
    if (!isValidOrigin) {
      return res.status(401).json({ error: 'Origin mismatch' });
    }

    // UV must be set even during recovery
    if (!checkUVFlag(authenticatorData)) {
      return res.status(401).json({
        error: 'User verification was required but not performed. Recovery rejected.'
      });
    }

    // Find user and their backup credential (must own this credential)
    const user = await User.findOne({ username: uname });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const backupCred = await Credential.findOne({
      credentialId,
      userId:  user.userId,
      type:   'backup',
      status: 'active'
    });
    if (!backupCred) {
      return res.status(401).json({
        error: 'Invalid backup credential. This credential is not registered as a backup key for this account.'
      });
    }

    // Verify ECDSA signature
    const authDataBuf    = Buffer.from(authenticatorData, 'base64url');
    const clientDataBuf  = Buffer.from(clientDataJSON,    'base64url');
    const signedData     = Buffer.concat([authDataBuf, sha256(clientDataBuf)]);
    const sigBuf         = Buffer.from(signature, 'base64url');

    const verified = verifySignature(backupCred.publicKeySpki, signedData, sigBuf);
    if (!verified) {
      await AuditLog.create({
        userId:   user.userId,
        username: uname,
        action:   'RECOVERY_REJECTED_BAD_SIG',
        credentialId,
        credType: 'backup',
        details:  'Recovery: backup key signature verification failed',
        success:  false
      }).catch(() => {});
      return res.status(401).json({ error: 'Backup key signature verification failed.' });
    }

    // Update backup key lastUsedAt
    backupCred.lastUsedAt = new Date();
    await backupCred.save().catch(() => {});

    // Issue a short-lived single-use recovery token
    const recoveryToken = recoveryStore.create(user.userId, uname);

    await AuditLog.create({
      userId:       user.userId,
      username:     uname,
      action:       'RECOVERY_AUTHORIZED',
      credentialId,
      credType:     'backup',
      details:      'Recovery authorized via backup key. Recovery token issued.',
      success:      true
    }).catch(() => {});

    res.json({
      authorized:    true,
      recoveryToken,
      message:       'Backup key verified. Use the recovery token to register your new primary key. ' +
                     `Token expires in ${(parseInt(process.env.RECOVERY_TOKEN_TTL_SECONDS) || 600) / 60} minutes.`
    });
  } catch (err) {
    console.error('recovery/verify error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /recovery/new-primary/options ────────────────────────────────────────
// Step 3 of recovery: generate a registration challenge for the replacement primary key.
// Requires a valid (not consumed, not expired) recovery token.
router.post('/new-primary/options', async (req, res) => {
  try {
    const { recoveryToken } = req.body;
    const tokenCheck = recoveryStore.verify(recoveryToken);
    if (!tokenCheck.valid) {
      return res.status(401).json({ error: `Recovery authorization invalid: ${tokenCheck.reason}` });
    }

    const { userId, username } = tokenCheck.entry;
    const challenge = crypto.randomBytes(32).toString('base64url');
    challengeStore.set(`recovery_reg_${recoveryToken}`, { userId, username, challenge });

    res.json({
      challenge,
      userId,
      userVerification: 'required',
      rp:   { id: process.env.RP_ID || 'localhost', name: 'USAP FIDO2 Demo' },
      user: { id: userId, name: username, displayName: username }
    });
  } catch (err) {
    console.error('recovery/new-primary/options error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /recovery/new-primary/verify ─────────────────────────────────────────
// Step 4 of recovery: register the replacement primary key, revoke the lost key.
// Consumes the recovery token (single-use guarantee).
router.post('/new-primary/verify', async (req, res) => {
  try {
    const { recoveryToken, credentialId, publicKeySpki, clientDataJSON, registrationAuthData } = req.body;

    if (!recoveryToken || !credentialId || !publicKeySpki || !clientDataJSON) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Consume the recovery token — single-use, this call either succeeds or permanently invalidates the token
    const tokenCheck = recoveryStore.consume(recoveryToken);
    if (!tokenCheck.valid) {
      return res.status(401).json({ error: `Recovery authorization invalid: ${tokenCheck.reason}` });
    }

    const { userId, username } = tokenCheck.entry;

    // Consume the registration challenge
    const pending = challengeStore.consume(`recovery_reg_${recoveryToken}`);
    if (!pending) {
      return res.status(400).json({ error: 'Recovery registration challenge expired. Start the recovery process again.' });
    }

    // Validate clientDataJSON
    let clientData;
    try {
      clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'Invalid clientDataJSON' });
    }

    if (clientData.type !== 'webauthn.create') {
      return res.status(400).json({ error: 'Invalid clientData type for registration' });
    }
    if (clientData.challenge !== pending.challenge) {
      return res.status(400).json({ error: 'Registration challenge mismatch during recovery' });
    }

    const configuredOrigin = process.env.RP_ORIGIN;
    const dynamicOrigin = req.headers.origin || (req.headers.referer ? new URL(req.headers.referer).origin : null);
    const isValidOrigin = clientData.origin === configuredOrigin ||
                          clientData.origin === dynamicOrigin ||
                          clientData.origin === 'http://localhost:5173';
    if (!isValidOrigin) {
      return res.status(400).json({ error: 'Origin mismatch' });
    }

    // UV check on the new key's registration
    if (registrationAuthData && !checkUVFlag(registrationAuthData)) {
      return res.status(400).json({
        error: 'User verification was required but not performed for the new primary key registration.'
      });
    }

    // Credential must be new
    const existingCred = await Credential.findOne({ credentialId });
    if (existingCred) {
      return res.status(409).json({ error: 'This credential ID is already registered' });
    }

    // Revoke ALL existing primary credentials for this user
    const revokedAt = new Date();
    const oldPrimaries = await Credential.find({ userId, type: 'primary', status: 'active' });
    const oldPrimaryIds = oldPrimaries.map(c => c.credentialId);

    await Credential.updateMany(
      { userId, type: 'primary', status: 'active' },
      { $set: { status: 'revoked', revokedAt } }
    );

    // Register the new replacement primary credential
    const newCredential = new Credential({
      userId,
      credentialId,
      publicKeySpki,
      label:  'Primary YubiKey (Replaced via Recovery)',
      type:   'primary',
      status: 'active'
    });
    await newCredential.save();

    // Create a full authenticated session
    const user = await User.findOne({ userId });
    if (user) {
      req.session.userId   = user.userId;
      req.session.username = user.username;
      req.session.email    = user.email;
    }

    // Audit log the full recovery event
    await AuditLog.create({
      userId,
      username,
      action:       'RECOVERY_COMPLETE',
      credentialId,
      credType:     'primary',
      details:      `Recovery complete. Old primary(s) [${oldPrimaryIds.join(', ')}] revoked. New primary registered.`,
      success:      true
    }).catch(() => {});

    res.json({
      verified:         true,
      message:          'Recovery complete. Your new primary key is registered and your old key has been revoked.',
      revokedCredentials: oldPrimaryIds,
      newCredentialId:   credentialId
    });
  } catch (err) {
    console.error('recovery/new-primary/verify error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
