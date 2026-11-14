'use strict';
const express = require('express');
const router  = express.Router();

const Credential = require('../models/Credential');
const AuditLog   = require('../models/AuditLog');

/** Require an active session for all credentials routes */
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

// ── GET /credentials/list ──────────────────────────────────────────────────────
router.get('/list', requireAuth, async (req, res) => {
  try {
    const credentials = await Credential.find({ userId: req.session.userId }).sort({ createdAt: 1 });
    res.json({
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
    console.error('credentials/list error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /credentials/revoke ───────────────────────────────────────────────────
// Revoke a credential. Keeps the record for auditing — does NOT delete it.
// A user cannot revoke their last remaining active credential.
router.post('/revoke', requireAuth, async (req, res) => {
  try {
    const { credentialId } = req.body;
    if (!credentialId) return res.status(400).json({ error: 'credentialId is required' });

    // Credential must belong to this user
    const cred = await Credential.findOne({ credentialId, userId: req.session.userId });
    if (!cred) return res.status(404).json({ error: 'Credential not found or does not belong to you' });

    if (cred.status === 'revoked') {
      return res.status(400).json({ error: 'Credential is already revoked' });
    }

    // Prevent revoking the only active credential
    const activeCreds = await Credential.countDocuments({ userId: req.session.userId, status: 'active' });
    if (activeCreds <= 1) {
      return res.status(400).json({
        error: 'Cannot revoke your only active credential. Register a replacement key first.'
      });
    }

    cred.status    = 'revoked';
    cred.revokedAt = new Date();
    await cred.save();

    await AuditLog.create({
      userId:       req.session.userId,
      username:     req.session.username || '',
      action:       'REVOKE_CREDENTIAL',
      credentialId,
      credType:     cred.type,
      details:      `Credential revoked by user. Label: ${cred.label}`,
      success:      true
    }).catch(() => {});

    res.json({ revoked: true, message: `Credential revoked successfully. It can no longer be used for authentication.` });
  } catch (err) {
    console.error('credentials/revoke error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /credentials/audit-log ─────────────────────────────────────────────────
router.get('/audit-log', requireAuth, async (req, res) => {
  try {
    const logs = await AuditLog.find({ userId: req.session.userId })
      .sort({ timestamp: -1 })
      .limit(50);
    res.json({ logs });
  } catch (err) {
    console.error('credentials/audit-log error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
