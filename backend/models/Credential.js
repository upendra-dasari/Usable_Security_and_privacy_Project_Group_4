'use strict';
const mongoose = require('mongoose');

/**
 * Credential model
 * Stores a registered FIDO2 public key credential for a user.
 * publicKeySpki: base64-encoded DER/SPKI public key (ECDSA P-256).
 * The corresponding private key lives in the client's simulated YubiKey ONLY.
 * Private keys are NEVER stored here.
 */
const credentialSchema = new mongoose.Schema({
  userId:        { type: String, required: true, index: true },
  credentialId:  { type: String, required: true, unique: true },
  publicKeySpki: { type: String, required: true }, // base64-encoded SPKI DER public key
  label:         { type: String, default: 'Primary YubiKey (Simulated)' },
  type:          { type: String, enum: ['primary', 'backup'], default: 'primary' },
  status:        { type: String, enum: ['active', 'revoked'], default: 'active' },
  signCount:     { type: Number, default: 0 },
  createdAt:     { type: Date, default: Date.now },
  lastUsedAt:    { type: Date, default: null },
  revokedAt:     { type: Date, default: null }
});

module.exports = mongoose.model('Credential', credentialSchema);
