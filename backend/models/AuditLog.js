'use strict';
const mongoose = require('mongoose');

/**
 * AuditLog model
 * Records significant security events: registrations, logins, revocations, recoveries.
 */
const auditLogSchema = new mongoose.Schema({
  userId:       { type: String, required: true, index: true },
  username:     { type: String, default: '' },
  action:       { type: String, required: true }, // e.g. 'REGISTER_PRIMARY', 'LOGIN_PRIMARY', 'RECOVERY', 'REVOKE'
  credentialId: { type: String, default: null },
  credType:     { type: String, default: null },  // 'primary' | 'backup'
  details:      { type: String, default: '' },
  success:      { type: Boolean, default: true },
  timestamp:    { type: Date, default: Date.now }
});

module.exports = mongoose.model('AuditLog', auditLogSchema);
