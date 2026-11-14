'use strict';
const mongoose = require('mongoose');

/**
 * User model
 * Represents a registered user account.
 * No password field — authentication is done via FIDO2 credentials.
 */
const userSchema = new mongoose.Schema({
  userId:    { type: String, required: true, unique: true },
  username:  { type: String, required: true, unique: true, trim: true, lowercase: true },
  email:     { type: String, required: true, unique: true, trim: true, lowercase: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
