'use strict';
require('dotenv').config();

const express  = require('express');
const cors     = require('cors');
const session  = require('express-session');
const mongoose = require('mongoose');

const registerRouter    = require('./routes/register');
const loginRouter       = require('./routes/login');
const recoveryRouter    = require('./routes/recovery');
const credentialsRouter = require('./routes/credentials');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── CORS ───────────────────────────────────────────────────────────────────────
app.use(cors({
  origin:      true,
  credentials: true
}));

app.use(express.json());

// ── Session ────────────────────────────────────────────────────────────────────
app.use(session({
  secret:            process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   false,         // set to true in production with HTTPS
    maxAge:   1000 * 60 * 60 * 24 // 24 hours
  }
}));

// ── Routes ─────────────────────────────────────────────────────────────────────
app.use('/register',    registerRouter);
app.use('/login',       loginRouter);
app.use('/recovery',    recoveryRouter);
app.use('/credentials', credentialsRouter);

// Health-check endpoint
app.get('/health', (_req, res) =>
  res.json({ status: 'ok', time: new Date().toISOString() })
);

// ── MongoDB ────────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/usap_fido2')
  .then(() => {
    console.log('✅ Connected to MongoDB');
    app.listen(PORT, () =>
      console.log(`🔐 USAP FIDO2 backend running on http://localhost:${PORT}`)
    );
  })
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

module.exports = app;
