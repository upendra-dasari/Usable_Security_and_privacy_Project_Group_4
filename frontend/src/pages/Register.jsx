import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { generateCredential } from '../simulator/yubikeySimulator';
import { api } from '../utils/api';

/** Encode a string to base64url */
function toBase64url(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

const STAGES = {
  FORM:    'FORM',       // username / email entry
  PRIMARY: 'PRIMARY',   // registering primary key
  BACKUP:  'BACKUP',    // registering backup key
  DONE:    'DONE'       // both keys registered
};

export default function Register() {
  const [username, setUsername] = useState('');
  const [email,    setEmail]    = useState('');
  const [stage,    setStage]    = useState(STAGES.FORM);
  const [status,   setStatus]   = useState(null);  // null | 'loading' | 'success' | 'error'
  const [message,  setMessage]  = useState('');
  const [userId,   setUserId]   = useState(null);  // needed for backup registration
  const navigate = useNavigate();

  // ── Stage 1: Register Primary Key ──────────────────────────────────────────
  const handlePrimaryRegister = async (e) => {
    e.preventDefault();
    setStatus('loading');
    setMessage('');

    try {
      // Step 1: Get registration challenge from server
      setMessage('Step 1/5 — Requesting registration challenge from server...');
      const options = await api.post('/register/options', {
        username: username.trim(),
        email:    email.trim()
      });

      // Step 2: Generate ECDSA P-256 key pair in simulated YubiKey
      setMessage('Step 2/5 — Generating ECDSA P-256 key pair in simulated YubiKey...');
      const { credentialId, publicKeySpki, registrationAuthData } = await generateCredential();

      // Step 3: Build clientDataJSON (mirrors WebAuthn spec)
      const clientData = {
        type:        'webauthn.create',
        challenge:   options.challenge,
        origin:      window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = toBase64url(JSON.stringify(clientData));

      // Step 4: Send registration response to server
      setMessage('Step 3/5 — Verifying registration on server (UV flag check)...');
      const result = await api.post('/register/verify', {
        username:            username.trim(),
        email:               email.trim(),
        credentialId,
        publicKeySpki,
        clientDataJSON,
        registrationAuthData,  // backend checks UV flag
        attestationData:       'simulated-educational-demo'
      });

      setUserId(result.userId);
      setStage(STAGES.BACKUP);
      setStatus('success');
      setMessage('✅ Primary key registered! Now register your backup key.');

    } catch (err) {
      setStatus('error');
      setMessage(err.message);
    }
  };

  // ── Stage 2: Register Backup Key ───────────────────────────────────────────
  const handleBackupRegister = async () => {
    setStatus('loading');
    setMessage('');

    try {
      // Step 1: Get backup registration challenge
      setMessage('Step 1/4 — Requesting backup key registration challenge...');
      const options = await api.post('/register/backup/options', {});

      // Step 2: Generate a NEW, independent key pair for the backup
      setMessage('Step 2/4 — Generating new ECDSA P-256 key pair for backup key...');
      const { credentialId, publicKeySpki, registrationAuthData } = await generateCredential();

      // Step 3: Build clientDataJSON
      const clientData = {
        type:        'webauthn.create',
        challenge:   options.challenge,
        origin:      window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = toBase64url(JSON.stringify(clientData));

      // Step 4: Send backup registration response
      setMessage('Step 3/4 — Verifying backup key on server...');
      const result = await api.post('/register/backup/verify', {
        credentialId,
        publicKeySpki,
        clientDataJSON,
        registrationAuthData
      });

      setStage(STAGES.DONE);
      setStatus('success');
      setMessage(result.message);

    } catch (err) {
      setStatus('error');
      setMessage(err.message);
    }
  };

  const handleSkipBackup = () => {
    setStage(STAGES.DONE);
    setStatus('error');
    setMessage('⚠️ Backup key not registered. Your account has limited recovery options.');
  };

  // ── Render: account details form ───────────────────────────────────────────
  if (stage === STAGES.FORM) {
    return (
      <div className="page-container">
        <div className="card">
          <div className="sim-badge">⚠️ Educational Simulation — Not a real YubiKey</div>
          <h1>🔐 Register</h1>
          <p className="subtitle">Create your passwordless account with a Primary and Backup simulated YubiKey</p>

          <div className="stage-indicator">
            <div className="stage-step active">1. Account Details</div>
            <div className="stage-sep">→</div>
            <div className="stage-step">2. Primary Key</div>
            <div className="stage-sep">→</div>
            <div className="stage-step">3. Backup Key</div>
          </div>

          <form onSubmit={handlePrimaryRegister}>
            <div className="form-group">
              <label>Username</label>
              <input type="text" value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="e.g. alice" required autoComplete="username" />
            </div>
            <div className="form-group">
              <label>Email Address</label>
              <input type="email" value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="e.g. alice@example.com" required />
            </div>
            <button type="submit" className="btn-primary"
              disabled={status === 'loading'}>
              {status === 'loading' ? '⏳ Registering...' : '🔑 Register Primary Key'}
            </button>
          </form>

          {status === 'loading' && <div className="status-info">🔄 {message}</div>}
          {status === 'error'   && <div className="status-error">❌ {message}</div>}

          <div className="info-box">
            <h3>📖 Two-Key Enrollment Process</h3>
            <ol>
              <li>Enter your username and email address</li>
              <li><strong>Stage 1:</strong> Register your Primary YubiKey (simulated) — touch + PIN verification</li>
              <li><strong>Stage 2:</strong> Register your Backup YubiKey — an independent key pair</li>
              <li>Server stores only public keys — private keys never leave the simulator</li>
            </ol>
          </div>
        </div>
      </div>
    );
  }

  // ── Render: backup key registration ────────────────────────────────────────
  if (stage === STAGES.BACKUP) {
    return (
      <div className="page-container">
        <div className="card">
          <div className="sim-badge">⚠️ Educational Simulation — Stage 2 of 2</div>
          <h1>🔑 Register Backup Key</h1>

          <div className="stage-indicator">
            <div className="stage-step done">1. Account Details ✓</div>
            <div className="stage-sep">→</div>
            <div className="stage-step done">2. Primary Key ✓</div>
            <div className="stage-sep">→</div>
            <div className="stage-step active">3. Backup Key</div>
          </div>

          <div className="status-success">✅ Primary key registered for <strong>{username}</strong></div>

          <div className="info-box" style={{ marginTop: 20 }}>
            <h3>🛡️ Why Register a Backup Key?</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: 8 }}>
              If you lose your primary YubiKey, you can still recover your account using the backup key.
              The backup key uses a completely separate key pair — it is not a copy of the primary key.
            </p>
          </div>

          <p style={{ color: 'var(--text-muted)', margin: '20px 0 8px', fontSize: '0.9rem' }}>
            Connect your second (backup) simulated YubiKey and click the button below.
            A new independent key pair will be generated for it.
          </p>

          {status === 'loading' && <div className="status-info">🔄 {message}</div>}
          {status === 'error'   && <div className="status-error">❌ {message}</div>}

          <button className="btn-primary" onClick={handleBackupRegister}
            disabled={status === 'loading'} style={{ marginTop: 16 }}>
            {status === 'loading' ? '⏳ Registering Backup...' : '🔑 Register Backup Key'}
          </button>

          <button className="btn-secondary" onClick={handleSkipBackup}
            disabled={status === 'loading'}
            style={{ marginTop: 10, width: '100%', padding: '12px' }}>
            Skip for now (not recommended)
          </button>
        </div>
      </div>
    );
  }

  // ── Render: registration complete ─────────────────────────────────────────
  return (
    <div className="page-container">
      <div className="card" style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 64, marginBottom: 16 }}>🎉</div>
        <h1 style={{ color: 'var(--success)' }}>Registration Complete</h1>
        <div className="status-success" style={{ marginTop: 20 }}>{message}</div>
        <p style={{ color: 'var(--text-muted)', marginTop: 16, fontSize: '0.9rem' }}>
          You have registered both a primary and backup key.<br />
          Your account is fully protected with two-factor FIDO2 authentication.
        </p>
        <button className="btn-primary" onClick={() => navigate('/login')}
          style={{ marginTop: 24 }}>
          → Go to Login
        </button>
      </div>
    </div>
  );
}
