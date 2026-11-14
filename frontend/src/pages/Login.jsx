import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { signChallenge } from '../simulator/yubikeySimulator';
import { api } from '../utils/api';

export default function Login() {
  const [username,    setUsername]    = useState('');
  const [credentials, setCredentials] = useState(null); // array from /login/options
  const [challenge,   setChallenge]   = useState('');
  const [status,      setStatus]      = useState(null); // null | 'loading' | 'success' | 'error'
  const [message,     setMessage]     = useState('');
  const navigate = useNavigate();

  // ── Step 1: look up the user's keys ──────────────────────────────────────
  const handleFindKeys = async (e) => {
    e.preventDefault();
    setStatus('loading');
    setMessage('Looking up registered keys…');
    setCredentials(null);

    try {
      const uname   = username.trim().toLowerCase();
      const options = await api.post('/login/options', { username: uname });

      setChallenge(options.challenge);
      setCredentials(options.allowCredentials || []);
      setStatus(null);
      setMessage('');
    } catch (err) {
      setStatus('error');
      setMessage(err.message);
    }
  };

  // ── Step 2: sign with whichever key the user picks ───────────────────────
  const handleSignIn = async (cred) => {
    setStatus('loading');
    setMessage('Waiting for YubiKey approval…');

    try {
      const uname = username.trim().toLowerCase();

      // Re-fetch a fresh challenge each time (the previous one was shown for display only;
      // the backend stores the latest challenge for auth_<username>)
      const options = await api.post('/login/options', { username: uname });
      const freshChallenge = options.challenge;

      // Find matching cred from new options (same credentialId)
      const chosen = (options.allowCredentials || []).find(c => c.id === cred.id) || cred;

      setMessage(`Signing with your ${chosen.credType === 'backup' ? 'Backup' : 'Primary'} Key…`);

      const signedResponse = await signChallenge({
        credentialId: chosen.id,
        challenge:    freshChallenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });

      setMessage('Verifying ECDSA signature on server…');
      const result = await api.post('/login/verify', {
        username:     uname,
        credentialId: chosen.id,
        ...signedResponse
      });

      setStatus('success');
      setMessage(result.message);
      setTimeout(() => navigate('/dashboard'), 900);

    } catch (err) {
      setStatus('error');
      if (err.message === 'USER_PRESENCE_TIMEOUT') {
        setMessage('Access denied: Authenticator approval timed out (30 s).');
      } else if (err.message === 'USER_PRESENCE_CANCELLED') {
        setMessage('Authentication cancelled.');
      } else {
        setMessage(err.message);
      }
    }
  };

  // ── Helpers ───────────────────────────────────────────────────────────────
  const primaryCreds = (credentials || []).filter(c => (c.credType || 'primary') === 'primary');
  const backupCreds  = (credentials || []).filter(c => c.credType === 'backup');

  return (
    <div className="page-container">
      <div className="card">
        <div className="sim-badge">🔬 Educational Simulation</div>
        <h1>🔑 Sign In</h1>
        <p className="subtitle">
          No password needed — authenticate with your simulated FIDO2 YubiKey
        </p>

        {/* Step 1 — username lookup */}
        {!credentials && (
          <form onSubmit={handleFindKeys}>
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="e.g. alice"
                required
                autoComplete="username"
              />
            </div>
            <button type="submit" className="btn-primary" disabled={status === 'loading'}>
              {status === 'loading' ? '⏳ Looking up…' : '🔍 Find My Keys'}
            </button>
          </form>
        )}

        {/* Step 2 — key selection */}
        {credentials && (
          <div>
            <p style={{ color: 'var(--text-muted)', marginBottom: 12, fontSize: '0.9rem' }}>
              Registered keys for <strong style={{ color: 'var(--accent)' }}>{username}</strong>:
            </p>

            <div className="key-choice-grid">
              {/* Primary key button */}
              <button
                className={`key-choice-btn primary-key${primaryCreds.length === 0 ? '' : ''}`}
                disabled={primaryCreds.length === 0 || status === 'loading'}
                onClick={() => handleSignIn(primaryCreds[0])}
              >
                <div style={{ fontSize: 28, marginBottom: 6 }}>🔑</div>
                <div className="key-label">Primary Key</div>
                <div className="key-status">
                  {primaryCreds.length > 0
                    ? `${primaryCreds.length} key available`
                    : 'No primary key registered'}
                </div>
              </button>

              {/* Backup key button */}
              <button
                className="key-choice-btn backup-key"
                disabled={backupCreds.length === 0 || status === 'loading'}
                onClick={() => handleSignIn(backupCreds[0])}
              >
                <div style={{ fontSize: 28, marginBottom: 6 }}>🗝️</div>
                <div className="key-label">Backup Key</div>
                <div className="key-status">
                  {backupCreds.length > 0
                    ? `${backupCreds.length} key available`
                    : 'No backup key registered'}
                </div>
              </button>
            </div>

            <button
              className="btn-secondary"
              style={{ marginTop: 10, padding: '8px 20px', fontSize: '0.85rem' }}
              onClick={() => { setCredentials(null); setStatus(null); setMessage(''); }}
              disabled={status === 'loading'}
            >
              ← Use different username
            </button>
          </div>
        )}

        {/* Status messages */}
        {status === 'loading' && <div className="status-info" style={{ marginTop: 14 }}>🔑 {message}</div>}
        {status === 'success' && <div className="status-success" style={{ marginTop: 14 }}>✅ {message}</div>}
        {status === 'error'   && <div className="status-error"   style={{ marginTop: 14 }}>❌ {message}</div>}

        {/* Info box */}
        <div className="info-box" style={{ marginTop: 24 }}>
          <h3>🔐 How passwordless login works</h3>
          <ol>
            <li>Enter your username — no password required</li>
            <li>Choose your Primary or Backup key</li>
            <li>Simulated YubiKey shows touch + PIN verification dialog</li>
            <li>Your private key signs the server challenge (real ECDSA P-256)</li>
            <li>Server verifies the UV flag and ECDSA signature</li>
            <li>Secure session created — you are authenticated</li>
          </ol>
        </div>

        <div style={{ marginTop: 16, textAlign: 'center' }}>
          <a href="/recover-account" style={{ color: 'var(--accent)', fontSize: '0.85rem' }}>
            Lost your primary key? → Account Recovery
          </a>
        </div>
      </div>
    </div>
  );
}
