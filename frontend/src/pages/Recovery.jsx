import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { generateCredential, signChallenge } from '../simulator/yubikeySimulator';
import { api } from '../utils/api';

/** base64url-encode a plain string */
function toBase64url(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

const STEPS = {
  USERNAME:    'USERNAME',
  BACKUP_AUTH: 'BACKUP_AUTH',
  NEW_PRIMARY: 'NEW_PRIMARY',
  DONE:        'DONE'
};

export default function Recovery() {
  const [step,          setStep]          = useState(STEPS.USERNAME);
  const [username,      setUsername]      = useState('');
  const [status,        setStatus]        = useState(null);
  const [message,       setMessage]       = useState('');
  const [recoveryToken, setRecoveryToken] = useState(null);
  const navigate = useNavigate();

  // ── Step 1: authenticate with backup key ─────────────────────────────────
  const handleBackupAuth = async (e) => {
    e.preventDefault();
    setStatus('loading');
    setMessage('Requesting recovery challenge…');

    try {
      const uname = username.trim().toLowerCase();

      // Get challenge from /recovery/options  (uses backup key)
      const opts = await api.post('/recovery/options', { username: uname });

      // Sign the challenge with the backup key
      setMessage('Waiting for backup YubiKey approval…');
      const signed = await signChallenge({
        credentialId: opts.backupCredentialId,
        challenge:    opts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });

      // Verify → receive recovery token
      setMessage('Verifying backup key…');
      const result = await api.post('/recovery/verify', {
        username:     uname,
        credentialId: opts.backupCredentialId,
        ...signed
      });

      setRecoveryToken(result.recoveryToken);
      setStep(STEPS.NEW_PRIMARY);
      setStatus(null);
      setMessage('');

    } catch (err) {
      setStatus('error');
      if (err.message === 'USER_PRESENCE_CANCELLED') {
        setMessage('Cancelled. Please try again.');
      } else {
        setMessage(err.message);
      }
    }
  };

  // ── Step 2: register new primary key ─────────────────────────────────────
  const handleNewPrimary = async () => {
    setStatus('loading');
    setMessage('Step 1/3 — Generating new ECDSA P-256 key pair…');

    try {
      // Generate a fresh key pair
      const { credentialId, publicKeySpki, registrationAuthData } = await generateCredential();

      // Get a registration challenge (requires recoveryToken)
      setMessage('Step 2/3 — Requesting new primary key challenge…');
      const opts = await api.post('/recovery/new-primary/options', { recoveryToken });

      // Build clientDataJSON
      const clientData = {
        type:        'webauthn.create',
        challenge:   opts.challenge,
        origin:      window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = toBase64url(JSON.stringify(clientData));

      // Complete new primary registration (token is consumed server-side)
      setMessage('Step 3/3 — Registering new primary key…');
      await api.post('/recovery/new-primary/verify', {
        recoveryToken,
        credentialId,
        publicKeySpki,
        clientDataJSON,
        registrationAuthData
      });

      setStep(STEPS.DONE);
      setStatus('success');
      setMessage('New primary key registered! Old primary key revoked. Logging you in…');
      setTimeout(() => navigate('/dashboard'), 2000);

    } catch (err) {
      setStatus('error');
      setMessage(err.message);
    }
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="page-container">
      <div className="card">
        <div className="sim-badge">🔬 Educational Simulation</div>
        <h1>🔄 Account Recovery</h1>
        <p className="subtitle">
          Lost your primary key? Authenticate with your backup key to register a new one.
        </p>

        {/* Stage indicator */}
        <div className="stage-indicator">
          <div className={`stage-step ${step === STEPS.USERNAME ? 'active' : step !== STEPS.USERNAME ? 'done' : ''}`}>
            1. Username {step !== STEPS.USERNAME && '✓'}
          </div>
          <div className="stage-sep">›</div>
          <div className={`stage-step ${step === STEPS.BACKUP_AUTH ? 'active' : [STEPS.NEW_PRIMARY, STEPS.DONE].includes(step) ? 'done' : ''}`}>
            2. Backup Key Auth {[STEPS.NEW_PRIMARY, STEPS.DONE].includes(step) && '✓'}
          </div>
          <div className="stage-sep">›</div>
          <div className={`stage-step ${step === STEPS.NEW_PRIMARY ? 'active' : step === STEPS.DONE ? 'done' : ''}`}>
            3. New Primary Key {step === STEPS.DONE && '✓'}
          </div>
        </div>

        {/* Step: username entry */}
        {step === STEPS.USERNAME && (
          <form onSubmit={e => { e.preventDefault(); setStep(STEPS.BACKUP_AUTH); }}>
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
            <button type="submit" className="btn-primary">Continue →</button>
          </form>
        )}

        {/* Step: authenticate with backup key */}
        {step === STEPS.BACKUP_AUTH && (
          <div>
            <div className="info-box" style={{ marginBottom: 20 }}>
              <h3>🗝️ What happens next</h3>
              <ol style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                <li>Server finds your registered backup key</li>
                <li>You approve the simulated YubiKey touch + PIN dialog</li>
                <li>Server verifies the signature and issues a one-time recovery token (10-min TTL)</li>
                <li>You register a fresh primary key using that token</li>
                <li>Old primary key is permanently revoked</li>
              </ol>
            </div>
            <button className="btn-primary" onClick={handleBackupAuth} disabled={status === 'loading'}>
              {status === 'loading' ? '⏳ Authenticating…' : '🗝️ Authenticate with Backup Key'}
            </button>
          </div>
        )}

        {/* Step: register new primary */}
        {step === STEPS.NEW_PRIMARY && (
          <div>
            <div className="status-success" style={{ marginBottom: 16 }}>
              ✅ Backup key verified. Recovery token issued (valid 10 minutes, single-use).
            </div>
            <div className="info-box" style={{ marginBottom: 20 }}>
              <h3>🔑 Register your new Primary Key</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                A new ECDSA P-256 key pair will be generated. The recovery token will be consumed
                on the server and your old primary key will be revoked.
              </p>
            </div>
            <button className="btn-primary" onClick={handleNewPrimary} disabled={status === 'loading'}>
              {status === 'loading' ? '⏳ Registering…' : '🔑 Register New Primary Key'}
            </button>
          </div>
        )}

        {/* Step: done */}
        {step === STEPS.DONE && (
          <div style={{ textAlign: 'center', marginTop: 20 }}>
            <div style={{ fontSize: 56 }}>🎉</div>
            <div className="status-success" style={{ marginTop: 12 }}>{message}</div>
          </div>
        )}

        {/* Status messages (loading / error) */}
        {status === 'loading' && step !== STEPS.DONE &&
          <div className="status-info" style={{ marginTop: 14 }}>⏳ {message}</div>}
        {status === 'error' &&
          <div className="status-error" style={{ marginTop: 14 }}>❌ {message}</div>}
      </div>
    </div>
  );
}
