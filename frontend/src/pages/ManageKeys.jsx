import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { generateCredential } from '../simulator/yubikeySimulator';
import { api } from '../utils/api';

/** base64url encode a plain string */
function toBase64url(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function CredBadge({ type }) {
  return (
    <span className={`cred-type-badge ${type || 'primary'}`}>
      {(type || 'primary').toUpperCase()}
    </span>
  );
}

export default function ManageKeys() {
  const [credentials, setCredentials] = useState(null);
  const [auditLog,    setAuditLog]    = useState([]);
  const [status,      setStatus]      = useState(null);
  const [message,     setMessage]     = useState('');
  const [revoking,    setRevoking]    = useState(null); // credentialId being revoked
  const [addingBackup, setAddingBackup] = useState(false);
  const navigate = useNavigate();

  const loadData = useCallback(async () => {
    try {
      const [credList, log] = await Promise.all([
        api.get('/credentials/list'),
        api.get('/credentials/audit-log')
      ]);
      setCredentials(credList.credentials || []);
      setAuditLog(log.events || []);
    } catch (err) {
      if (err.message === 'Not authenticated') {
        navigate('/login');
      } else {
        setStatus('error');
        setMessage(err.message);
      }
    }
  }, [navigate]);

  useEffect(() => { loadData(); }, [loadData]);

  // ── Revoke ────────────────────────────────────────────────────────────────
  const handleRevoke = async (cred) => {
    if (!window.confirm(`Revoke ${cred.type?.toUpperCase() || 'PRIMARY'} key "${cred.label}"?\nThis cannot be undone.`)) return;
    setRevoking(cred.credentialId);
    try {
      await api.post('/credentials/revoke', { credentialId: cred.credentialId });
      await loadData();
    } catch (err) {
      setStatus('error');
      setMessage(err.message);
    } finally {
      setRevoking(null);
    }
  };

  // ── Add backup key ────────────────────────────────────────────────────────
  const handleAddBackup = async () => {
    setAddingBackup(true);
    setStatus('loading');
    setMessage('Step 1/3 — Requesting backup key registration challenge…');

    try {
      const opts = await api.post('/register/backup/options', {});

      setMessage('Step 2/3 — Generating new ECDSA P-256 key pair…');
      const { credentialId, publicKeySpki, registrationAuthData } = await generateCredential();

      const clientData = {
        type:        'webauthn.create',
        challenge:   opts.challenge,
        origin:      window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = toBase64url(JSON.stringify(clientData));

      setMessage('Step 3/3 — Verifying backup key on server…');
      const result = await api.post('/register/backup/verify', {
        credentialId,
        publicKeySpki,
        clientDataJSON,
        registrationAuthData
      });

      setStatus('success');
      setMessage(result.message || 'Backup key registered!');
      await loadData();
    } catch (err) {
      setStatus('error');
      setMessage(err.message);
    } finally {
      setAddingBackup(false);
    }
  };

  // ── Loading state ─────────────────────────────────────────────────────────
  if (!credentials) {
    return (
      <div className="page-container">
        <div className="card">
          <div className="status-info">🔑 Loading keys…</div>
        </div>
      </div>
    );
  }

  const activeBackup = credentials.some(c => c.type === 'backup' && c.status === 'active');

  return (
    <div className="page-container">
      <div className="card">
        <h1>⚙️ Manage Keys</h1>
        <p className="subtitle">View, revoke, or add your registered YubiKeys.</p>

        {/* Status */}
        {status === 'loading' && <div className="status-info">⏳ {message}</div>}
        {status === 'success' && <div className="status-success">✅ {message}</div>}
        {status === 'error'   && <div className="status-error">❌ {message}</div>}

        {/* Add backup button */}
        {!activeBackup && (
          <div className="info-box" style={{ borderColor: 'rgba(239,68,68,0.4)', marginBottom: 20 }}>
            <h3 style={{ color: 'var(--error)' }}>⚠️ No Active Backup Key</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: 12 }}>
              Without a backup key, losing your primary key will lock you out permanently.
            </p>
            <button className="btn-primary" onClick={handleAddBackup}
              disabled={addingBackup} style={{ width: 'auto', padding: '10px 24px' }}>
              {addingBackup ? '⏳ Registering…' : '🗝️ Register Backup Key'}
            </button>
          </div>
        )}

        {/* Credential table */}
        <div className="profile-section">
          <h2>All Credentials ({credentials.length})</h2>
          {credentials.length === 0 && (
            <p style={{ color: 'var(--text-muted)' }}>No credentials found.</p>
          )}
          {credentials.map((c, i) => (
            <div key={i} className={`credential-card ${c.status}`}
              style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ flex: 1, minWidth: 220 }}>
                <CredBadge type={c.type} />
                <div className="cred-label">🔑 {c.label}</div>
                <div className="cred-id">ID: <code>{c.credentialId.substring(0, 20)}…</code></div>
                <div className={`cred-status ${c.status}`}>
                  {c.status === 'active' ? '🟢 Active' : '🔴 Revoked'}
                </div>
                <div className="cred-date">Created: {new Date(c.createdAt).toLocaleString()}</div>
                {c.lastUsedAt && (
                  <div className="cred-date" style={{ color: 'var(--accent)' }}>
                    Last used: {new Date(c.lastUsedAt).toLocaleString()}
                  </div>
                )}
                {c.revokedAt && (
                  <div className="cred-date" style={{ color: 'var(--error)' }}>
                    Revoked: {new Date(c.revokedAt).toLocaleString()}
                  </div>
                )}
              </div>
              {c.status === 'active' && (
                <button
                  className="btn-secondary"
                  style={{ padding: '8px 16px', fontSize: '0.82rem', color: 'var(--error)', borderColor: 'var(--error)' }}
                  disabled={revoking === c.credentialId}
                  onClick={() => handleRevoke(c)}
                >
                  {revoking === c.credentialId ? '⏳' : '🗑️ Revoke'}
                </button>
              )}
            </div>
          ))}
        </div>

        {/* Audit log */}
        <div className="profile-section">
          <h2>Audit Log (last 50 events)</h2>
          {auditLog.length === 0 && (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>No events yet.</p>
          )}
          <div style={{ maxHeight: 300, overflowY: 'auto', marginTop: 10 }}>
            {auditLog.map((ev, i) => (
              <div key={i} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
                padding: '8px 12px', borderRadius: 6, marginBottom: 4,
                background: ev.success ? 'rgba(34,197,94,0.07)' : 'rgba(239,68,68,0.07)',
                border: `1px solid ${ev.success ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}`,
                fontSize: '0.82rem'
              }}>
                <div>
                  <span style={{ color: ev.success ? 'var(--success)' : 'var(--error)', fontWeight: 700 }}>
                    {ev.success ? '✅' : '❌'} {ev.action}
                  </span>
                  {ev.credType && (
                    <span className={`cred-type-badge ${ev.credType}`} style={{ marginLeft: 8, fontSize: '0.68rem' }}>
                      {ev.credType.toUpperCase()}
                    </span>
                  )}
                  <div style={{ color: 'var(--text-muted)', marginTop: 2 }}>{ev.details}</div>
                </div>
                <div style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap', marginLeft: 12 }}>
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ marginTop: 20, display: 'flex', gap: 12 }}>
          <Link to="/dashboard" className="btn-secondary"
            style={{ padding: '10px 20px', textDecoration: 'none', display: 'inline-block', fontSize: '0.9rem' }}>
            ← Back to Dashboard
          </Link>
          <Link to="/recover-account" className="btn-secondary"
            style={{ padding: '10px 20px', textDecoration: 'none', display: 'inline-block', fontSize: '0.9rem' }}>
            🔄 Account Recovery
          </Link>
        </div>
      </div>
    </div>
  );
}
