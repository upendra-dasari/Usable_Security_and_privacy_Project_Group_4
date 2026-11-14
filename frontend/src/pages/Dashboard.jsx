import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api } from '../utils/api';

export default function Dashboard() {
  const [profile, setProfile] = useState(null);
  const [error,   setError]   = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    api.get('/login/profile')
      .then(setProfile)
      .catch(err => {
        setError(err.message);
        if (err.message === 'Not authenticated') {
          setTimeout(() => navigate('/login'), 1500);
        }
      });
  }, [navigate]);

  if (error) {
    return (
      <div className="page-container">
        <div className="card">
          <div className="status-error">❌ {error}</div>
        </div>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="page-container">
        <div className="card">
          <div className="status-info">🔑 Loading profile…</div>
        </div>
      </div>
    );
  }

  const { user, credentials } = profile;

  const primaryCreds = credentials.filter(c => (c.type || 'primary') === 'primary');
  const backupCreds  = credentials.filter(c => c.type === 'backup');

  return (
    <div className="page-container">
      <div className="card">
        <h1>🛡️ Dashboard</h1>
        <div className="status-success">
          ✅ You are authenticated via simulated FIDO2 / YubiKey — no password was used.
        </div>

        {/* Account info */}
        <div className="profile-section">
          <h2>Account Information</h2>
          <table className="info-table">
            <tbody>
              <tr><td><strong>Username</strong></td><td>{user.username}</td></tr>
              <tr><td><strong>Email</strong></td><td>{user.email}</td></tr>
              <tr><td><strong>User ID</strong></td><td><code>{user.userId}</code></td></tr>
              <tr><td><strong>Registered</strong></td><td>{new Date(user.createdAt).toLocaleString()}</td></tr>
            </tbody>
          </table>
        </div>

        {/* Key status summary */}
        <div className="profile-section">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2>Registered YubiKeys ({credentials.length})</h2>
            <Link to="/manage-keys" className="btn-secondary"
              style={{ padding: '8px 16px', fontSize: '0.85rem', textDecoration: 'none', display: 'inline-block' }}>
              ⚙️ Manage Keys
            </Link>
          </div>

          {credentials.length === 0 && (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>No credentials found.</p>
          )}

          {credentials.map((c, i) => (
            <div key={i} className={`credential-card ${c.status}`}>
              {/* Type badge */}
              <span className={`cred-type-badge ${c.type || 'primary'}`}>
                {(c.type || 'primary').toUpperCase()}
              </span>
              <div className="cred-label">🔑 {c.label}</div>
              <div className="cred-id">
                Credential ID: <code>{c.credentialId.substring(0, 20)}…</code>
              </div>
              <div className={`cred-status ${c.status}`}>
                {c.status === 'active' ? '🟢 Active' : '🔴 Revoked'}
              </div>
              <div className="cred-date">
                Registered: {new Date(c.createdAt).toLocaleString()}
              </div>
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
          ))}
        </div>

        {/* Recovery reminder */}
        {backupCreds.filter(c => c.status === 'active').length === 0 && (
          <div className="info-box" style={{ borderColor: 'rgba(239,68,68,0.4)', marginTop: 8 }}>
            <h3 style={{ color: 'var(--error)' }}>⚠️ No Active Backup Key</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
              You have no active backup key. If you lose your primary key you will be locked out.
              <br />
              <Link to="/manage-keys" style={{ color: 'var(--accent)' }}>→ Register a Backup Key</Link>
            </p>
          </div>
        )}

        {/* Security summary */}
        <div className="info-box">
          <h3>🔐 Security Summary</h3>
          <ul>
            <li>No password was transmitted or stored</li>
            <li>Private key never left your browser / simulated YubiKey</li>
            <li>Server verified your identity using your stored public key</li>
            <li>Each login used a unique, single-use random challenge (replay-proof)</li>
            <li>User Verification (UV) flag checked on every login</li>
            <li>Session managed via server-side HttpOnly cookie</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
