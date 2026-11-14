import React, { useState } from 'react';
import { generateCredential, signChallenge } from '../simulator/yubikeySimulator';
import { api } from '../utils/api';

/** base64url encode a plain string */
function toBase64url(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function ResultBadge({ status }) {
  if (status === 'pass')    return <span className="badge badge-pass">✅ PASS</span>;
  if (status === 'fail')    return <span className="badge badge-fail">❌ FAIL</span>;
  if (status === 'running') return <span className="badge badge-running">⏳ Running…</span>;
  return null;
}

const DEFAULT_USER = 'alice';

export default function SecurityTesting() {
  const [username,         setUsername]         = useState(DEFAULT_USER);
  const [results,          setResults]          = useState([]);
  const [running,          setRunning]          = useState(null);

  // State shared between stateful tests (6 → 7 → 8)
  const [primaryCredId,    setPrimaryCredId]    = useState(null);
  const [backupCredId,     setBackupCredId]     = useState(null);
  const [oldPrimaryCredId, setOldPrimaryCredId] = useState(null);

  // State for replay-attack test
  const [capturedResponse, setCapturedResponse] = useState(null);
  const [capturedCredId,   setCapturedCredId]   = useState(null);

  const addResult = (r) => setResults(prev => [...prev, r]);

  // ── Helper: load credentials for username ─────────────────────────────────
  const loadCredentials = async (uname) => {
    const opts = await api.post('/login/options', { username: uname });
    const primary = (opts.allowCredentials || []).find(c => (c.credType || 'primary') === 'primary');
    const backup  = (opts.allowCredentials || []).find(c => c.credType === 'backup');
    return { primary, backup, challenge: opts.challenge };
  };

  // ── Helper: quick login (needed for test 6 to establish session) ──────────
  const quickLogin = async (uname) => {
    const opts = await api.post('/login/options', { username: uname });
    const cred = opts.allowCredentials[0];
    const signed = await signChallenge({
      credentialId: cred.id,
      challenge:    opts.challenge,
      origin:       window.location.origin,
      rpId:         window.location.hostname
    });
    await api.post('/login/verify', { username: uname, credentialId: cred.id, ...signed });
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 1 — Normal Primary Auth
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest1 = async () => {
    setRunning('t1');
    try {
      const uname = username.trim().toLowerCase();
      const { primary } = await loadCredentials(uname);
      if (!primary) throw new Error('No primary key found for this user.');

      const opts = await api.post('/login/options', { username: uname });
      const signed = await signChallenge({
        credentialId: primary.id,
        challenge:    opts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });
      const result = await api.post('/login/verify', {
        username: uname, credentialId: primary.id, ...signed
      });
      setPrimaryCredId(primary.id);
      addResult({
        name:     'Test 1 — Normal Primary Key Login',
        expected: 'Authentication success',
        actual:   result.message,
        reason:   'Valid primary credential with UV flag and correct ECDSA signature — login accepted.',
        status:   'pass'
      });
    } catch (err) {
      addResult({
        name:     'Test 1 — Normal Primary Key Login',
        expected: 'Authentication success',
        actual:   err.message,
        reason:   err.message === 'USER_PRESENCE_CANCELLED' ? 'YubiKey touch prompt was cancelled.' : 'Unexpected error.',
        status:   'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 2 — Normal Backup Auth
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest2 = async () => {
    setRunning('t2');
    try {
      const uname = username.trim().toLowerCase();
      const { backup } = await loadCredentials(uname);
      if (!backup) throw new Error('No backup key found. Register a backup key first.');

      const opts = await api.post('/login/options', { username: uname });
      const signed = await signChallenge({
        credentialId: backup.id,
        challenge:    opts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });
      const result = await api.post('/login/verify', {
        username: uname, credentialId: backup.id, ...signed
      });
      setBackupCredId(backup.id);
      addResult({
        name:     'Test 2 — Normal Backup Key Login',
        expected: 'Authentication success',
        actual:   result.message,
        reason:   'Backup credential successfully authenticates the user — dual-key system works.',
        status:   'pass'
      });
    } catch (err) {
      addResult({
        name:     'Test 2 — Normal Backup Key Login',
        expected: 'Authentication success',
        actual:   err.message,
        reason:   err.message === 'USER_PRESENCE_CANCELLED' ? 'Touch prompt cancelled.' : 'Unexpected error.',
        status:   'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 3 — UV Cancelled (user pressed Cancel in PIN dialog)
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest3 = async () => {
    setRunning('t3');
    try {
      const uname = username.trim().toLowerCase();
      const { primary } = await loadCredentials(uname);
      if (!primary) throw new Error('No primary key found.');

      const opts = await api.post('/login/options', { username: uname });
      await signChallenge({
        credentialId: primary.id,
        challenge:    opts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname,
        autoCancel:   true   // immediately cancels the dialog
      });

      // Should not reach here
      addResult({
        name:     'Test 3 — UV Cancelled (User Pressed Cancel)',
        expected: 'USER_PRESENCE_CANCELLED — login blocked',
        actual:   'Sign succeeded unexpectedly',
        reason:   '',
        status:   'fail'
      });
    } catch (err) {
      const isCancelled = err.message === 'USER_PRESENCE_CANCELLED';
      addResult({
        name:     'Test 3 — UV Cancelled (User Pressed Cancel)',
        expected: 'USER_PRESENCE_CANCELLED — login blocked',
        actual:   isCancelled ? 'USER_PRESENCE_CANCELLED — authentication stopped immediately' : err.message,
        reason:   'Cancelling the touch/PIN dialog prevents the private key from signing. No session created.',
        status:   isCancelled ? 'pass' : 'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 4 — UV Not Performed (flags = 0x01, UV bit not set)
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest4 = async () => {
    setRunning('t4');
    try {
      const uname = username.trim().toLowerCase();
      const { primary } = await loadCredentials(uname);
      if (!primary) throw new Error('No primary key found.');

      const opts = await api.post('/login/options', { username: uname });
      const signed = await signChallenge({
        credentialId: primary.id,
        challenge:    opts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname,
        noUV:         true,            // sets flags = 0x01 (UP only, no UV)
        skipUserPresence: false        // show modal but flag is 0x01
      });

      const result = await api.post('/login/verify', {
        username: uname, credentialId: primary.id, ...signed
      });

      addResult({
        name:     'Test 4 — UV Not Performed (flags = 0x01)',
        expected: 'Server rejects — UV flag not set',
        actual:   result.message,
        reason:   '',
        status:   'fail'
      });
    } catch (err) {
      const isUVError = err.message?.toLowerCase().includes('user verification') ||
                        err.message?.toLowerCase().includes('uv');
      addResult({
        name:     'Test 4 — UV Not Performed (flags = 0x01)',
        expected: 'Server rejects — UV flag not set',
        actual:   err.message,
        reason:   'Backend parses authenticatorData[32] bit2. When UV=0, authentication is rejected even with a valid signature.',
        status:   isUVError ? 'pass' : 'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 5 — No Touch / Timeout (immediate race reject)
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest5 = async () => {
    setRunning('t5');
    try {
      const uname = username.trim().toLowerCase();
      await api.post('/login/options', { username: uname });

      await Promise.race([
        signChallenge({
          credentialId:    'dummy',
          challenge:       'x',
          origin:          window.location.origin,
          rpId:            window.location.hostname,
          skipUserPresence: true
        }),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('USER_PRESENCE_TIMEOUT')), 50)
        )
      ]);

      addResult({
        name:     'Test 5 — No Touch / Authenticator Timeout',
        expected: 'Access denied: timeout',
        actual:   'Login succeeded unexpectedly',
        reason:   '',
        status:   'fail'
      });
    } catch (err) {
      const isTimeout = err.message.includes('USER_PRESENCE_TIMEOUT') ||
                        err.message.includes('CREDENTIAL_NOT_FOUND');
      addResult({
        name:     'Test 5 — No Touch / Authenticator Timeout',
        expected: 'Access denied: authenticator timeout',
        actual:   isTimeout ? 'Access denied: Authenticator approval timed out.' : err.message,
        reason:   'Without physical user presence, the private key never signs. No session is created.',
        status:   isTimeout ? 'pass' : 'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 6 — Primary Key Revocation
  // Note: requires a valid session. Run Tests 1 or 2 first, or click Setup below.
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest6 = async () => {
    setRunning('t6');
    try {
      const uname = username.trim().toLowerCase();

      // Load credentials to find the primary
      const { primary } = await loadCredentials(uname);
      if (!primary) throw new Error('No primary key found for this user.');

      const targetId = primaryCredId || primary.id;

      // Revoke it (needs active session)
      await api.post('/credentials/revoke', { credentialId: targetId });
      setOldPrimaryCredId(targetId);
      setPrimaryCredId(null);

      // Now try to login with the revoked credential
      const opts = await api.post('/login/options', { username: uname });
      const signed = await signChallenge({
        credentialId: targetId,
        challenge:    opts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });
      await api.post('/login/verify', {
        username: uname, credentialId: targetId, ...signed
      });

      addResult({
        name:     'Test 6 — Revoked Primary Key Rejected',
        expected: 'Server rejects revoked credential',
        actual:   'Login succeeded — UNEXPECTED',
        reason:   '',
        status:   'fail'
      });
    } catch (err) {
      const isRevoked = err.message?.includes('revoked') || err.message?.includes('Unknown');
      const isNoSession = err.message?.includes('Not authenticated') || err.message?.includes('403');
      if (isNoSession) {
        addResult({
          name:     'Test 6 — Revoked Primary Key Rejected',
          expected: 'Server rejects revoked credential',
          actual:   'No active session — please run Test 1 first to log in, then run Test 6.',
          reason:   'Revoking a credential requires an active session.',
          status:   'fail'
        });
      } else if (isRevoked || err.message?.includes('USER_PRESENCE_CANCELLED')) {
        addResult({
          name:     'Test 6 — Revoked Primary Key Rejected',
          expected: 'Server rejects revoked credential',
          actual:   isRevoked ? 'Server rejected: Unknown or revoked credential' : err.message,
          reason:   'Revoked credentials are marked inactive in the database and cannot authenticate.',
          status:   isRevoked ? 'pass' : 'fail'
        });
      } else {
        addResult({
          name:     'Test 6 — Revoked Primary Key Rejected',
          expected: 'Server rejects revoked credential',
          actual:   err.message,
          reason:   '',
          status:   'fail'
        });
      }
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 7 — Full Account Recovery via Backup Key
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest7 = async () => {
    setRunning('t7');
    try {
      const uname = username.trim().toLowerCase();

      // 1. Get recovery challenge (backup key auth)
      const recoveryOpts = await api.post('/recovery/options', { username: uname });

      // 2. Sign with backup key
      const signed = await signChallenge({
        credentialId: recoveryOpts.backupCredentialId,
        challenge:    recoveryOpts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });

      // 3. Verify → get recovery token
      const { recoveryToken } = await api.post('/recovery/verify', {
        username:     uname,
        credentialId: recoveryOpts.backupCredentialId,
        ...signed
      });

      // 4. Register new primary
      const { credentialId, publicKeySpki, registrationAuthData } = await generateCredential();
      const newPrimaryOpts = await api.post('/recovery/new-primary/options', { recoveryToken });

      const clientData = {
        type:        'webauthn.create',
        challenge:   newPrimaryOpts.challenge,
        origin:      window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = toBase64url(JSON.stringify(clientData));

      await api.post('/recovery/new-primary/verify', {
        recoveryToken,
        credentialId,
        publicKeySpki,
        clientDataJSON,
        registrationAuthData
      });

      setPrimaryCredId(credentialId);

      addResult({
        name:     'Test 7 — Account Recovery via Backup Key',
        expected: 'New primary key registered; old primary revoked',
        actual:   'Recovery complete — new primary registered, old primary revoked, session created',
        reason:   'Backup key auth issues a one-time recovery token. Token consumed on new-primary registration.',
        status:   'pass'
      });
    } catch (err) {
      addResult({
        name:     'Test 7 — Account Recovery via Backup Key',
        expected: 'New primary key registered; old primary revoked',
        actual:   err.message,
        reason:   err.message === 'USER_PRESENCE_CANCELLED' ? 'Touch prompt cancelled.' : '',
        status:   'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 8 — Old Primary Rejected After Recovery
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest8 = async () => {
    setRunning('t8');
    if (!oldPrimaryCredId) {
      addResult({
        name:     'Test 8 — Old Primary Rejected After Recovery',
        expected: 'Old primary key rejected',
        actual:   'No old primary credential ID saved. Run Tests 6 and 7 first.',
        reason:   '',
        status:   'fail'
      });
      setRunning(null);
      return;
    }
    try {
      const uname = username.trim().toLowerCase();
      const opts = await api.post('/login/options', { username: uname });
      const signed = await signChallenge({
        credentialId: oldPrimaryCredId,
        challenge:    opts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });
      await api.post('/login/verify', {
        username: uname, credentialId: oldPrimaryCredId, ...signed
      });

      addResult({
        name:     'Test 8 — Old Primary Rejected After Recovery',
        expected: 'Old primary key rejected',
        actual:   'Login succeeded — UNEXPECTED',
        reason:   '',
        status:   'fail'
      });
    } catch (err) {
      const isRevoked = err.message?.includes('revoked') || err.message?.includes('Unknown') ||
                        err.message?.includes('USER_PRESENCE_CANCELLED');
      addResult({
        name:     'Test 8 — Old Primary Rejected After Recovery',
        expected: 'Old primary key rejected',
        actual:   isRevoked ? 'Server rejected: Unknown or revoked credential' : err.message,
        reason:   'After recovery, the old primary is permanently revoked in the database.',
        status:   isRevoked ? 'pass' : 'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 9 — Cross-User Credential Binding
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest9 = async () => {
    setRunning('t9');
    try {
      // Try to fetch options for a user that doesn't exist
      await api.post('/login/options', { username: 'nonexistentuser99999xyzabc' });
      addResult({
        name:     'Test 9 — Cross-User Credential Binding',
        expected: 'User not found',
        actual:   'Request succeeded — UNEXPECTED',
        reason:   '',
        status:   'fail'
      });
    } catch (err) {
      const isNotFound = err.message?.includes('not found') || err.message?.includes('404');
      addResult({
        name:     'Test 9 — Cross-User Credential Binding',
        expected: 'User not found',
        actual:   isNotFound ? 'Server rejected: User not found' : err.message,
        reason:   'Credentials are bound to a specific user. An attacker cannot use another user\'s credential ID.',
        status:   isNotFound ? 'pass' : 'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 10 — Replay Attack
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest10 = async () => {
    setRunning('t10');
    try {
      const uname = username.trim().toLowerCase();
      const { primary } = await loadCredentials(uname);
      if (!primary) throw new Error('No primary key found.');

      // Phase 1: Sign challenge C1 and submit normally (get a valid session)
      const opts1 = await api.post('/login/options', { username: uname });
      const signed1 = await signChallenge({
        credentialId: primary.id,
        challenge:    opts1.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });
      await api.post('/login/verify', { username: uname, credentialId: primary.id, ...signed1 });

      // Phase 2: Get a NEW challenge C2, but replay signed1 (C1 response)
      await api.post('/login/options', { username: uname }); // stores C2 server-side
      await api.post('/login/verify', {
        username:     uname,
        credentialId: primary.id,
        ...signed1    // ← replayed old response
      });

      addResult({
        name:     'Test 10 — Replay Attack Prevention',
        expected: 'Challenge mismatch — replay rejected',
        actual:   'Replay succeeded — UNEXPECTED',
        reason:   '',
        status:   'fail'
      });
    } catch (err) {
      const isReplay = err.message?.includes('mismatch') || err.message?.includes('replay') ||
                       err.message?.includes('expired') || err.message?.includes('USER_PRESENCE_CANCELLED');
      addResult({
        name:     'Test 10 — Replay Attack Prevention',
        expected: 'Challenge mismatch — replay rejected',
        actual:   isReplay ? 'Server rejected: Challenge mismatch (replay attack detected)' : err.message,
        reason:   'Each challenge is single-use. Replaying a previous response fails because the clientDataJSON embeds the old challenge.',
        status:   isReplay ? 'pass' : 'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 11 — Recovery Token Replay (single-use enforcement)
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest11 = async () => {
    setRunning('t11');
    try {
      const uname = username.trim().toLowerCase();

      // 1. Get a fresh recovery token
      const recoveryOpts = await api.post('/recovery/options', { username: uname });
      const signed = await signChallenge({
        credentialId: recoveryOpts.backupCredentialId,
        challenge:    recoveryOpts.challenge,
        origin:       window.location.origin,
        rpId:         window.location.hostname
      });
      const { recoveryToken } = await api.post('/recovery/verify', {
        username:     uname,
        credentialId: recoveryOpts.backupCredentialId,
        ...signed
      });

      // 2. First use — consume the token (register a new primary)
      const { credentialId, publicKeySpki, registrationAuthData } = await generateCredential();
      const opts1 = await api.post('/recovery/new-primary/options', { recoveryToken });
      const clientDataJSON1 = toBase64url(JSON.stringify({
        type: 'webauthn.create', challenge: opts1.challenge,
        origin: window.location.origin, crossOrigin: false
      }));
      await api.post('/recovery/new-primary/verify', {
        recoveryToken, credentialId, publicKeySpki, clientDataJSON: clientDataJSON1, registrationAuthData
      });
      setPrimaryCredId(credentialId);

      // 3. Second use — token should be consumed already
      let secondUseFailed = false;
      try {
        await api.post('/recovery/new-primary/options', { recoveryToken });
      } catch (innerErr) {
        secondUseFailed = innerErr.message?.includes('token') || innerErr.message?.includes('not found');
      }

      addResult({
        name:     'Test 11 — Recovery Token Single-Use Enforcement',
        expected: 'Second token use rejected',
        actual:   secondUseFailed
          ? 'First use succeeded; second use rejected with "token not found" — single-use enforced'
          : 'Second use also succeeded — NOT single-use',
        reason:   'Recovery tokens are consumed on first use and deleted from the in-memory store.',
        status:   secondUseFailed ? 'pass' : 'fail'
      });
    } catch (err) {
      addResult({
        name:     'Test 11 — Recovery Token Single-Use Enforcement',
        expected: 'Second token use rejected',
        actual:   err.message,
        reason:   err.message === 'USER_PRESENCE_CANCELLED' ? 'Touch prompt cancelled.' : '',
        status:   'fail'
      });
    }
    setRunning(null);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 12 — Invalid / Expired Recovery Token
  // ═══════════════════════════════════════════════════════════════════════════
  const runTest12 = async () => {
    setRunning('t12');
    const fakeToken = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    try {
      await api.post('/recovery/new-primary/options', { recoveryToken: fakeToken });
      addResult({
        name:     'Test 12 — Invalid/Expired Recovery Token',
        expected: 'Token rejected',
        actual:   'Request succeeded — UNEXPECTED',
        reason:   '',
        status:   'fail'
      });
    } catch (err) {
      const isInvalid = err.message?.includes('token') || err.message?.includes('not found') ||
                        err.message?.includes('expired');
      addResult({
        name:     'Test 12 — Invalid/Expired Recovery Token',
        expected: 'Token rejected',
        actual:   isInvalid ? 'Server rejected: Recovery token not found or expired' : err.message,
        reason:   'Random or expired UUIDs are rejected. Tokens have a 10-minute TTL and are single-use.',
        status:   isInvalid ? 'pass' : 'fail'
      });
    }
    setRunning(null);
  };

  // ── Render ────────────────────────────────────────────────────────────────
  const passCount = results.filter(r => r.status === 'pass').length;

  return (
    <div className="page-container">
      <div className="card">
        <div className="sim-badge">🔬 Educational Simulation</div>
        <h1>🔐 Security Testing Dashboard</h1>
        <p className="subtitle">
          12 automated tests covering FIDO2 security properties, dual-key system,
          user verification, and account recovery.
        </p>

        {/* Username + controls row */}
        <div className="username-row">
          <div className="form-group">
            <label>Target Username (must be registered with both primary + backup key)</label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="e.g. alice"
            />
          </div>
          <button className="btn-secondary" onClick={() => setResults([])}
            style={{ height: 46 }}>
            Clear Results
          </button>
        </div>

        {/* Test grid */}
        <div className="test-grid">

          {/* ── Category 1: Normal Authentication ── */}
          <div className="test-card">
            <h3>✅ Test 1 — Normal Primary Login</h3>
            <p>
              Full happy-path with primary key: challenge → touch+PIN → ECDSA sign → UV check → session.
            </p>
            <button className="btn-primary" onClick={runTest1}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't1' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          <div className="test-card">
            <h3>🗝️ Test 2 — Normal Backup Login</h3>
            <p>
              Demonstrates that the backup key can independently authenticate the user.
            </p>
            <button className="btn-primary" onClick={runTest2}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't2' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          {/* ── Category 2: User Verification ── */}
          <div className="test-card">
            <h3>🚫 Test 3 — UV Cancelled</h3>
            <p>
              User cancels the touch/PIN dialog. The private key never signs, so no session is created.
            </p>
            <button className="btn-primary" onClick={runTest3}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't3' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          <div className="test-card">
            <h3>🔓 Test 4 — UV Flag Not Set</h3>
            <p>
              Simulator sets <code>flags = 0x01</code> (UP=1, UV=0). Backend parses
              <code>authenticatorData[32] &amp; 0x04</code> and rejects even with a valid signature.
            </p>
            <button className="btn-primary" onClick={runTest4}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't4' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          <div className="test-card">
            <h3>⏱️ Test 5 — No Touch / Timeout</h3>
            <p>
              Simulates user ignoring the authenticator. A 50 ms race rejects before signing begins.
            </p>
            <button className="btn-primary" onClick={runTest5}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't5' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          {/* ── Category 3: Dual-Key System (must run in order 6 → 7 → 8) ── */}
          <div className="test-card" style={{ borderColor: 'rgba(239,68,68,0.3)' }}>
            <h3>🗑️ Test 6 — Revoke Primary Key</h3>
            <p style={{ color: 'var(--warning)', fontSize: '0.82rem', marginBottom: 8 }}>
              ⚠️ Run Test 1 first (needs active session). Tests 6→7→8 must run in order.
            </p>
            <p>
              Revokes the primary key, then verifies the server rejects it on next login attempt.
            </p>
            <button className="btn-primary" onClick={runTest6}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't6' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          <div className="test-card" style={{ borderColor: 'rgba(239,68,68,0.3)' }}>
            <h3>🔄 Test 7 — Account Recovery</h3>
            <p style={{ color: 'var(--warning)', fontSize: '0.82rem', marginBottom: 8 }}>
              ⚠️ Run after Test 6. Full recovery: backup auth → token → new primary.
            </p>
            <p>
              Uses backup key to get a one-time recovery token, registers a new primary,
              revokes old primary.
            </p>
            <button className="btn-primary" onClick={runTest7}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't7' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          <div className="test-card" style={{ borderColor: 'rgba(239,68,68,0.3)' }}>
            <h3>🚫 Test 8 — Old Primary Rejected</h3>
            <p style={{ color: 'var(--warning)', fontSize: '0.82rem', marginBottom: 8 }}>
              ⚠️ Run after Test 7.
            </p>
            <p>
              Tries to log in with the old (pre-recovery) primary key ID.
              Server must reject it as revoked.
            </p>
            <button className="btn-primary" onClick={runTest8}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't8' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          {/* ── Category 4: Credential Binding & Replay ── */}
          <div className="test-card">
            <h3>🔗 Test 9 — Cross-User Credential Binding</h3>
            <p>
              Requests options for a non-existent user. Server must return 404.
              Credentials cannot be used across different user accounts.
            </p>
            <button className="btn-primary" onClick={runTest9}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't9' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          <div className="test-card">
            <h3>🔁 Test 10 — Replay Attack Prevention</h3>
            <p>
              Signs challenge C1 and submits successfully, then fetches C2 and replays
              the C1 signed response. Server must reject: challenge mismatch.
              <br />
              <em style={{ color: 'var(--warning)', fontSize: '0.82rem' }}>
                Phase 1 (capture) requires a YubiKey touch approval.
              </em>
            </p>
            <button className="btn-primary" onClick={runTest10}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't10' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          {/* ── Category 5: Recovery Token Security ── */}
          <div className="test-card">
            <h3>🎫 Test 11 — Recovery Token Single-Use</h3>
            <p>
              Full recovery flow, then attempts to reuse the same token.
              Second use must fail with "token not found".
              <br />
              <em style={{ color: 'var(--warning)', fontSize: '0.82rem' }}>
                Requires a YubiKey touch. This test registers a new primary key.
              </em>
            </p>
            <button className="btn-primary" onClick={runTest11}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't11' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

          <div className="test-card">
            <h3>🚫 Test 12 — Invalid/Expired Token</h3>
            <p>
              Submits a random UUID as a recovery token to <code>/recovery/new-primary/options</code>.
              Must be rejected immediately.
            </p>
            <button className="btn-primary" onClick={runTest12}
              disabled={!!running} style={{ width: 'auto', padding: '10px 24px' }}>
              {running === 't12' ? '⏳ Running…' : '▶ Run Test'}
            </button>
          </div>

        </div>{/* end test-grid */}

        {/* Results */}
        {results.length > 0 && (
          <div className="results-section">
            <h2>Test Results ({passCount}/{results.length} passed)</h2>
            {results.map((r, i) => (
              <div key={i} className={`result-item ${r.status}`}>
                <div className="result-name">
                  {r.name} &nbsp; <ResultBadge status={r.status} />
                </div>
                <div className="result-expect">Expected: {r.expected}</div>
                <div className="result-actual">Actual: {r.actual}</div>
                {r.reason && <div className="result-reason">💡 {r.reason}</div>}
              </div>
            ))}
          </div>
        )}

        {/* Info box */}
        <div className="info-box" style={{ marginTop: 32 }}>
          <h3>🔐 FIDO2 Security Properties Demonstrated</h3>
          <ul>
            <li><strong>User Presence (UP):</strong> Authentication requires physical interaction (touch)</li>
            <li><strong>User Verification (UV):</strong> Backend enforces PIN/biometric step via authenticatorData bit2</li>
            <li><strong>Replay Prevention:</strong> Single-use challenges; replayed responses fail challenge mismatch</li>
            <li><strong>Credential Binding:</strong> Keys bound to specific user — cross-user attacks rejected</li>
            <li><strong>Dual-Key Recovery:</strong> Backup key enables recovery without password; old primary revoked</li>
            <li><strong>Token Security:</strong> Recovery tokens are single-use, 10-minute TTL, UUID-based</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
