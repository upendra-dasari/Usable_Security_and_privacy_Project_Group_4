/**
 * yubikeySimulator.js
 *
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  EDUCATIONAL SIMULATOR — NOT A REAL FIDO2/CTAP DEVICE           ║
 * ║                                                                  ║
 * ║  Real cryptographic operations (ECDSA P-256 via Web Crypto API): ║
 * ║    ✅ Key pair generation                                         ║
 * ║    ✅ Challenge signing (private key stays in localStorage)       ║
 * ║    ✅ Signature verified independently by the backend             ║
 * ║    ✅ PIN hashed with SHA-256 before storage                      ║
 * ║                                                                  ║
 * ║  Simulated (clearly labelled as demo behaviour):                 ║
 * ║    🔵 Physical USB/NFC touch interaction                          ║
 * ║    🔵 PIN verification (stored locally, hashed — not hardware)   ║
 * ║    🔵 CTAP protocol & attestation certificate                     ║
 * ║                                                                  ║
 * ║  For real hardware-backed security use navigator.credentials     ║
 * ║  with a physical FIDO2 YubiKey or platform authenticator.        ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */

const STORAGE_KEY           = 'yubikey_sim_credentials';
const USER_PRESENCE_TIMEOUT = 30000; // 30 s
const MAX_PIN_ATTEMPTS      = 3;     // lock out after 3 wrong PINs (like real FIDO2)

// ─── Storage helpers ────────────────────────────────────────────────────────────

function loadCredentials() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch { return {}; }
}

function saveCredentials(creds) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(creds));
}

// ─── Encoding helpers ───────────────────────────────────────────────────────────

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary  = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function arrayBufferToBase64url(buf) {
  return arrayBufferToBase64(buf)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ─── PIN hashing helper ─────────────────────────────────────────────────────────

/**
 * hashPin(pin) → hex string
 * SHA-256 of the PIN so we never store the raw PIN in localStorage.
 * On real FIDO2 hardware the PIN is processed inside the authenticator chip.
 */
async function hashPin(pin) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pin));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Inject CSS once ────────────────────────────────────────────────────────────

function ensureSimStyle() {
  if (document.getElementById('yubikey-sim-style')) return;
  const s = document.createElement('style');
  s.id = 'yubikey-sim-style';
  s.textContent = `
    @keyframes ykspin  { to { transform: rotate(360deg); } }
    @keyframes ykpulse { 0%,100%{transform:scale(1);opacity:1} 50%{transform:scale(1.08);opacity:.8} }
    .yk-btn-primary {
      background:#00d4ff;color:#000;border:none;border-radius:8px;
      padding:14px 28px;font-size:15px;font-weight:700;cursor:pointer;
      flex:1;min-width:140px;transition:opacity .2s;
    }
    .yk-btn-primary:hover { opacity:.85 }
    .yk-btn-cancel {
      background:transparent;color:#94a3b8;border:1px solid #374151;border-radius:8px;
      padding:14px 24px;font-size:15px;cursor:pointer;flex:1;min-width:100px;
      transition:border-color .2s;
    }
    .yk-btn-cancel:hover { border-color:#ef4444;color:#ef4444 }
    .yk-input {
      width:100%;box-sizing:border-box;background:#0d0d1a;border:2px solid #374151;
      border-radius:8px;color:#fff;font-size:15px;padding:11px 13px;outline:none;
      font-family:monospace;letter-spacing:3px;transition:border-color .2s,box-shadow .2s;
    }
    .yk-input:focus { border-color:#00d4ff;box-shadow:0 0 0 3px rgba(0,212,255,0.2); }
    .yk-input.error { border-color:#ef4444; }
    .yk-input::placeholder { color:#4a5568;letter-spacing:normal; }
  `;
  document.head.appendChild(s);
}

// ─── Helper: build the dark overlay + modal shell ──────────────────────────────

function buildOverlay() {
  ensureSimStyle();
  const overlay = document.createElement('div');
  overlay.style.cssText =
    'position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;' +
    'background:rgba(0,0,0,0.78);display:flex;align-items:center;justify-content:center;';

  const modal = document.createElement('div');
  modal.style.cssText =
    'background:#1a1a2e;color:#eee;border:2px solid #00d4ff;border-radius:16px;' +
    'padding:40px;text-align:center;max-width:460px;width:90%;' +
    'box-shadow:0 0 60px rgba(0,212,255,0.25);font-family:system-ui,sans-serif;';

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  const cleanup = () => {
    if (document.body.contains(overlay)) document.body.removeChild(overlay);
  };

  return { overlay, modal, cleanup };
}

const EDU_BADGE = `
  <div style="background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.4);
              color:#f59e0b;border-radius:8px;padding:6px 12px;font-size:12px;margin-bottom:14px">
    ⚠️ EDUCATIONAL DEMO — Not a real hardware security key
  </div>`;

// ─── PIN setup modal (called during registration) ───────────────────────────────

/**
 * setupPin() → Promise<pinHash>
 *
 * Shows a "Set your FIDO2 PIN" modal with two fields: PIN + Confirm PIN.
 * Returns the SHA-256 hex hash of the chosen PIN.
 * Rejects with USER_PRESENCE_CANCELLED if the user dismisses.
 */
function setupPin() {
  const { modal, cleanup } = buildOverlay();

  return new Promise((resolve, reject) => {
    modal.innerHTML = `
      <div style="font-size:56px;margin-bottom:12px">🔑</div>
      <h2 style="color:#00d4ff;margin:0 0 8px">Set Your FIDO2 PIN</h2>
      ${EDU_BADGE}
      <p style="color:#94a3b8;font-size:13px;margin-bottom:20px;line-height:1.5">
        Choose a PIN for this simulated YubiKey.<br/>
        You will need to enter <strong style="color:#e2e8f0">this exact PIN</strong>
        every time you log in with this key.
      </p>

      <div style="text-align:left;margin-bottom:12px">
        <label style="font-size:13px;color:#94a3b8;display:block;margin-bottom:5px">
          New PIN <span style="color:#64748b">(min 4 characters)</span>:
        </label>
        <input id="yk-newpin" type="password" placeholder="Enter new PIN"
               class="yk-input" autocomplete="new-password" />
      </div>

      <div style="text-align:left;margin-bottom:6px">
        <label style="font-size:13px;color:#94a3b8;display:block;margin-bottom:5px">
          Confirm PIN:
        </label>
        <input id="yk-confirmpin" type="password" placeholder="Re-enter PIN"
               class="yk-input" autocomplete="new-password" />
      </div>

      <div id="yk-setup-error"
           style="color:#ef4444;font-size:12px;min-height:18px;margin:6px 0 16px;text-align:left"></div>

      <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
        <button class="yk-btn-primary" id="yk-setpin-btn">🔒 Set PIN</button>
        <button class="yk-btn-cancel"  id="yk-setpin-cancel">Cancel</button>
      </div>`;

    setTimeout(() => { const f = modal.querySelector('#yk-newpin'); if (f) f.focus(); }, 50);

    modal.addEventListener('click', async (e) => {
      if (e.target.id === 'yk-setpin-btn') {
        const newPin     = modal.querySelector('#yk-newpin').value;
        const confirmPin = modal.querySelector('#yk-confirmpin').value;
        const errEl      = modal.querySelector('#yk-setup-error');

        // Reset borders
        modal.querySelector('#yk-newpin').classList.remove('error');
        modal.querySelector('#yk-confirmpin').classList.remove('error');
        errEl.textContent = '';

        if (newPin.length < 4) {
          errEl.textContent = '⚠️ PIN must be at least 4 characters.';
          modal.querySelector('#yk-newpin').classList.add('error');
          modal.querySelector('#yk-newpin').focus();
          return;
        }
        if (newPin !== confirmPin) {
          errEl.textContent = '⚠️ PINs do not match. Please re-enter the confirmation.';
          modal.querySelector('#yk-confirmpin').classList.add('error');
          modal.querySelector('#yk-confirmpin').value = '';
          modal.querySelector('#yk-confirmpin').focus();
          return;
        }

        const pinHash = await hashPin(newPin);
        cleanup();
        resolve(pinHash);

      } else if (e.target.id === 'yk-setpin-cancel') {
        cleanup();
        reject(new Error('USER_PRESENCE_CANCELLED'));
      }
    });

    modal.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const btn = modal.querySelector('#yk-setpin-btn');
        if (btn) btn.click();
      }
    });
  });
}

// ─── Two-step user-presence + PIN verification modal ───────────────────────────

/**
 * requestUserPresenceAndVerification({ credentialId, ... })
 *
 * Step 1: "Touch YubiKey" — simulates physical button press (user presence)
 * Step 2: PIN entry — compared against the SHA-256 hash stored at registration.
 *         Allows up to MAX_PIN_ATTEMPTS (3) before rejecting, like real FIDO2 hardware.
 *
 * Options:
 *   credentialId - used to look up the stored PIN hash in localStorage
 *   timeoutMs    - auto-cancel after N ms (default 30 000)
 *   autoCancel   - immediately reject with USER_PRESENCE_CANCELLED (Test 3)
 *   skipUV       - skip PIN step entirely; resolve after touch only (flags = UP-only)
 */
function requestUserPresenceAndVerification({
  credentialId = null,
  timeoutMs    = USER_PRESENCE_TIMEOUT,
  autoCancel   = false,
  skipUV       = false
} = {}) {
  if (autoCancel) {
    return Promise.reject(new Error('USER_PRESENCE_CANCELLED'));
  }

  const { modal, cleanup: removeOverlay } = buildOverlay();

  return new Promise((resolve, reject) => {
    let secondsLeft = Math.floor(timeoutMs / 1000);
    let pinAttempts = 0;

    // Look up stored PIN hash for this credential
    const allCreds      = loadCredentials();
    const storedPinHash = credentialId && allCreds[credentialId]
      ? (allCreds[credentialId].pinHash || null)
      : null;

    // ── Step 1: touch ──────────────────────────────────────────────────────────
    function renderStep1() {
      modal.innerHTML = `
        <div style="font-size:60px;margin-bottom:16px;animation:ykpulse 1.2s infinite">🔐</div>
        <h2 style="color:#00d4ff;margin:0 0 8px">Simulated YubiKey</h2>
        ${EDU_BADGE}
        <p style="margin:0 0 6px;font-size:15px;color:#e2e8f0">
          Step 1 of 2 — Simulated User Presence<br/>
          <span style="font-size:13px;color:#94a3b8">
            Touch the security key to confirm physical presence
          </span>
        </p>
        <div style="font-size:12px;color:#94a3b8;margin:12px 0 20px">
          Auto-cancel in <span id="yk-countdown">${secondsLeft}</span>s
        </div>
        <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
          <button class="yk-btn-primary" id="yk-touch-btn">👆 Touch YubiKey</button>
          <button class="yk-btn-cancel"  id="yk-cancel-btn">Cancel</button>
        </div>`;
    }

    // ── Step 2: PIN entry ──────────────────────────────────────────────────────
    function renderStep2(errorMsg = '') {
      const attemptsLeft = MAX_PIN_ATTEMPTS - pinAttempts;
      const hasStoredPin = !!storedPinHash;

      modal.innerHTML = `
        <div style="font-size:60px;margin-bottom:16px">✅</div>
        <h2 style="color:#00d4ff;margin:0 0 8px">Enter Your FIDO2 PIN</h2>
        <div style="background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.4);
                    color:#f59e0b;border-radius:8px;padding:6px 12px;font-size:12px;margin-bottom:14px">
          ⚠️ EDUCATIONAL DEMO — PIN verified against stored SHA-256 hash
        </div>
        <p style="margin:0 0 6px;font-size:15px;color:#e2e8f0">
          Step 2 of 2 — PIN Verification<br/>
          <span style="font-size:13px;color:#94a3b8">
            ${hasStoredPin
              ? 'Enter the PIN you set when you registered this key.'
              : 'No PIN was set for this key — any PIN (min 4 chars) is accepted.'}
          </span>
        </p>

        <div style="text-align:left;margin:16px 0 4px">
          <label style="font-size:13px;color:#94a3b8;display:block;margin-bottom:5px">🔑 PIN:</label>
          <input id="yk-pin-input" type="password" placeholder="Enter your PIN"
                 class="yk-input ${errorMsg ? 'error' : ''}"
                 autocomplete="current-password" />
          <div id="yk-pin-error"
               style="color:#ef4444;font-size:12px;margin-top:5px;min-height:16px">
            ${errorMsg}
          </div>
        </div>

        ${hasStoredPin ? `
          <div style="font-size:11px;color:#64748b;margin-bottom:14px;text-align:left">
            🔒 ${attemptsLeft} attempt${attemptsLeft !== 1 ? 's' : ''} remaining before lockout
          </div>` : ''}

        <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-top:8px">
          <button class="yk-btn-primary" id="yk-pin-btn">🔓 Confirm PIN</button>
          <button class="yk-btn-cancel"  id="yk-cancel-btn2">Cancel</button>
        </div>`;

      setTimeout(() => { const f = modal.querySelector('#yk-pin-input'); if (f) f.focus(); }, 30);
    }

    renderStep1();

    // Countdown ticker
    const countdownTimer = setInterval(() => {
      secondsLeft--;
      const el = modal.querySelector('#yk-countdown');
      if (el) el.textContent = secondsLeft;
      if (secondsLeft <= 0) clearInterval(countdownTimer);
    }, 1000);

    const cleanup = () => {
      clearInterval(countdownTimer);
      clearTimeout(timeoutHandle);
      removeOverlay();
    };

    const timeoutHandle = setTimeout(() => {
      cleanup();
      reject(new Error('USER_PRESENCE_TIMEOUT'));
    }, timeoutMs);

    // ── Event delegation ───────────────────────────────────────────────────────
    modal.addEventListener('click', async (e) => {
      // --- Touch button (Step 1) ---
      if (e.target.id === 'yk-touch-btn') {
        if (skipUV) {
          cleanup();
          resolve({ userPresence: true, userVerified: false });
        } else {
          renderStep2();
        }

      // --- Confirm PIN button (Step 2) ---
      } else if (e.target.id === 'yk-pin-btn') {
        const inp = modal.querySelector('#yk-pin-input');
        const pin = inp ? inp.value : '';

        // Length check
        if (pin.length < 4) {
          renderStep2('⚠️ PIN must be at least 4 characters.');
          return;
        }

        // If a PIN hash is stored, compare it
        if (storedPinHash) {
          const enteredHash = await hashPin(pin);
          if (enteredHash !== storedPinHash) {
            pinAttempts++;
            if (pinAttempts >= MAX_PIN_ATTEMPTS) {
              cleanup();
              reject(new Error('PIN_LOCKED: Too many incorrect PIN attempts. Authentication blocked.'));
              return;
            }
            const left = MAX_PIN_ATTEMPTS - pinAttempts;
            renderStep2(`❌ Incorrect PIN. ${left} attempt${left !== 1 ? 's' : ''} remaining.`);
            return;
          }
        }

        // ✅ PIN correct (or no stored PIN — any input accepted)
        cleanup();
        resolve({ userPresence: true, userVerified: true });

      // --- Cancel buttons ---
      } else if (e.target.id === 'yk-cancel-btn' || e.target.id === 'yk-cancel-btn2') {
        cleanup();
        reject(new Error('USER_PRESENCE_CANCELLED'));
      }
    });

    // Enter key submits
    modal.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const btn = modal.querySelector('#yk-pin-btn') || modal.querySelector('#yk-touch-btn');
        if (btn) btn.click();
      }
    });
  });
}

// ─── Core simulator API ─────────────────────────────────────────────────────────

/**
 * generateCredential()
 *
 * Called during registration.
 * 1. Shows a "Set PIN" modal — user chooses and confirms their PIN.
 * 2. Generates a real ECDSA P-256 key pair via Web Crypto API.
 * 3. Stores { privateJwk, pinHash } in localStorage (educational — never send to server).
 *
 * Returns { credentialId, publicKeySpki, registrationAuthData }
 *   registrationAuthData — simplified authenticatorData with UV flag for backend verification
 */
async function generateCredential() {
  // Step 0: User sets their PIN for this key
  const pinHash = await setupPin();

  // Step 1: Generate ECDSA P-256 key pair
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,         // extractable — needed to serialise for localStorage
    ['sign', 'verify']
  );

  // Export private key as JWK for localStorage persistence
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  // Export public key as SPKI (DER) — this is what goes to the server
  const publicSpkiBuf = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeySpki = arrayBufferToBase64(publicSpkiBuf);

  // Unique 16-byte credential ID
  const credIdBytes = new Uint8Array(16);
  crypto.getRandomValues(credIdBytes);
  const credentialId = arrayBufferToBase64url(credIdBytes.buffer);

  // Build a simplified registration authenticatorData so the backend can verify the UV flag.
  // Real format: rpIdHash(32) | flags(1) | signCount(4)
  // flags = 0x45:  bit0=UP, bit2=UV, bit6=AT (attested credential data present)
  const currentRpId = (typeof window !== 'undefined' && window.location.hostname) || 'localhost';
  const rpIdHash    = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(currentRpId));
  const flags       = new Uint8Array([0x45]); // UP=1, UV=1, AT=1
  const signCount   = new Uint8Array([0, 0, 0, 0]);
  const authDataBuf = new Uint8Array([
    ...new Uint8Array(rpIdHash),
    ...flags,
    ...signCount
  ]);
  const registrationAuthData = arrayBufferToBase64url(authDataBuf.buffer);

  // Persist { privateJwk, pinHash } in localStorage
  const creds = loadCredentials();
  creds[credentialId] = { privateJwk, credentialId, pinHash };
  saveCredentials(creds);

  console.log('[YubiKey Sim] Key pair generated. Credential ID:', credentialId);
  console.log('[YubiKey Sim] ⚠️  Private key + PIN hash stored in localStorage. NEVER send to server!');

  return { credentialId, publicKeySpki, registrationAuthData };
}

/**
 * signChallenge({ credentialId, challenge, origin, rpId,
 *                 requireUserPresence, skipUserPresence,
 *                 noUV, autoCancel })
 *
 * Called during authentication.
 * Shows the two-step (touch → PIN) modal; PIN is verified against the stored hash.
 * Sets authenticatorData flags accordingly:
 *   - Normal:              0x05  (UP=1, UV=1)
 *   - noUV=true:           0x01  (UP=1, UV=0) — for Test 4
 *   - skipUserPresence:    skips modal entirely (timeout/no-touch tests)
 *   - autoCancel:          immediately rejects with USER_PRESENCE_CANCELLED (Test 3)
 */
async function signChallenge({
  credentialId,
  challenge,
  origin,
  rpId               = 'localhost',
  requireUserPresence = true,
  skipUserPresence    = false,
  noUV               = false,   // if true, sign with UV bit NOT set (Test 4)
  autoCancel         = false    // if true, immediately cancel (Test 3)
}) {
  // 1. Simulate user presence and PIN verification
  let userVerified = false;
  if (requireUserPresence && !skipUserPresence) {
    const result = await requestUserPresenceAndVerification({
      credentialId,   // ← passed so PIN hash can be looked up
      autoCancel,
      skipUV: noUV
    });
    userVerified = result.userVerified;
  } else if (!skipUserPresence) {
    userVerified = !noUV;
  }

  // 2. Load private key from localStorage
  const creds  = loadCredentials();
  const stored = creds[credentialId];
  if (!stored) {
    throw new Error(
      'CREDENTIAL_NOT_FOUND: No private key found for credential ' + credentialId +
      '. Make sure you registered using this browser.'
    );
  }

  const privateKey = await crypto.subtle.importKey(
    'jwk',
    stored.privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  // 3. Build clientDataJSON — mirrors WebAuthn specification
  const clientData = {
    type:        'webauthn.get',
    challenge,
    origin,
    crossOrigin: false
  };
  const clientDataStr   = JSON.stringify(clientData);
  const clientDataBytes = new TextEncoder().encode(clientDataStr);
  const clientDataB64   = arrayBufferToBase64url(clientDataBytes.buffer);

  // 4. Build authenticatorData
  //    rpIdHash(32) | flags(1) | signCount(4)
  //    flags: bit0=UP, bit2=UV
  //    noUV=false → 0x05 (UP+UV),  noUV=true → 0x01 (UP only)
  const rpIdHash    = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId));
  const flagByte    = noUV ? 0x01 : 0x05;
  const flagsArr    = new Uint8Array([flagByte]);
  const signCount   = new Uint8Array([0, 0, 0, 1]);
  const authDataBuf = new Uint8Array([
    ...new Uint8Array(rpIdHash),
    ...flagsArr,
    ...signCount
  ]);
  const authDataB64 = arrayBufferToBase64url(authDataBuf.buffer);

  // 5. Compute signedData = authenticatorData || sha256(clientDataJSON)
  const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataBytes);
  const signedData     = new Uint8Array(authDataBuf.length + clientDataHash.byteLength);
  signedData.set(authDataBuf, 0);
  signedData.set(new Uint8Array(clientDataHash), authDataBuf.length);

  // 6. Sign with ECDSA P-256 (IEEE P1363, 64 bytes raw r||s)
  const sigBuf = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signedData);
  const sigB64 = arrayBufferToBase64url(sigBuf);

  console.log(`[YubiKey Sim] Signed. UV=${!noUV}, UP=true, flagByte=0x${flagByte.toString(16).padStart(2,'0')}`);

  return {
    signature:         sigB64,
    authenticatorData: authDataB64,
    clientDataJSON:    clientDataB64
  };
}

/** hasCredential(credentialId) — check if a private key exists for the given ID */
function hasCredential(credentialId) {
  return !!loadCredentials()[credentialId];
}

/** listCredentials() — returns all stored credential IDs (no private key data exposed) */
function listCredentials() {
  return Object.keys(loadCredentials());
}

/** clearCredentials() — wipes all credentials from localStorage */
function clearCredentials() {
  localStorage.removeItem(STORAGE_KEY);
}

export {
  generateCredential,
  signChallenge,
  hasCredential,
  listCredentials,
  clearCredentials
};
