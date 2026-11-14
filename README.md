# Passwordless Authentication System (FIDO2 / WebAuthn)

A complete, production-grade passwordless authentication web application featuring an in-browser **Software YubiKey Simulator**, a **Dual-Token Multi-YubiKey Recovery System**, and an **Automated Security Testing Dashboard** with 12 real-world attack vectors.

---

## 🚀 Key Features

* **Passwordless FIDO2 / WebAuthn Protocol:** End-to-end implementation of registration and authentication ceremonies adhering to W3C WebAuthn Level 2.
* **Cryptographic Foundation:** Asymmetric ECDSA over NIST curve P-256 (`secp256r1`) and SHA-256 (`ES256`, COSE alg `-7`), producing 64-byte IEEE P1363 signatures.
* **In-Browser Software YubiKey Simulator:** Built with the W3C Web Crypto API (`window.crypto.subtle`). Emulates physical capacitive touch (User Presence / UP) and on-device PIN verification (User Verification / UV) with anti-hammering lockout defense.
* **Dual-Token Multi-YubiKey Recovery:** Self-service account recovery via a registered Backup Key. Issues single-use 600s UUID recovery tokens and executes atomic revocation of lost primary keys.
* **Automated Security Testing Suite:** Interactive dashboard executing 12 automated test cases verifying defenses against replay attacks, origin spoofing (phishing), PIN bypass, revoked credentials, and token tampering.

---

## 🛠️ Tech Stack

* **Frontend:** React 18, Vite, Web Crypto API
* **Backend:** Node.js, Express.js, native `crypto` module, Express Session
* **Database:** MongoDB, Mongoose ORM

---

## 📦 Getting Started

### 1. Prerequisites
* [Node.js](https://nodejs.org/) (v16 or higher)
* [MongoDB](https://www.mongodb.com/) (running locally on `mongodb://localhost:27017` or MongoDB Atlas URI)

---

### 2. Backend Setup
```bash
cd backend
npm install
```

Create a `.env` file in `backend/` (you can copy `.env.example`):
```env
PORT=3001
MONGO_URI=mongodb://localhost:27017/usap_fido2
SESSION_SECRET=your_strong_session_secret_here
RP_ID=localhost
RP_ORIGIN=http://localhost:5173
CHALLENGE_TTL_SECONDS=120
RECOVERY_TOKEN_TTL_SECONDS=600
```

Start the backend server:
```bash
npm start
```
The backend server runs on `http://localhost:3001`.

---

### 3. Frontend Setup
In a new terminal window:
```bash
cd frontend
npm install
npm run dev
```
Open your browser and navigate to `http://localhost:5173`.

---

## 🧪 Security Testing
Navigate to the **Security Testing** page in the application to run the 12 automated security test cases:
1. Normal Primary Key Login (Baseline)
2. Normal Backup Key Login
3. User Verification Cancelled (Touch / PIN prompt cancelled)
4. User Verification Not Performed (`flags = 0x01`, UV missing)
5. Authenticator Timeout (No physical touch)
6. Revoked Primary Key Login Rejection
7. End-to-End Account Recovery via Backup Key
8. Old Primary Key Rejected Post-Recovery
9. Cross-User Credential Binding Rejection
10. Challenge Replay Attack Prevention
11. Recovery Token Single-Use Enforcement
12. Invalid / Expired Recovery Token Rejection

---

## 📄 License
MIT License
