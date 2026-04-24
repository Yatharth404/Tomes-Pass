# Changelog

All notable changes to this project will be documented in this file.

---

## [1.0.1] - 2026-04-25 — Security Update

This release addresses **7 critical security vulnerabilities** discovered during a full source audit, plus a **backward-compatibility migration** to ensure passwords saved in v1.0.0 continue to load after the upgrade. No new features were added.

### 🔴 Critical Fixes

#### 1. Static scrypt Salt Replaced with Per-Install Random Salt (`SecurityManager.js`)
- **Severity:** Critical
- **Issue:** Every key derivation call used the hardcoded string `'tomes-pass-salt'` as the KDF salt. A static salt completely defeats the KDF — an attacker with the vault files can precompute a rainbow table for all 10,000 possible 4-digit PINs offline in minutes.
- **Fix:** A cryptographically random 32-byte salt is generated with `crypto.randomBytes(32)` on first launch and persisted to `~/.tomes-pass/keys/kdf.salt`. The salt is also embedded in every password envelope (`kdfSalt` field) so each file is self-describing and future-proof. Legacy files (no `kdfSalt`) transparently fall back to the old static salt for decryption and are re-encrypted to the new format on first login.

#### 2. No PIN Brute-Force Protection (`electron/main.js`)
- **Severity:** Critical
- **Issue:** The `verify-pin` IPC handler had no attempt counter or delay. All 10,000 PINs could be tried in a tight loop in under a second.
- **Fix:** Session-level counter; 5 failed attempts trigger a 30-second lockout returned as a user-visible error. Counter resets on success.

#### 3. Missing UUID Validation — Path Traversal (`modules/PasswordManager.js`)
- **Severity:** Critical
- **Issue:** `updatePassword(id)` and `deletePassword(id)` used the caller-supplied ID directly in `path.join(PASSWORDS_DIR, id + '.json')`. A crafted IPC call with `id = "../../keys/pin"` would delete the PIN hash, bypassing authentication entirely.
- **Fix:** New `isValidId(id)` method validates against a strict UUID v4 regex before any path construction. Both methods throw immediately on invalid input.

#### 4. Missing `webSecurity` and `sandbox` in BrowserWindow (`electron/main.js`)
- **Severity:** High
- **Issue:** Neither `webSecurity: true` nor `sandbox: true` was set in `webPreferences`.
- **Fix:** Both are now explicitly declared.

#### 5. Missing Content-Security-Policy (`assets/index.html`)
- **Severity:** High
- **Issue:** No CSP was present. An XSS via a crafted password title could execute arbitrary JS.
- **Fix:** Strict CSP meta tag: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';`

#### 6. Clipboard Not Cleared After Password Copy (`assets/renderer.js`)
- **Severity:** High
- **Issue:** Copied passwords remained in the system clipboard indefinitely.
- **Fix:** A 30-second `setTimeout` auto-clears the clipboard after every copy.

#### 7. Accumulating Event Listeners on Password List Re-render (`assets/renderer.js`)
- **Severity:** Medium
- **Issue:** `displayPasswords()` stacked a new `click` listener on the container every call. After many renders each click fired the handler dozens of times, enabling multi-delete race conditions.
- **Fix:** Container is replaced with a `cloneNode(true)` (stripping all listeners) before attaching one fresh delegated listener.

### Additional Fix

#### 8. Encryption Key Not Zeroed Before Nulling on Logout (`assets/renderer.js`)
- **Severity:** Medium
- **Issue:** `logout()` nulled `appState.encryptionKey` directly. The string value could remain readable in a V8 heap dump until GC ran.
- **Fix:** Key string is overwritten with null bytes before being nulled.

### 🔄 Migration

#### Transparent v1.0.0 → v1.0.1 Password Migration
- **Issue:** Passwords saved by v1.0.0 were encrypted with the old static salt and lacked the `kdfSalt` envelope field, making them unreadable by v1.0.1's new KDF path.
- **Fix:** `decryptData` detects the absence of `kdfSalt` and falls back to the legacy static salt for decryption. `getAllPasswords` then immediately re-encrypts any legacy file to the new self-describing format. Migration is silent and automatic on the first login after upgrading.

---

## [1.0.0] - 2026-04-23

- First stable release
- Added secure offline password manager
- Windows NSIS installer and portable EXE included
- Basic UI and password management features
- Implemented AES-256 encryption for password data
- Added PIN-based authentication with bcrypt hashing for security
- Offline storage in user home directory (~/.tomes-pass)
- Password management: add, view, edit, and delete password entries
- Simple and intuitive user interface built with HTML, CSS, and JavaScript
