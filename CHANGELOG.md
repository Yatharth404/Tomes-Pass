# Changelog

All notable changes to this project will be documented in this file.

---

## [1.0.1] - 2026-04-25 — Security Update

This release addresses **7 critical security vulnerabilities** discovered during a full source audit. No new features were added; all changes are security fixes.

### 🔴 Critical Fixes

#### 1. Static scrypt Salt Replaced with Per-Install Random Salt (`SecurityManager.js`)
- **Severity:** Critical
- **Issue:** `scryptSync` was called with the hardcoded string `'tomes-pass-salt'` as the KDF salt in every code path (PIN key wrapping, data encryption, data decryption). A hardcoded salt completely defeats the purpose of a KDF — an attacker who obtained a vault could precompute rainbow tables for all short PINs (10,000 possible 4-digit PINs) offline with trivial cost.
- **Fix:** A cryptographically random 32-byte salt is now generated with `crypto.randomBytes(32)` on first launch and persisted to `~/.tomes-pass/keys/kdf.salt`. All key-derivation calls use this salt. The synchronous `scryptSync` calls in the PIN-wrapping paths were replaced with async `crypto.scrypt` to avoid blocking the main process.

#### 2. No PIN Brute-Force Protection (`electron/main.js`)
- **Severity:** Critical
- **Issue:** The `verify-pin` IPC handler had zero rate limiting. An attacker with local access could iterate all 10,000 possible 4-digit PINs in seconds.
- **Fix:** A session-level counter tracks consecutive failures. After 5 failed attempts the handler enforces a 30-second lockout and returns an error with the remaining wait time. The counter resets on a successful verification.

#### 3. Missing UUID Validation — Path Traversal (`modules/PasswordManager.js`)
- **Severity:** Critical
- **Issue:** `updatePassword(id, ...)` and `deletePassword(id)` used the caller-supplied `id` directly in `path.join(PASSWORDS_DIR, \`${id}.json\`)` without validation. A malicious IPC call with `id = "../../keys/pin"` would overwrite or delete critical key files.
- **Fix:** A new `isValidId(id)` method validates the ID against a strict UUID v4 regex before any path construction. Both methods throw immediately if the ID fails validation.

#### 4. Missing `webSecurity` and `sandbox` in BrowserWindow (`electron/main.js`)
- **Severity:** High
- **Issue:** `webSecurity` was not explicitly set and `sandbox` was absent from `webPreferences`. This leaves the renderer able to load arbitrary `file://` URIs and removes OS-level sandbox isolation.
- **Fix:** `webSecurity: true` and `sandbox: true` are now explicitly declared in `webPreferences`.

#### 5. Missing Content-Security-Policy (`assets/index.html`)
- **Severity:** High
- **Issue:** No CSP was present. If any HTML injection occurred (e.g., via a maliciously crafted password title), an injected `<script>` tag would execute without restriction.
- **Fix:** A strict CSP meta tag was added: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';`. This blocks all inline scripts and all external resource loads.

#### 6. Clipboard Not Cleared After Password Copy (`assets/renderer.js`)
- **Severity:** High
- **Issue:** Copied passwords remained in the system clipboard indefinitely, accessible to any application with clipboard access.
- **Fix:** A 30-second `setTimeout` clears the clipboard automatically after every copy operation.

#### 7. Accumulating Event Listeners on Password List Re-render (`assets/renderer.js`)
- **Severity:** Medium
- **Issue:** `displayPasswords()` added a new `click` listener to the container every time it ran without removing the previous one. After many renders, each click fired the handler hundreds of times, enabling multi-delete race conditions.
- **Fix:** The container is replaced with a `cloneNode(true)` (stripping all listeners) before a single fresh delegated listener is attached.

### Additional Fix

#### 8. Encryption Key Not Zeroed Before Nulling on Logout (`assets/renderer.js`)
- **Severity:** Medium
- **Issue:** `logout()` set `appState.encryptionKey = null` directly. The original string could remain readable in a V8 heap dump until GC ran.
- **Fix:** The key string is now overwritten with null bytes before being nulled.

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
