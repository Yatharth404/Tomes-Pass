const { contextBridge, ipcRenderer } = require('electron');

// contextBridge.exposeInMainWorld safely injects an object called `window.api`
// into the renderer. Because contextIsolation is enabled, the renderer's
// JavaScript environment is completely separate from the Node/Electron world —
// this bridge is the only sanctioned way to cross that boundary.
//
// Each method wraps ipcRenderer.invoke, which sends a message to the
// corresponding ipcMain.handle registered in main.js and returns a Promise
// that resolves with whatever that handler returns.
contextBridge.exposeInMainWorld('api', {

  // ── First-launch detection ───────────────────────────────────────────────
  // Returns true when no PIN has been configured yet (fresh install).
  isFirstLaunch: () => ipcRenderer.invoke('is-first-launch'),

  // ── Setup flow ───────────────────────────────────────────────────────────
  // Hashes and stores a 4-digit PIN on first run.
  setupPin: (pin) => ipcRenderer.invoke('setup-pin', pin),

  // Wraps the master encryption key with the PIN and persists it to disk.
  setupEncryptionKey: (pin, encryptionKey) =>
    ipcRenderer.invoke('setup-encryption-key', pin, encryptionKey),

  // ── Authentication ───────────────────────────────────────────────────────
  // Checks the supplied PIN against the stored bcrypt hash.
  verifyPin: (pin) => ipcRenderer.invoke('verify-pin', pin),

  // Decrypts and returns the master key after a successful PIN check,
  // so the renderer can hold it in memory for the current session.
  decryptSecretKey: (pin) => ipcRenderer.invoke('decrypt-secret-key', pin),

  // Verifies the user-typed encryption key against its stored hash.
  verifyEncryptionKey: (encryptionKey) =>
    ipcRenderer.invoke('verify-encryption-key', encryptionKey),

  // ── Password vault CRUD ──────────────────────────────────────────────────
  // Fetches and decrypts all stored password entries.
  getPasswords: (encryptionKey) =>
    ipcRenderer.invoke('get-passwords', encryptionKey),

  // Encrypts and saves a new password entry.
  addPassword: (passwordData, encryptionKey) =>
    ipcRenderer.invoke('add-password', passwordData, encryptionKey),

  // Updates an existing entry by ID.
  updatePassword: (id, passwordData, encryptionKey) =>
    ipcRenderer.invoke('update-password', id, passwordData, encryptionKey),

  // Permanently deletes an entry by ID.
  deletePassword: (id) => ipcRenderer.invoke('delete-password', id),

  // ── Session ──────────────────────────────────────────────────────────────
  // Signals the main process that the user has logged out. The renderer is
  // responsible for clearing any in-memory keys before calling this.
  logout: () => ipcRenderer.invoke('logout'),
});
