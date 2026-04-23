const { app, BrowserWindow, Menu, ipcMain } = require('electron');
const path = require('path');
const SecurityManager = require('../modules/SecurityManager');
const PasswordManager = require('../modules/PasswordManager');

// Global references kept at module scope so they aren't garbage-collected
// while the app is running.
let mainWindow;
let securityManager;
let passwordManager;

// Creates and configures the main application window.
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    resizable: true,
    fullscreen: false,
    maximizable: true,
    useContentSize: true,
    webPreferences: {
      // nodeIntegration is disabled so renderer code cannot access Node APIs
      // directly — the preload script is the only bridge.
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js')
    },
    icon: path.join(__dirname, '../assets/icon.ico'),
    // Start hidden so the window isn't shown before it's ready to paint.
    show: false
  });

  // Open maximized for a full-screen-like first impression.
  mainWindow.maximize();

  // Remove the default OS menu bar (File, Edit, View…) so the app
  // feels like a native desktop tool rather than a browser window.
  Menu.setApplicationMenu(null);

  const startUrl = 'file://' + path.join(__dirname, '../assets/index.html');
  mainWindow.loadURL(startUrl);
  mainWindow.show();
}

// Electron fires 'ready' once the native environment is fully initialised.
// This is the earliest safe point to create windows or use native APIs.
app.on('ready', () => {
  securityManager = new SecurityManager();
  passwordManager = new PasswordManager(securityManager);
  createWindow();
  setupIPCHandlers();
});

// On Windows and Linux, closing all windows should exit the app.
// On macOS the convention is to keep the app running until Cmd+Q.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// macOS: re-create the window when the dock icon is clicked and no
// windows are currently open.
app.on('activate', () => {
  if (!mainWindow) {
    createWindow();
  }
});

// Registers all IPC (Inter-Process Communication) handlers.
// The renderer sends a channel name via window.api.*; these handlers
// run in the main process where Node and file-system access is allowed.
function setupIPCHandlers() {
  // Tells the renderer whether this is the very first time the app has
  // launched (i.e. no PIN has been configured yet).
  ipcMain.handle('is-first-launch', async () => {
    return securityManager.isFirstLaunch();
  });

  // Hashes and persists the user's 4-digit PIN.
  ipcMain.handle('setup-pin', async (event, pin) => {
    try { return await securityManager.setupPin(pin); }
    catch (error) { return { success: false, error: error.message }; }
  });

  // Encrypts the user's master encryption key using the PIN as the
  // wrapping secret, then saves it to disk.
  ipcMain.handle('setup-encryption-key', async (event, pin, encryptionKey) => {
    try { return await securityManager.setupEncryptionKey(pin, encryptionKey); }
    catch (error) { return { success: false, error: error.message }; }
  });

  // Compares the supplied PIN against the stored bcrypt hash.
  ipcMain.handle('verify-pin', async (event, pin) => {
    try { return await securityManager.verifyPin(pin); }
    catch (error) { return { success: false, error: error.message }; }
  });

  // Uses the PIN to unwrap and return the stored encryption key so
  // the renderer can hold it in memory for the current session.
  ipcMain.handle('decrypt-secret-key', async (event, pin) => {
    try { return await securityManager.decryptSecretKey(pin); }
    catch (error) { return { success: false, error: error.message }; }
  });

  // Validates the encryption key the user typed against its stored hash
  // without exposing the raw key to the comparison.
  ipcMain.handle('verify-encryption-key', async (event, encryptionKey) => {
    try {
      const isValid = await securityManager.verifyEncryptionKey(encryptionKey);
      return isValid ? { success: true } : { success: false, error: 'Invalid encryption key' };
    } catch (error) { return { success: false, error: error.message }; }
  });

  // Reads and decrypts every password entry from disk, returning them
  // as plain objects for the renderer to display.
  ipcMain.handle('get-passwords', async (event, encryptionKey) => {
    try {
      const passwords = await passwordManager.getAllPasswords(encryptionKey);
      return { success: true, data: passwords };
    } catch (error) { return { success: false, error: error.message }; }
  });

  // Encrypts a new password entry and writes it as an individual JSON
  // file, named by its UUID, inside the passwords directory.
  ipcMain.handle('add-password', async (event, passwordData, encryptionKey) => {
    try {
      const result = await passwordManager.addPassword(passwordData, encryptionKey);
      return { success: true, data: result };
    } catch (error) { return { success: false, error: error.message }; }
  });

  // Decrypts an existing entry, merges the supplied fields, re-encrypts,
  // and overwrites the file on disk.
  ipcMain.handle('update-password', async (event, id, passwordData, encryptionKey) => {
    try {
      const result = await passwordManager.updatePassword(id, passwordData, encryptionKey);
      return { success: true, data: result };
    } catch (error) { return { success: false, error: error.message }; }
  });

  // Permanently removes the JSON file for the given entry ID.
  ipcMain.handle('delete-password', async (event, id) => {
    try {
      await passwordManager.deletePassword(id);
      return { success: true };
    } catch (error) { return { success: false, error: error.message }; }
  });

  // Logout is handled entirely on the renderer side (clearing in-memory
  // keys). The main process just acknowledges the call.
  ipcMain.handle('logout', async () => {
    return { success: true };
  });
}
