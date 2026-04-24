const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const os = require('os');

// Key material is stored under ~/.tomes-pass/keys/ as separate files
// so each piece can be read or rotated independently.
const DATA_BASE  = path.join(os.homedir(), '.tomes-pass');
const KEYS_DIR   = path.join(DATA_BASE, 'keys');

// bcrypt cost factor — 12 gives a good balance between brute-force resistance
// and acceptable wait time (~300 ms on a modern CPU).
const SALT_ROUNDS = 12;

// scrypt parameters — N must be a power of 2; r and p control memory/CPU cost.
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

class SecurityManager {
  constructor() {
    // In-memory copies of the key material loaded from disk.
    // These are only populated after initializeDirs() resolves.
    this.pinHash            = null;
    this.encryptedSecretKey = null;
    this.iv                 = null;
    this.encryptedKeyHash   = null;
    // Per-install random salt used for scrypt key derivation.
    // Loaded from disk on startup; generated on first run.
    this.scryptSalt         = null;
    this.initializeDirs();
  }

  // Creates the keys directory and loads any previously saved key material.
  // Called in the constructor — failures are caught so a bad disk state
  // doesn't prevent the app from starting.
  async initializeDirs() {
    try {
      await fs.mkdir(KEYS_DIR, { recursive: true });
      await this.loadKeys();
    } catch (error) {
      console.error('Failed to initialize directories:', error);
    }
  }

  // Populates the in-memory key fields by reading each key file if it exists.
  // Missing files are silently skipped — they simply mean the feature that
  // depends on that file hasn't been set up yet.
  async loadKeys() {
    const pinHashPath  = path.join(KEYS_DIR, 'pin.hash');
    const keyPath      = path.join(KEYS_DIR, 'key.enc');
    const ivPath       = path.join(KEYS_DIR, 'key.iv');
    const keyHashPath  = path.join(KEYS_DIR, 'key.hash');
    const saltPath     = path.join(KEYS_DIR, 'kdf.salt');

    if (await this.fileExists(pinHashPath))  this.pinHash            = await fs.readFile(pinHashPath, 'utf8');
    if (await this.fileExists(keyPath))      this.encryptedSecretKey = await fs.readFile(keyPath,     'utf8');
    if (await this.fileExists(ivPath))       this.iv                 = await fs.readFile(ivPath,      'utf8');
    if (await this.fileExists(keyHashPath))  this.encryptedKeyHash   = await fs.readFile(keyHashPath, 'utf8');

    // Load persisted scrypt salt, or generate and store a new one on first run.
    if (await this.fileExists(saltPath)) {
      this.scryptSalt = await fs.readFile(saltPath, 'utf8');
    } else {
      this.scryptSalt = crypto.randomBytes(32).toString('hex');
      await fs.writeFile(saltPath, this.scryptSalt, 'utf8');
    }
  }

  // Returns true when a file exists and can be accessed, false otherwise.
  async fileExists(filePath) {
    try { await fs.access(filePath); return true; }
    catch { return false; }
  }

  // The app is in "first launch" state when no PIN has been set yet.
  // The setup wizard is shown instead of the login screen in this case.
  isFirstLaunch() {
    return !this.pinHash;
  }

  // Validates that the PIN is exactly 4 numeric digits.
  isValidPin(pin) {
    return /^\d{4}$/.test(pin);
  }

  // Hashes the PIN with bcrypt and writes the hash to disk.
  // The raw PIN is never stored — only the hash is persisted.
  async setupPin(pin) {
    if (!this.isValidPin(pin)) {
      return { success: false, error: 'PIN must be exactly 4 digits' };
    }
    const hash = await bcrypt.hash(pin, SALT_ROUNDS);
    this.pinHash = hash;
    await fs.writeFile(path.join(KEYS_DIR, 'pin.hash'), hash, 'utf8');
    return { success: true };
  }

  // Wraps the user's master encryption key with the PIN as the wrapping secret.
  // Three files are written:
  //   key.enc  — the AES-256-CBC ciphertext of the encryption key
  //   key.iv   — the random IV used for that encryption
  //   key.hash — a bcrypt hash of the encryption key for later verification
  async setupEncryptionKey(pin, encryptionKey) {
    try {
      if (!this.pinHash) throw new Error('PIN not set up');
      const pinValid = await bcrypt.compare(pin, this.pinHash);
      if (!pinValid) throw new Error('Invalid PIN');

      if (!encryptionKey || encryptionKey.length < 8) {
        throw new Error('Encryption key must be at least 8 characters');
      }

      // Store a bcrypt hash so the key can be verified without decrypting it.
      const keyHash = await bcrypt.hash(encryptionKey, SALT_ROUNDS);
      this.encryptedKeyHash = keyHash;

      // Derive a 32-byte AES key from the PIN using scrypt with a
      // per-install random salt (prevents precomputed rainbow-table attacks).
      const saltBuf = Buffer.from(this.scryptSalt, 'hex');
      const key = await new Promise((resolve, reject) => {
        crypto.scrypt(pin, saltBuf, 32, SCRYPT_PARAMS, (err, derived) => {
          if (err) reject(err); else resolve(derived);
        });
      });
      const iv     = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      let encrypted = cipher.update(encryptionKey, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      this.encryptedSecretKey = encrypted;
      this.iv = iv.toString('hex');

      await fs.writeFile(path.join(KEYS_DIR, 'key.enc'),  encrypted, 'utf8');
      await fs.writeFile(path.join(KEYS_DIR, 'key.iv'),   this.iv,   'utf8');
      await fs.writeFile(path.join(KEYS_DIR, 'key.hash'), keyHash,   'utf8');

      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Compares the supplied PIN against the stored bcrypt hash.
  async verifyPin(pin) {
    try {
      if (!this.pinHash) throw new Error('PIN not set up');
      const isValid = await bcrypt.compare(pin, this.pinHash);
      return { success: isValid };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Verifies the PIN then uses it to unwrap the stored encryption key.
  // The returned key is held in the renderer's memory for the session
  // and is never written to disk in plain text.
  async decryptSecretKey(pin) {
    try {
      if (!this.pinHash) throw new Error('PIN not set up');
      const pinValid = await bcrypt.compare(pin, this.pinHash);
      if (!pinValid) throw new Error('Invalid PIN');
      if (!this.encryptedSecretKey || !this.iv) throw new Error('Encryption key not configured');

      const saltBuf = Buffer.from(this.scryptSalt, 'hex');
      const key = await new Promise((resolve, reject) => {
        crypto.scrypt(pin, saltBuf, 32, SCRYPT_PARAMS, (err, derived) => {
          if (err) reject(err); else resolve(derived);
        });
      });
      const iv       = Buffer.from(this.iv, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted  = decipher.update(this.encryptedSecretKey, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return { success: true, secretKey: decrypted };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Validates the user's encryption key against its bcrypt hash without
  // needing to decrypt anything — used on the login screen to confirm the
  // key is correct before granting vault access.
  async verifyEncryptionKey(encryptionKey) {
    try {
      if (!this.encryptedKeyHash) throw new Error('Encryption key not set up');
      return await bcrypt.compare(encryptionKey, this.encryptedKeyHash);
    } catch (error) {
      console.error('Error verifying encryption key:', error);
      return false;
    }
  }

  // Encrypts an arbitrary JS object to a { iv, kdfSalt, data } envelope using
  // AES-256-CBC. The per-install kdfSalt is embedded in the envelope so
  // decryption never relies on an ambient global — each file is self-describing.
  // A fresh random IV is generated per call so identical plaintext → different ciphertext.
  encryptData(data, encryptionKey) {
    const iv      = crypto.randomBytes(16);
    const salt    = this.scryptSalt ? Buffer.from(this.scryptSalt, 'hex') : crypto.randomBytes(32);
    const saltHex = salt.toString('hex');
    const key     = crypto.scryptSync(encryptionKey, salt, 32, SCRYPT_PARAMS);
    const cipher  = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    // kdfSalt is stored alongside the ciphertext so the file can always be
    // decrypted independently of whatever salt is currently loaded in memory.
    return { iv: iv.toString('hex'), kdfSalt: saltHex, data: encrypted };
  }

  // Decrypts a { iv, data } or { iv, kdfSalt, data } envelope.
  // — New format (kdfSalt present): uses the embedded salt — fully self-describing.
  // — Legacy format (no kdfSalt): falls back to the old hardcoded 'tomes-pass-salt'
  //   so passwords saved before v1.0.1 are transparently migrated on next save.
  decryptData(encrypted, encryptionKey) {
    let salt;
    if (encrypted.kdfSalt) {
      // New self-describing format introduced in v1.0.1
      salt = Buffer.from(encrypted.kdfSalt, 'hex');
    } else {
      // Legacy format — hardcoded salt used by v1.0.0
      salt = Buffer.from('tomes-pass-salt', 'utf8');
    }
    const key      = crypto.scryptSync(encryptionKey, salt, 32, SCRYPT_PARAMS);
    const iv       = Buffer.from(encrypted.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted  = decipher.update(encrypted.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  }
}

module.exports = SecurityManager;
