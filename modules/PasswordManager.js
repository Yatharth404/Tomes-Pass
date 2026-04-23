const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { v4: uuidv4 } = require('uuid');

// All password data lives under ~/.tomes-pass/passwords/.
// Using the home directory makes the path consistent across user accounts
// and keeps the data outside the app bundle (important for auto-updates).
const DATA_BASE = path.join(os.homedir(), '.tomes-pass');
const PASSWORDS_DIR = path.join(DATA_BASE, 'passwords');

class PasswordManager {
  // SecurityManager is injected here so PasswordManager can delegate all
  // encryption and decryption work without reimplementing crypto logic.
  constructor(securityManager) {
    this.securityManager = securityManager;
  }

  // Creates the passwords directory if it doesn't exist yet.
  // { recursive: true } makes this a no-op when the folder already exists.
  async ensureDirs() {
    await fs.mkdir(PASSWORDS_DIR, { recursive: true });
  }

  // Resolves to true when a file exists and is accessible, false otherwise.
  // Using fs.access is more reliable than checking for an ENOENT error on read.
  async fileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  // Reads every .json file in the passwords directory, decrypts each one,
  // and returns them as an array of plain password objects.
  // Files that fail to decrypt are skipped so one corrupt entry doesn't
  // break access to the rest of the vault.
  async getAllPasswords(encryptionKey) {
    // Reject obviously invalid keys before hitting the file system.
    if (!encryptionKey || typeof encryptionKey !== 'string' || encryptionKey.length < 8) {
      return [];
    }

    await this.ensureDirs();

    const files = await fs.readdir(PASSWORDS_DIR);
    const passwords = [];

    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      try {
        const content = await fs.readFile(path.join(PASSWORDS_DIR, file), 'utf8');
        const encrypted = JSON.parse(content);
        const decrypted = this.securityManager.decryptData(encrypted, encryptionKey);
        passwords.push(decrypted);
      } catch (err) {
        // Log the bad file but keep iterating — partial vaults are better
        // than a complete read failure.
        console.error(`Skipping corrupted file ${file}:`, err.message);
      }
    }

    return passwords;
  }

  // Creates a new password entry with a UUID filename so entries never
  // collide, even if two are added at the exact same millisecond.
  async addPassword(passwordData, encryptionKey) {
    await this.ensureDirs();

    const id = uuidv4();
    const timestamp = new Date().toISOString();

    // Build the canonical password shape, filling optional fields with
    // safe defaults so downstream code never has to guard for undefined.
    const password = {
      id,
      title:    passwordData.title    || '',
      username: passwordData.username || '',
      password: passwordData.password || '',
      url:      passwordData.url      || '',
      category: passwordData.category || 'personal',
      notes:    passwordData.notes    || '',
      createdAt: timestamp,
      updatedAt: timestamp,
    };

    const encrypted = this.securityManager.encryptData(password, encryptionKey);
    await fs.writeFile(
      path.join(PASSWORDS_DIR, `${id}.json`),
      JSON.stringify(encrypted),
      'utf8'
    );

    // Return the plain object so the renderer can immediately add it to
    // the UI without needing to re-fetch the full list.
    return password;
  }

  // Loads an existing entry, merges only the fields that were supplied
  // (leaving the rest intact), then re-encrypts and overwrites the file.
  async updatePassword(id, passwordData, encryptionKey) {
    await this.ensureDirs();

    const filePath = path.join(PASSWORDS_DIR, `${id}.json`);
    if (!await this.fileExists(filePath)) {
      throw new Error('Password not found');
    }

    const content  = await fs.readFile(filePath, 'utf8');
    const existing = this.securityManager.decryptData(JSON.parse(content), encryptionKey);

    // Only overwrite a field when the caller explicitly sent a new value —
    // undefined means "leave it as-is", not "clear it".
    const updated = {
      ...existing,
      title:     passwordData.title     !== undefined ? passwordData.title     : existing.title,
      username:  passwordData.username  !== undefined ? passwordData.username  : existing.username,
      password:  passwordData.password  !== undefined ? passwordData.password  : existing.password,
      url:       passwordData.url       !== undefined ? passwordData.url       : existing.url,
      category:  passwordData.category  !== undefined ? passwordData.category  : existing.category,
      notes:     passwordData.notes     !== undefined ? passwordData.notes     : existing.notes,
      updatedAt: new Date().toISOString(),
    };

    const newEncrypted = this.securityManager.encryptData(updated, encryptionKey);
    await fs.writeFile(filePath, JSON.stringify(newEncrypted), 'utf8');

    return updated;
  }

  // Permanently removes the file for the given entry ID.
  // Throws if the file doesn't exist so the caller can surface the error.
  async deletePassword(id) {
    const filePath = path.join(PASSWORDS_DIR, `${id}.json`);
    if (!await this.fileExists(filePath)) {
      throw new Error('Password not found');
    }
    await fs.unlink(filePath);
  }
}

module.exports = PasswordManager;
