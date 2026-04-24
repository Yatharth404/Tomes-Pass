// ============================================================
//  Application State
// ============================================================
const appState = {
    encryptionKey: null,
    currentPassword: null,
    currentView: 'list',
    currentCategory: 'all',
    passwords: [],
    inactivityTimer: null,
};

// ============================================================
//  Constants
// ============================================================
const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

// ============================================================
//  DOM Helpers — resolve once, guard against missing elements
// ============================================================
const screens = {
    loading:         document.getElementById('loadingScreen'),
    pinSetup:        document.getElementById('pinSetupScreen'),
    encryptionSetup: document.getElementById('encryptionSetupScreen'),
    login:           document.getElementById('loginScreen'),
    main:            document.getElementById('mainScreen'),
};

const views = {
    list:    document.getElementById('listView'),
    details: document.getElementById('detailsView'),
    edit:    document.getElementById('editView'),
};

// ============================================================
//  Initialisation
// ============================================================
async function initializeApp() {
    try {
        const isFirstLaunch = await window.api.isFirstLaunch(); // unified API name
        if (isFirstLaunch) {
            showScreen('pinSetup');
            setupPinForm();
        } else {
            showScreen('login');
            setupLoginForm();
        }
    } catch (error) {
        console.error('Initialization error:', error);
        showScreen('login');
        setupLoginForm();
    }
}

// ============================================================
//  Screen & View Management
// ============================================================
function showScreen(screenName) {
    Object.values(screens).forEach(screen => {
        if (!screen) return;
        screen.classList.remove('active');
        screen.classList.add('hidden');
    });

    const target = screens[screenName];
    if (target) {
        target.classList.remove('hidden');
        target.classList.add('active');
    }
}

function showView(viewName) {
    Object.values(views).forEach(view => {
        if (view) view.classList.remove('active');
    });

    const target = views[viewName];
    if (target) target.classList.add('active');

    appState.currentView = viewName;
}

// ============================================================
//  Inactivity Auto-Lock
// ============================================================
function resetInactivityTimer() {
    clearTimeout(appState.inactivityTimer);
    appState.inactivityTimer = setTimeout(() => {
        logout();
    }, INACTIVITY_TIMEOUT_MS);
}

function startInactivityTimer() {
    ['mousemove', 'keydown', 'click', 'scroll'].forEach(event => {
        document.addEventListener(event, resetInactivityTimer, { passive: true });
    });
    resetInactivityTimer();
}

function stopInactivityTimer() {
    clearTimeout(appState.inactivityTimer);
    ['mousemove', 'keydown', 'click', 'scroll'].forEach(event => {
        document.removeEventListener(event, resetInactivityTimer);
    });
}

// ============================================================
//  PIN Setup
// ============================================================
function setupPinForm() {
    const form       = document.getElementById('pinSetupForm');
    const pinInput   = document.getElementById('pinInput');
    const pinConfirm = document.getElementById('pinConfirm');
    const errorDiv   = document.getElementById('pinSetupError');

    // Restrict to 4 digits only
    [pinInput, pinConfirm].forEach(input => {
        if (!input) return;
        input.addEventListener('input', e => {
            e.target.value = e.target.value.replace(/\D/g, '').slice(0, 4);
        });
    });

    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        if (errorDiv) errorDiv.textContent = '';

        const pin     = pinInput?.value ?? '';
        const confirm = pinConfirm?.value ?? '';

        if (pin.length !== 4) {
            if (errorDiv) errorDiv.textContent = 'PIN must be exactly 4 digits.';
            return;
        }
        if (pin !== confirm) {
            if (errorDiv) errorDiv.textContent = 'PINs do not match.';
            return;
        }

        const result = await window.api.setupPin(pin);
        if (result.success) {
            showScreen('encryptionSetup');
            setupEncryptionForm(pin); // pass PIN so we don't re-read a cleared field
        } else {
            if (errorDiv) errorDiv.textContent = result.error;
        }
    });
}

// ============================================================
//  Encryption Key Setup
// ============================================================
function setupEncryptionForm(pin) {
    const form      = document.getElementById('encryptionSetupForm');
    const keyInput  = document.getElementById('encryptionKeyInput');
    const keyConfirm = document.getElementById('encryptionKeyConfirm');
    const errorDiv  = document.getElementById('encryptionSetupError');

    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        if (errorDiv) errorDiv.textContent = '';

        const key     = keyInput?.value ?? '';
        const confirm = keyConfirm?.value ?? '';

        if (key.length < 8) {
            if (errorDiv) errorDiv.textContent = 'Key must be at least 8 characters.';
            return;
        }
        if (key !== confirm) {
            if (errorDiv) errorDiv.textContent = 'Keys do not match.';
            return;
        }

        // Use PIN passed from setupPinForm — never re-read a possibly-cleared input
        const result = await window.api.setupEncryptionKey(pin, key);
        if (result.success) {
            showScreen('login');
            setupLoginForm();
        } else {
            if (errorDiv) errorDiv.textContent = result.error;
        }
    });
}

// ============================================================
//  Login
// ============================================================
function setupLoginForm() {
    const form      = document.getElementById('loginForm');
    const loginPin  = document.getElementById('loginPin');
    const loginKey  = document.getElementById('loginKey');
    const errorDiv  = document.getElementById('loginError');
    const toggleBtn = document.getElementById('toggleKeyVisibility');

    if (loginPin) {
        loginPin.addEventListener('input', e => {
            const pos = e.target.selectionStart;
            const next = e.target.value.replace(/\D/g, '').slice(0, 4);
            e.target.value = next;
            e.target.setSelectionRange(Math.min(pos, next.length), Math.min(pos, next.length));
        });
    }

    if (toggleBtn && loginKey) {
        toggleBtn.addEventListener('click', () => {
            loginKey.type = loginKey.type === 'password' ? 'text' : 'password';
        });
    }

    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        if (errorDiv) errorDiv.textContent = '';

        const pin           = loginPin?.value ?? '';
        const encryptionKey = loginKey?.value ?? '';

        if (pin.length !== 4) {
            if (errorDiv) errorDiv.textContent = 'PIN must be 4 digits.';
            return;
        }

        const pinResult = await window.api.verifyPin(pin);
        if (!pinResult.success) {
            if (errorDiv) errorDiv.textContent = 'Invalid PIN.';
            return;
        }

        const keyResult = await window.api.verifyEncryptionKey(encryptionKey);
        if (!keyResult.success) {
            if (errorDiv) errorDiv.textContent = 'Invalid encryption key.';
            return;
        }

        appState.encryptionKey = encryptionKey;
        showScreen('main');
        setupMainApp();
        showView('list');
        loadPasswords();
        startInactivityTimer();
    });
}

// ============================================================
//  Main App — Navigation & Global Event Setup
//  Called ONCE per session; uses event delegation where possible
// ============================================================
function setupMainApp() {
    // --- Category navigation ---
    const categoryMap = {
        allPasswordsBtn: { category: 'all',      title: 'All Passwords' },
        personalBtn:     { category: 'personal', title: 'Personal' },
        workBtn:         { category: 'work',      title: 'Work' },
        bankingBtn:      { category: 'banking',   title: 'Banking' },
    };

    Object.entries(categoryMap).forEach(([btnId, { category, title }]) => {
        const btn = document.getElementById(btnId);
        if (!btn) return;
        btn.addEventListener('click', () => {
            appState.currentCategory = category;
            updateNavigation(btnId, title);
            loadPasswords();
        });
    });

    // --- Add password ---
    document.getElementById('addPasswordBtn')?.addEventListener('click', () => {
        openEditView(null);
    });

    // --- Logout ---
    document.getElementById('logoutBtn')?.addEventListener('click', logout);

    // --- Back buttons ---
    document.querySelectorAll('.back-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            showView('list');
            await loadPasswords();
        });
    });

    // --- Password form ---
    document.getElementById('passwordForm')?.addEventListener('submit', handlePasswordFormSubmit);

    // --- Search ---
    document.getElementById('searchInput')?.addEventListener('input', () => {
        displayPasswords(appState.passwords);
    });

    // --- Modal ---
    document.querySelector('.modal-close')?.addEventListener('click', closeModal);
    document.getElementById('modal')?.addEventListener('click', e => {
        if (e.target === e.currentTarget) closeModal();
    });

    // Set default nav highlight
    document.getElementById('allPasswordsBtn')?.classList.add('active');
}

function updateNavigation(activeBtnId, title) {
    document.querySelectorAll('.nav-item').forEach(btn => btn.classList.remove('active'));
    document.getElementById(activeBtnId)?.classList.add('active');
    const viewTitle = document.getElementById('viewTitle');
    if (viewTitle) viewTitle.textContent = title;
}

// ============================================================
//  Password Loading & Display
// ============================================================
async function loadPasswords() {
    try {
        const result = await window.api.getPasswords(appState.encryptionKey);
        if (!result.success) return;

        appState.passwords = result.data;

        const searchInput = document.getElementById('searchInput');
        if (searchInput) searchInput.value = '';

        displayPasswords(appState.passwords);
    } catch (error) {
        console.error('Error loading passwords:', error);
    }
}

function displayPasswords(passwords) {
    const container = document.getElementById('passwordsList');
    if (!container) return;

    let filtered = passwords;

    if (appState.currentCategory !== 'all') {
        filtered = filtered.filter(p => p.category === appState.currentCategory);
    }

    const searchTerm = (document.getElementById('searchInput')?.value ?? '').toLowerCase();
    if (searchTerm) {
        filtered = filtered.filter(p =>
            p.title.toLowerCase().includes(searchTerm) ||
            p.username.toLowerCase().includes(searchTerm) ||
            (p.url ?? '').toLowerCase().includes(searchTerm)
        );
    }

    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No passwords found.</p></div>';
        return;
    }

    container.innerHTML = filtered.map(password => `
        <div class="password-item" data-id="${escapeHtml(password.id)}">
            <div class="password-item-info">
                <h3>${escapeHtml(password.title)}</h3>
                <div class="password-item-meta">${escapeHtml(password.username)}</div>
                <div class="password-item-category">${escapeHtml(password.category)}</div>
            </div>
            <div class="password-item-actions">
                <button class="btn btn-secondary view-btn" data-id="${escapeHtml(password.id)}">View</button>
                <button class="btn btn-danger delete-btn" data-id="${escapeHtml(password.id)}">Delete</button>
            </div>
        </div>
    `).join('');

    // Replace the container node to remove any previously accumulated
    // delegated click listeners before adding a fresh one.
    const fresh = container.cloneNode(true);
    container.parentNode.replaceChild(fresh, container);
    fresh.addEventListener('click', handlePasswordListClick);
}

function handlePasswordListClick(e) {
    const viewBtn   = e.target.closest('.view-btn');
    const deleteBtn = e.target.closest('.delete-btn');

    if (viewBtn) {
        showPasswordDetails(viewBtn.dataset.id);
    } else if (deleteBtn) {
        e.stopPropagation();
        confirmDelete(deleteBtn.dataset.id);
    }
}

// ============================================================
//  Password Details View
// ============================================================
function showPasswordDetails(id) {
    const password = appState.passwords.find(p => p.id === id);
    if (!password) return;

    appState.currentPassword = password;
    populateDetailsView(password);
    showView('details');
}

function populateDetailsView(password) {
    setTextContent('detailsTitle',    password.title);
    setTextContent('detailsTitle2',   password.title);
    setTextContent('detailsUsername', password.username);
    setTextContent('detailsUrl',      password.url      || 'N/A');
    setTextContent('detailsCategory', password.category);
    setTextContent('detailsNotes',    password.notes    || 'N/A');
    setTextContent('detailsCreated',  new Date(password.createdAt).toLocaleString());

    const passwordField = document.getElementById('detailsPassword');
    if (passwordField) {
        passwordField.textContent = '••••••••';
        passwordField.classList.add('masked');
    }

    // --- Toggle password visibility ---
    const toggleBtn = document.getElementById('togglePasswordBtn');
    if (toggleBtn) {
        // Clone to remove any previous listener
        const freshToggle = toggleBtn.cloneNode(true);
        toggleBtn.replaceWith(freshToggle);

        let visible = false;
        freshToggle.addEventListener('click', () => {
            visible = !visible;
            if (passwordField) {
                passwordField.textContent = visible ? password.password : '••••••••';
                passwordField.classList.toggle('masked', !visible);
            }
        });
    }

    // --- Copy buttons ---
    document.querySelectorAll('.copy-btn').forEach(btn => {
        const fresh = btn.cloneNode(true);
        btn.replaceWith(fresh);
        fresh.addEventListener('click', e => {
            e.preventDefault();
            copyToClipboard(password[fresh.dataset.copy], fresh);
        });
    });

    // --- Edit button ---
    const editBtn = document.getElementById('editPasswordBtn');
    if (editBtn) {
        const freshEdit = editBtn.cloneNode(true);
        editBtn.replaceWith(freshEdit);
        freshEdit.addEventListener('click', () => openEditView(password));
    }

    // --- Delete button ---
    const deleteBtn = document.getElementById('deletePasswordBtn');
    if (deleteBtn) {
        const freshDelete = deleteBtn.cloneNode(true);
        deleteBtn.replaceWith(freshDelete);
        freshDelete.addEventListener('click', () => {
            confirmDelete(password.id, password.title);
        });
    }
}

// ============================================================
//  Edit View
// ============================================================
function openEditView(password) {
    const editTitle = document.getElementById('editTitle');
    const form      = document.getElementById('passwordForm');
    const errorDiv  = document.getElementById('editError');

    if (editTitle) editTitle.textContent = password ? 'Edit Password' : 'Add New Password';
    if (errorDiv)  errorDiv.textContent  = '';
    if (form)      form.reset();

    if (password) {
        setInputValue('formTitle',    password.title);
        setInputValue('formUsername', password.username);
        setInputValue('formPassword', password.password);
        setInputValue('formUrl',      password.url);
        setInputValue('formCategory', password.category);
        setInputValue('formNotes',    password.notes);
    }

    appState.currentPassword = password ?? null;
    showView('edit');
}

async function handlePasswordFormSubmit(e) {
    e.preventDefault();

    const passwordData = {
        title:    document.getElementById('formTitle')?.value    ?? '',
        username: document.getElementById('formUsername')?.value ?? '',
        password: document.getElementById('formPassword')?.value ?? '',
        url:      document.getElementById('formUrl')?.value      ?? '',
        category: document.getElementById('formCategory')?.value ?? '',
        notes:    document.getElementById('formNotes')?.value    ?? '',
    };

    const errorDiv = document.getElementById('editError');
    if (errorDiv) errorDiv.textContent = '';

    try {
        let result;
        if (appState.currentPassword) {
            result = await window.api.updatePassword(
                appState.currentPassword.id,
                passwordData,
                appState.encryptionKey
            );
        } else {
            result = await window.api.addPassword(passwordData, appState.encryptionKey);
        }

        if (result.success) {
            showView('list');
            loadPasswords();
        } else {
            if (errorDiv) errorDiv.textContent = result.error;
        }
    } catch (error) {
        if (errorDiv) errorDiv.textContent = error.message;
    }
}

// ============================================================
//  Delete
// ============================================================
function confirmDelete(id, title = '') {
    const label = title ? `"${escapeHtml(title)}"` : 'this password';
    if (confirm(`Delete ${label}? This cannot be undone.`)) {
        deletePassword(id);
    }
}

async function deletePassword(id) {
    try {
        const result = await window.api.deletePassword(id);
        if (result.success) {
            // Remove from local state immediately (no extra round-trip)
            appState.passwords = appState.passwords.filter(p => p.id !== id);
            showView('list');
            displayPasswords(appState.passwords);
        }
    } catch (error) {
        console.error('Error deleting password:', error);
    }
}

// ============================================================
//  Logout
// ============================================================
async function logout() {
    // Overwrite the in-memory key string with zeros before nulling it so the
    // garbage collector doesn't leave the value sitting in freed heap memory.
    if (appState.encryptionKey) {
        appState.encryptionKey = '\0'.repeat(appState.encryptionKey.length);
    }

    appState.encryptionKey    = null;
    appState.currentPassword  = null;
    appState.passwords        = [];
    appState.currentCategory  = 'all';
    appState.currentView      = 'list';

    stopInactivityTimer();

    // Notify the main process so it can perform any server-side cleanup.
    await window.api.logout().catch(() => {});

    showView('list');
    showScreen('login');

    const loginForm = document.getElementById('loginForm');
    if (loginForm) loginForm.reset();
}

// ============================================================
//  Modal
// ============================================================
function closeModal() {
    document.getElementById('modal')?.classList.add('hidden');
}

// ============================================================
//  Utilities
// ============================================================
function copyToClipboard(text, button) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        const original = button.textContent;
        button.textContent = 'Copied!';
        button.classList.add('copied');

        // Auto-clear the clipboard after 30 seconds so copied passwords
        // aren't left available indefinitely.
        setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30_000);

        setTimeout(() => {
            button.textContent = original;
            button.classList.remove('copied');
        }, 2000);
    }).catch(err => {
        console.error('Clipboard error:', err);
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = String(text ?? '');
    return div.innerHTML;
}

function setTextContent(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = escapeHtml(value);
}

function setInputValue(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value ?? '';
}

// ============================================================
//  Boot
// ============================================================
window.addEventListener('DOMContentLoaded', initializeApp);


