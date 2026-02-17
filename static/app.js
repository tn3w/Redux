const state = {
    currentCode: '',
    currentToken: '',
    selectedLinks: new Set(),
    allLinks: [],
    deleteTarget: null,
    bulkEditData: null,
    customCode: '',
    customKey: '',
    requireCaptcha: false,
    showPage: false,
    csrfToken: '',
};

const views = {
    home: document.getElementById('home'),
    manage: document.getElementById('manage'),
    preview: document.getElementById('preview'),
    redirect: document.getElementById('redirect'),
    encrypted: document.getElementById('encrypted'),
    notFound: document.getElementById('not-found'),
    rateLimit: document.getElementById('rate-limit'),
    captchaPage: document.getElementById('captcha-page'),
};

const storage = {
    get: (code) => localStorage.getItem(`token_${code}`),
    set: (code, token) => localStorage.setItem(`token_${code}`, token),
    getAll: () => {
        const tokens = {};
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('token_')) {
                tokens[key.slice(6)] = localStorage.getItem(key);
            }
        }
        return tokens;
    },
};

function validateUrl(url) {
    if (!url || url.length < 10 || url.length > 2048) return false;
    if (!url.startsWith('https://')) return false;
    if (/[<>"'\0\n\r]/.test(url)) return false;
    try {
        const parsed = new URL(url);

        if (parsed.username || parsed.password) {
            return false;
        }

        const hostname = parsed.hostname;
        const currentHost = window.location.hostname;

        if (hostname === currentHost || hostname.endsWith('.' + currentHost)) {
            return false;
        }

        if (hostname === 'localhost' || hostname.endsWith('.local')) {
            return false;
        }

        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
            return false;
        }

        if (/^\[[\da-f:]+\]$/i.test(hostname)) {
            return false;
        }

        if (!/^[\x00-\x7F]*$/.test(hostname)) {
            return false;
        }

        if (hostname.includes('@') || hostname.includes('\\')) {
            return false;
        }

        if (
            !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(
                hostname
            )
        ) {
            return false;
        }

        if (hostname.length > 253) {
            return false;
        }

        const labels = hostname.split('.');
        if (labels.some((label) => label.length > 63)) {
            return false;
        }

        if (labels.length < 2) {
            return false;
        }

        return parsed.protocol === 'https:' && hostname;
    } catch {
        return false;
    }
}

function sanitizeUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'https:' ? parsed.href : null;
    } catch {
        return null;
    }
}

function getCsrfToken() {
    const match = document.cookie.match(/ripplit_csrf=([^;]+)/);
    return match ? match[1] : '';
}

function updateCsrfToken() {
    state.csrfToken = getCsrfToken();
}

function showError(message) {
    const error = document.getElementById('error');
    error.textContent = message;
    error.classList.add('show');
}

function showView(name) {
    Object.values(views).forEach((v) => v.classList.add('hidden'));
    views[name].classList.remove('hidden');
    document.querySelectorAll('.nav-link').forEach((link) => {
        link.classList.toggle('active', link.dataset.view === name);
    });

    if (name === 'manage') {
        window.history.replaceState(null, '', '/#manage');
    } else if (name === 'home') {
        window.history.replaceState(null, '', '/');
    }
}

function generateToken() {
    const array = new Uint8Array(14);
    crypto.getRandomValues(array);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    return Array.from(array, (b) => chars[b % 64]).join('');
}

async function encryptUrl(url, token) {
    const encoder = new TextEncoder();
    const tokenData = encoder.encode(token.padEnd(16, '_'));
    const keyMaterial = await crypto.subtle.importKey('raw', tokenData, 'PBKDF2', false, [
        'deriveKey',
    ]);
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: encoder.encode('Ripplit'),
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoder.encode(url)
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...combined))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

async function decryptUrl(encrypted, token) {
    const encoder = new TextEncoder();
    const tokenData = encoder.encode(token.padEnd(16, '_'));
    const keyMaterial = await crypto.subtle.importKey('raw', tokenData, 'PBKDF2', false, [
        'deriveKey',
    ]);
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: encoder.encode('Ripplit'),
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
    const data = Uint8Array.from(atob(encrypted.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
        c.charCodeAt(0)
    );
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
}

async function generateSignature(url, token) {
    const encoder = new TextEncoder();
    const tokenData = encoder.encode(token.padEnd(32, '_'));

    const key = await crypto.subtle.importKey(
        'raw',
        tokenData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(url));

    const signatureArray = Array.from(new Uint8Array(signature));
    return signatureArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifySignature(url, token, expectedSignature) {
    const encoder = new TextEncoder();
    const tokenData = encoder.encode(token.padEnd(32, '_'));

    const key = await crypto.subtle.importKey(
        'raw',
        tokenData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
    );

    const signatureBytes = new Uint8Array(
        expectedSignature.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
    );

    return await crypto.subtle.verify('HMAC', key, signatureBytes, encoder.encode(url));
}

document.getElementById('settings-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    const dropdown = document.getElementById('settings-dropdown');
    const isVisible = dropdown.classList.contains('show');
    dropdown.classList.toggle('show');
    if (!isVisible) {
        document.getElementById('custom-code-input').value = state.customCode;
        document.getElementById('custom-key-input').value = state.customKey;
        document.getElementById('require-captcha-input').checked = state.requireCaptcha;
        document.getElementById('show-page-input').checked = state.showPage;
        const encryptEnabled = document.getElementById('encrypt').checked;
        document.getElementById('custom-key-input').disabled = !encryptEnabled;
        updateShowPageState(encryptEnabled);
    }
});

function updateShowPageState(encryptEnabled) {
    const showPageInput = document.getElementById('show-page-input');
    if (encryptEnabled) {
        showPageInput.checked = true;
        showPageInput.disabled = true;
        state.showPage = true;
    } else {
        showPageInput.disabled = false;
    }
}

document.getElementById('encrypt').addEventListener('change', (e) => {
    const dropdown = document.getElementById('settings-dropdown');
    if (dropdown.classList.contains('show')) {
        document.getElementById('custom-key-input').disabled = !e.target.checked;
        if (!e.target.checked) {
            document.getElementById('custom-key-input').value = '';
            state.customKey = '';
        }
        updateShowPageState(e.target.checked);
    }
});

const urlInput = document.getElementById('url');
const urlClear = document.getElementById('url-clear');

function updateClearButton() {
    if (urlInput.value.trim()) {
        urlClear.classList.add('show');
    } else {
        urlClear.classList.remove('show');
    }
}

urlInput.addEventListener('input', updateClearButton);

urlClear.addEventListener('click', () => {
    urlInput.value = '';
    urlClear.classList.remove('show');
    urlInput.focus();
});

document.getElementById('custom-code-input').addEventListener('input', (e) => {
    state.customCode = e.target.value.trim();
});

document.getElementById('custom-key-input').addEventListener('input', (e) => {
    state.customKey = e.target.value.trim();
});

document.getElementById('require-captcha-input').addEventListener('change', (e) => {
    state.requireCaptcha = e.target.checked;
});

document.getElementById('show-page-input').addEventListener('change', (e) => {
    state.showPage = e.target.checked;
});

document.querySelectorAll('.help-icon').forEach((icon) => {
    icon.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const helpId = e.currentTarget.dataset.help;
        const tooltip = document.getElementById(`help-${helpId}`);
        const isVisible = tooltip.classList.contains('show');

        document.querySelectorAll('.help-tooltip').forEach((t) => t.classList.remove('show'));

        if (!isVisible) {
            tooltip.classList.add('show');
        }
    });
});

document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('settings-dropdown');
    const settingsBtn = document.getElementById('settings-btn');
    if (!dropdown.contains(e.target) && !settingsBtn.contains(e.target)) {
        dropdown.classList.remove('show');
        document.querySelectorAll('.help-tooltip').forEach((t) => t.classList.remove('show'));
    }
});

document.getElementById('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const error = document.getElementById('error');
    const result = document.getElementById('result');
    const urlInput = document.getElementById('url');
    const encryptToggle = document.getElementById('encrypt');
    const submitButton = e.target.querySelector('button[type="submit"]');

    error.classList.remove('show');
    result.classList.remove('show');

    updateCsrfToken();

    const rawUrl = urlInput.value.trim();
    const customCode = state.customCode;

    if (customCode) {
        if (customCode.length === 6) {
            return showError('Custom code cannot be exactly 6 characters');
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(customCode)) {
            return showError('Custom code can only contain letters, numbers, _ and -');
        }
        if (customCode.length > 24) {
            return showError('Custom code too long (max 24 characters)');
        }
        if (customCode.startsWith('-') || customCode.endsWith('-')) {
            return showError('Custom code cannot start or end with -');
        }
    }

    if (!validateUrl(rawUrl)) {
        return showError('Cannot shorten URLs to this domain');
    }

    const sanitized = sanitizeUrl(rawUrl);
    if (!sanitized) {
        return showError('Invalid URL');
    }

    submitButton.disabled = true;
    const originalText = submitButton.textContent;
    submitButton.textContent = 'Loading...';

    try {
        let urlToSend = sanitized;
        let signature = null;
        if (encryptToggle.checked) {
            state.currentToken = state.customKey || generateToken();
            urlToSend = await encryptUrl(sanitized, state.currentToken);
            signature = await generateSignature(sanitized, state.currentToken);
        }

        const requestData = {
            url: urlToSend,
            encrypted: encryptToggle.checked,
            signature,
            require_captcha: state.requireCaptcha,
            show_page: state.showPage || encryptToggle.checked,
            csrf_token: state.csrfToken,
        };

        if (customCode) {
            requestData.custom_code = customCode;
        }

        let code;
        try {
            code = await window.captchaHandler.handleSubmit(requestData, submitButton);
        } catch (err) {
            submitButton.disabled = false;
            submitButton.textContent = originalText;
            throw err;
        }

        if (!code) {
            submitButton.disabled = false;
            submitButton.textContent = originalText;
            return;
        }

        state.currentCode = code;
        const finalUrl = encryptToggle.checked
            ? `${window.location.origin}/${code}#${state.currentToken}`
            : `${window.location.origin}/${code}`;

        if (encryptToggle.checked) {
            storage.set(state.currentCode, state.currentToken);
        }

        document.getElementById('short-url').textContent = finalUrl;
        result.classList.add('show');
        urlInput.value = '';
        urlClear.classList.remove('show');
        state.customCode = '';
        document.getElementById('custom-code-input').value = '';
    } catch (err) {
        const errorMsg = err.message || 'Network error - please try again';
        if (errorMsg.includes('Rate limit')) {
            showError('Rate limit exceeded - please wait before creating more links');
        } else {
            showError(errorMsg);
        }
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
});

document.getElementById('copy').addEventListener('click', () => {
    const shortUrl = document.getElementById('short-url').textContent;
    const button = document.getElementById('copy');
    navigator.clipboard.writeText(shortUrl).then(
        () => {
            button.textContent = 'Copied!';
            setTimeout(() => (button.textContent = 'Copy'), 2000);
        },
        () => {
            button.textContent = 'Failed';
            setTimeout(() => (button.textContent = 'Copy'), 2000);
        }
    );
});

document.getElementById('preview-btn').addEventListener('click', () => {
    const url = state.currentToken
        ? `/${state.currentCode}+#${state.currentToken}`
        : `/${state.currentCode}+`;
    window.open(url, '_blank');
});

document.getElementById('result-close').addEventListener('click', () => {
    document.getElementById('result').classList.remove('show');
    state.currentCode = '';
    state.currentToken = '';
});

document.querySelectorAll('[data-view]').forEach((link) => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const view = e.target.dataset.view;
        if (view === 'manage') {
            updateCsrfToken();
            loadManageView();
        }
        showView(view);
    });
});

async function loadManageView() {
    const list = document.getElementById('links');
    const stats = document.getElementById('stats');
    list.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const response = await fetch('/api/links');
        updateCsrfToken();

        if (!response.ok) {
            const text = await response.text();
            let errorMsg = 'Failed to load links';
            try {
                const data = JSON.parse(text);
                errorMsg = data.error || errorMsg;
            } catch {}
            throw new Error(errorMsg);
        }

        const links = await response.json();
        state.allLinks = links;
        state.selectedLinks.clear();
        updateSelectAllCheckbox();

        stats.textContent = `${links.length} link${links.length !== 1 ? 's' : ''}`;

        if (links.length === 0) {
            const emptyDiv = document.createElement('div');
            emptyDiv.className = 'loading';
            emptyDiv.textContent = 'No links yet';
            list.textContent = '';
            list.appendChild(emptyDiv);
            return;
        }

        const tokens = storage.getAll();
        list.textContent = '';

        links.forEach((link) => {
            const li = createLinkItem(link, tokens);
            list.appendChild(li);
        });

        attachLinkEventListeners();
    } catch (err) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'loading';
        errorDiv.textContent = err.message || 'Failed to load';
        list.textContent = '';
        list.appendChild(errorDiv);
    }
}

function createLinkItem(link, tokens) {
    const li = document.createElement('li');
    li.className = 'link-item';
    li.id = `item-${link.code}`;

    const header = document.createElement('div');
    header.className = 'link-header';

    const left = document.createElement('div');
    left.className = 'link-left';

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'checkbox link-select';
    checkbox.dataset.code = link.code;

    const codeDiv = document.createElement('div');
    codeDiv.className = 'link-code';
    codeDiv.textContent = `/${link.code}`;

    const badge = document.createElement('span');
    badge.className = 'link-badge';
    badge.textContent = link.encrypted ? 'Encrypted' : 'Public';

    const urlDiv = document.createElement('div');
    urlDiv.className = 'link-url';
    urlDiv.id = `url-${link.code}`;

    let displayUrl = link.original_url;
    if (link.encrypted) {
        const token = tokens[link.code];
        if (token) {
            displayUrl = '(Decrypting...)';
            urlDiv.classList.add('encrypted');
            decryptUrl(link.original_url, token)
                .then((url) => {
                    const elem = document.getElementById(`url-${link.code}`);
                    const editInput = document.getElementById(`edit-input-${link.code}`);
                    if (elem) {
                        elem.textContent = url;
                        elem.classList.remove('encrypted');
                    }
                    if (editInput) {
                        editInput.value = url;
                        editInput.dataset.decrypted = 'true';
                    }
                })
                .catch(() => {
                    const elem = document.getElementById(`url-${link.code}`);
                    if (elem) elem.textContent = '(Failed to decrypt)';
                });
        } else {
            displayUrl = '(Encrypted - token required)';
            urlDiv.classList.add('encrypted');
        }
    }
    urlDiv.textContent = displayUrl;

    left.append(checkbox, codeDiv, badge, urlDiv);

    const right = document.createElement('div');
    right.className = 'link-right';

    const meta = document.createElement('div');
    meta.className = 'link-meta';

    const clicks = document.createElement('span');
    clicks.textContent = `${link.clicks} clicks`;

    const created = document.createElement('span');
    const createdDate = new Date(link.created_at * 1000);
    created.textContent = createdDate.toLocaleDateString();

    meta.append(clicks, created);
    right.appendChild(meta);
    header.append(left, right);

    const editDiv = document.createElement('div');
    editDiv.className = 'link-edit';
    editDiv.id = `edit-${link.code}`;

    const editInput = document.createElement('input');
    editInput.type = 'url';
    editInput.id = `edit-input-${link.code}`;
    editInput.value = link.encrypted ? '' : link.original_url;
    editInput.placeholder = 'New URL';
    editInput.dataset.decrypted = 'false';

    const editActions = document.createElement('div');
    editActions.className = 'actions';

    const hasToken = link.encrypted && tokens[link.code];
    const saveBtn = createButton('Save', 'save', link.code, {
        encrypted: link.encrypted,
        hasToken: !!hasToken,
    });
    const cancelBtn = createButton('Cancel', 'cancel', link.code);

    editActions.append(saveBtn, cancelBtn);
    editDiv.append(editInput, editActions);

    const actions = document.createElement('div');
    actions.className = 'actions';

    const copyBtn = createButton('Copy', 'copy', link.code, {
        hasToken: !!hasToken,
    });
    const previewBtn = createButton('Preview', 'preview', link.code, {
        hasToken: !!hasToken,
    });
    const editBtn = createButton('Edit', 'edit', link.code);
    const deleteBtn = createButton('Delete', 'delete', link.code);

    actions.append(copyBtn, previewBtn, editBtn, deleteBtn);
    li.append(header, editDiv, actions);

    return li;
}

function createButton(text, action, code, extra = {}) {
    const btn = document.createElement('button');
    btn.className = 'btn-small';
    btn.textContent = text;
    btn.dataset.action = action;
    btn.dataset.code = code;
    if (extra.encrypted !== undefined) {
        btn.dataset.encrypted = extra.encrypted;
    }
    if (extra.hasToken !== undefined) {
        btn.dataset.hasToken = extra.hasToken;
    }
    return btn;
}

function attachLinkEventListeners() {
    document.querySelectorAll('.link-select').forEach((checkbox) => {
        checkbox.addEventListener('change', (e) => {
            const code = e.target.dataset.code;
            const item = document.getElementById(`item-${code}`);
            if (e.target.checked) {
                state.selectedLinks.add(code);
                item.classList.add('selected');
            } else {
                state.selectedLinks.delete(code);
                item.classList.remove('selected');
            }
            updateSelectAllCheckbox();
        });
    });

    document.querySelectorAll('[data-action]').forEach((button) => {
        button.addEventListener('click', (e) => {
            const { action, code, hasToken, encrypted } = e.target.dataset;
            if (action === 'copy') copyLink(code, hasToken === 'true');
            else if (action === 'preview') {
                const token = hasToken === 'true' ? storage.get(code) : '';
                const url = token ? `/${code}+#${token}` : `/${code}+`;
                window.open(url, '_blank');
            } else if (action === 'edit') {
                document.getElementById(`edit-${code}`).classList.add('show');
            } else if (action === 'cancel') {
                document.getElementById(`edit-${code}`).classList.remove('show');
            } else if (action === 'save') {
                saveEdit(code, encrypted === 'true', hasToken === 'true');
            } else if (action === 'delete') deleteLink(code);
        });
    });
}

function copyLink(code, hasToken) {
    const token = hasToken ? storage.get(code) : '';
    const url = token
        ? `${window.location.origin}/${code}#${token}`
        : `${window.location.origin}/${code}`;
    navigator.clipboard.writeText(url);
    const button = event.target;
    const originalText = button.textContent;
    button.textContent = 'Copied!';
    setTimeout(() => (button.textContent = originalText), 2000);
}

async function saveEdit(code, isEncrypted, hasToken) {
    const input = document.getElementById(`edit-input-${code}`);
    const newUrl = input.value.trim();

    if (!newUrl) {
        return showError('URL cannot be empty');
    }

    if (!validateUrl(newUrl)) {
        return showError('Cannot shorten URLs to this domain');
    }

    const sanitized = sanitizeUrl(newUrl);
    if (!sanitized) {
        return showError('Invalid URL');
    }

    updateCsrfToken();

    try {
        let urlToSend = sanitized;
        let signature = null;
        if (isEncrypted && hasToken) {
            const token = storage.get(code);
            urlToSend = await encryptUrl(sanitized, token);
            signature = await generateSignature(sanitized, token);
        }

        const response = await fetch(`/api/links/${code}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: urlToSend,
                encrypted: isEncrypted,
                signature,
                csrf_token: state.csrfToken,
            }),
        });

        updateCsrfToken();

        if (!response.ok) {
            const text = await response.text();
            let errorMsg = 'Failed to update link';
            try {
                const data = JSON.parse(text);
                errorMsg = data.error || errorMsg;
            } catch {}
            throw new Error(errorMsg);
        }

        const data = await response.json();
        if (data.success) {
            loadManageView();
        } else {
            showError(data.error || 'Failed to update link');
        }
    } catch (err) {
        showError(err.message || 'Failed to update link');
    }
}

function deleteLink(code) {
    state.deleteTarget = code;
    document.getElementById('delete-message').textContent =
        'Are you sure you want to delete this link? This action cannot be undone.';
    document.getElementById('delete-modal').classList.add('show');
}

document.getElementById('select-all').addEventListener('change', (e) => {
    const checkboxes = document.querySelectorAll('.link-select');
    checkboxes.forEach((checkbox) => {
        checkbox.checked = e.target.checked;
        const code = checkbox.dataset.code;
        const item = document.getElementById(`item-${code}`);
        if (e.target.checked) {
            state.selectedLinks.add(code);
            item.classList.add('selected');
        } else {
            state.selectedLinks.delete(code);
            item.classList.remove('selected');
        }
    });
    updateSelectAllCheckbox();
});

document.getElementById('clear').addEventListener('click', () => {
    state.selectedLinks.clear();
    document.querySelectorAll('.link-select').forEach((cb) => (cb.checked = false));
    document.querySelectorAll('.link-item').forEach((item) => {
        item.classList.remove('selected');
    });
    updateSelectAllCheckbox();
});

function updateSelectAllCheckbox() {
    const selectAll = document.getElementById('select-all');
    const actionsLabel = document.getElementById('actions-label');
    const checkboxes = document.querySelectorAll('.link-select');
    const checkedCount = Array.from(checkboxes).filter((cb) => cb.checked).length;

    selectAll.checked = checkboxes.length > 0 && checkedCount === checkboxes.length;
    selectAll.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;

    actionsLabel.textContent =
        state.selectedLinks.size > 0 ? `${state.selectedLinks.size} selected` : 'Select All';
}

document.getElementById('bulk-delete').addEventListener('click', () => {
    if (state.selectedLinks.size === 0) return;
    state.deleteTarget = Array.from(state.selectedLinks);
    document.getElementById('delete-message').textContent =
        `Are you sure you want to delete ${state.selectedLinks.size} ` +
        `link${state.selectedLinks.size !== 1 ? 's' : ''}? ` +
        'This action cannot be undone.';
    document.getElementById('delete-modal').classList.add('show');
});

document.getElementById('cancel-delete').addEventListener('click', () => {
    document.getElementById('delete-modal').classList.remove('show');
    state.deleteTarget = null;
});

document.getElementById('confirm-delete').addEventListener('click', async () => {
    if (!state.deleteTarget) return;

    updateCsrfToken();

    try {
        const deletedCodes = Array.isArray(state.deleteTarget)
            ? state.deleteTarget
            : [state.deleteTarget];

        let response;
        if (Array.isArray(state.deleteTarget)) {
            response = await fetch('/api/links/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    codes: state.deleteTarget,
                    csrf_token: state.csrfToken,
                }),
            });
        } else {
            response = await fetch(`/api/links/${state.deleteTarget}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': state.csrfToken,
                },
            });
        }

        updateCsrfToken();

        if (!response.ok) {
            const text = await response.text();
            let errorMsg = 'Failed to delete link(s)';
            try {
                const data = JSON.parse(text);
                errorMsg = data.error || errorMsg;
            } catch {}
            throw new Error(errorMsg);
        }

        if (deletedCodes.includes(state.currentCode)) {
            document.getElementById('result').classList.remove('show');
            state.currentCode = '';
            state.currentToken = '';
        }

        document.getElementById('delete-modal').classList.remove('show');
        state.deleteTarget = null;
        state.selectedLinks.clear();
        loadManageView();
    } catch (err) {
        showError(err.message || 'Failed to delete link(s)');
    }
});

document.getElementById('bulk-edit').addEventListener('click', async () => {
    if (state.selectedLinks.size === 0) return;
    const tokens = storage.getAll();
    state.bulkEditData = await Promise.all(
        Array.from(state.selectedLinks).map(async (code) => {
            const link = state.allLinks.find((l) => l.code === code);
            if (!link) return null;
            let displayUrl = link.original_url;
            if (link.encrypted) {
                const token = tokens[code];
                if (token) {
                    try {
                        displayUrl = await decryptUrl(link.original_url, token);
                    } catch {
                        displayUrl = '';
                    }
                } else {
                    displayUrl = '';
                }
            }
            return {
                code,
                originalUrl: displayUrl,
                encrypted: link.encrypted,
                token: tokens[code],
            };
        })
    );
    state.bulkEditData = state.bulkEditData.filter(Boolean);
    document.getElementById('bulk-find').value = '';
    document.getElementById('bulk-replace').value = '';
    updateBulkEditPreview();
    document.getElementById('bulk-edit-modal').classList.add('show');
});

function updateBulkEditPreview() {
    const findPattern = document.getElementById('bulk-find').value;
    const replacePattern = document.getElementById('bulk-replace').value;
    const preview = document.getElementById('bulk-preview');

    preview.textContent = '';

    if (!state.bulkEditData || state.bulkEditData.length === 0) {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'loading';
        emptyDiv.textContent = 'No links to edit';
        preview.appendChild(emptyDiv);
        return;
    }

    let regex;
    try {
        regex = findPattern ? new RegExp(findPattern, 'g') : null;
    } catch {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'loading';
        errorDiv.textContent = 'Invalid regex';
        preview.appendChild(errorDiv);
        return;
    }

    state.bulkEditData.forEach((item) => {
        const oldUrl = item.originalUrl;
        const newUrl = regex ? oldUrl.replace(regex, replacePattern) : oldUrl;
        const changed = oldUrl !== newUrl;

        const itemDiv = document.createElement('div');
        itemDiv.className = 'preview-item';

        const codeDiv = document.createElement('div');
        codeDiv.className = 'preview-code';
        codeDiv.textContent = `/${item.code}`;

        const oldDiv = document.createElement('div');
        oldDiv.className = 'preview-old';
        oldDiv.textContent = oldUrl || '(encrypted - no token)';

        const newDiv = document.createElement('div');
        newDiv.className = 'preview-new';
        if (!changed) newDiv.style.color = '#888';
        newDiv.textContent = newUrl || '(encrypted - no token)';

        itemDiv.append(codeDiv, oldDiv, newDiv);
        preview.appendChild(itemDiv);
    });

    if (preview.children.length === 0) {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'loading';
        emptyDiv.textContent = 'No changes';
        preview.appendChild(emptyDiv);
    }
}

document.getElementById('bulk-find').addEventListener('input', updateBulkEditPreview);
document.getElementById('bulk-replace').addEventListener('input', updateBulkEditPreview);

document.getElementById('cancel-bulk').addEventListener('click', () => {
    document.getElementById('bulk-edit-modal').classList.remove('show');
    state.bulkEditData = null;
});

document.getElementById('confirm-bulk').addEventListener('click', async () => {
    const findPattern = document.getElementById('bulk-find').value;
    const replacePattern = document.getElementById('bulk-replace').value;

    if (!findPattern) {
        return showError('Please enter a find pattern');
    }

    let regex;
    try {
        regex = new RegExp(findPattern, 'g');
    } catch {
        return showError('Invalid regex pattern');
    }

    const edits = state.bulkEditData
        .filter((item) => item.originalUrl)
        .map((item) => ({
            code: item.code,
            url: item.originalUrl.replace(regex, replacePattern),
            encrypted: item.encrypted,
            token: item.token,
            changed: item.originalUrl.replace(regex, replacePattern) !== item.originalUrl,
        }))
        .filter((edit) => edit.changed);

    if (edits.length === 0) {
        return showError('No changes to apply');
    }

    for (const edit of edits) {
        if (!validateUrl(edit.url)) {
            return showError(`Cannot use this domain for code ${edit.code}`);
        }
    }

    updateCsrfToken();

    try {
        const editsToSend = await Promise.all(
            edits.map(async (edit) => {
                const sanitized = sanitizeUrl(edit.url);
                if (!sanitized) {
                    throw new Error(`Invalid URL for ${edit.code}`);
                }
                let urlToSend = sanitized;
                let signature = null;
                if (edit.encrypted && edit.token) {
                    urlToSend = await encryptUrl(sanitized, edit.token);
                    signature = await generateSignature(sanitized, edit.token);
                }
                return {
                    code: edit.code,
                    url: urlToSend,
                    encrypted: edit.encrypted,
                    signature,
                };
            })
        );

        const response = await fetch('/api/links/edit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                edits: editsToSend,
                csrf_token: state.csrfToken,
            }),
        });

        updateCsrfToken();

        if (!response.ok) {
            const text = await response.text();
            let errorMsg = 'Failed to update links';
            try {
                const data = JSON.parse(text);
                errorMsg = data.error || errorMsg;
            } catch {}
            throw new Error(errorMsg);
        }

        const data = await response.json();
        if (data.success) {
            document.getElementById('bulk-edit-modal').classList.remove('show');
            state.bulkEditData = null;
            state.selectedLinks.clear();
            loadManageView();
        } else {
            showError(data.error || 'Failed to update links');
        }
    } catch (err) {
        showError(err.message || 'Failed to update links');
    }
});

async function handlePath() {
    const path = window.location.pathname;
    const hash = window.location.hash.slice(1);

    if (path === '/') {
        updateCsrfToken();
        if (hash === 'manage') {
            loadManageView();
            showView('manage');
        }
        return;
    }

    const code = path.slice(1);

    if (code.endsWith('+')) {
        const actualCode = code.slice(0, -1);
        showView('preview');
        try {
            const response = await fetch(`/api/links/${actualCode}/preview`, {
                headers: { 'X-Preview': '1' },
            });
            if (response.status === 429) {
                return showView('rateLimit');
            }

            if (!response.ok) return showView('notFound');

            const link = await response.json();

            if (link.error) return showView('notFound');

            if (link.token && link.image && link.rounds) {
                return showCaptchaPage(link, actualCode, true);
            }

            let displayUrl = link.original_url;
            let decrypted = false;

            if (link.encrypted) {
                const token = hash || storage.get(actualCode);
                if (token) {
                    try {
                        displayUrl = await decryptUrl(link.original_url, token);
                        decrypted = true;
                    } catch {
                        displayUrl = '(Failed to decrypt - invalid token)';
                    }
                } else {
                    displayUrl = '(Encrypted - token not found in storage)';
                }
            }

            const created = new Date(link.created_at * 1000);
            const previewContent = document.getElementById('preview-content');
            previewContent.textContent = '';

            const header = document.createElement('div');
            header.className = 'preview-header';

            const codeDiv = document.createElement('div');
            codeDiv.className = 'preview-code';
            codeDiv.textContent = `/${actualCode}`;

            const badge = document.createElement('span');
            badge.className = 'preview-badge';
            badge.textContent = link.encrypted ? 'Encrypted' : 'Public';

            header.appendChild(codeDiv);
            header.appendChild(badge);

            const urlContainer = document.createElement('div');
            urlContainer.className = 'preview-url-container';

            const urlDiv = document.createElement('div');
            urlDiv.className = 'preview-url';
            urlDiv.textContent = displayUrl;

            const copyBtn = document.createElement('button');
            copyBtn.className = 'preview-copy';
            copyBtn.textContent = 'Copy';
            copyBtn.onclick = () => {
                navigator.clipboard.writeText(displayUrl);
                copyBtn.textContent = 'Copied!';
                setTimeout(() => (copyBtn.textContent = 'Copy'), 2000);
            };

            urlContainer.appendChild(urlDiv);
            urlContainer.appendChild(copyBtn);

            const stats = document.createElement('div');
            stats.className = 'preview-stats';

            const clicksStat = document.createElement('div');
            clicksStat.className = 'preview-stat';
            const clicksLabel = document.createElement('div');
            clicksLabel.className = 'preview-stat-label';
            clicksLabel.textContent = 'Clicks';
            const clicksValue = document.createElement('div');
            clicksValue.className = 'preview-stat-value';
            clicksValue.textContent = link.clicks;
            clicksStat.appendChild(clicksLabel);
            clicksStat.appendChild(clicksValue);

            const createdStat = document.createElement('div');
            createdStat.className = 'preview-stat';
            const createdLabel = document.createElement('div');
            createdLabel.className = 'preview-stat-label';
            createdLabel.textContent = 'Created';
            const createdValue = document.createElement('div');
            createdValue.className = 'preview-stat-value';
            createdValue.textContent = created.toLocaleDateString();
            createdStat.appendChild(createdLabel);
            createdStat.appendChild(createdValue);

            stats.appendChild(clicksStat);
            stats.appendChild(createdStat);

            previewContent.appendChild(header);
            previewContent.appendChild(urlContainer);
            previewContent.appendChild(stats);

            if (!link.encrypted || decrypted) {
                const visitLink = document.createElement('a');
                visitLink.href = displayUrl;
                visitLink.className = 'preview-visit';
                visitLink.target = '_blank';
                visitLink.rel = 'noopener noreferrer';
                visitLink.textContent = 'Visit URL';
                previewContent.appendChild(visitLink);
            }

            const reportLink = document.createElement('a');
            reportLink.className = 'preview-report';
            const token = hash || storage.get(actualCode);
            reportLink.href = token ? `/report#${actualCode}:${token}` : `/report#${actualCode}`;
            reportLink.textContent = 'Report Abuse';
            previewContent.appendChild(reportLink);
        } catch {
            showView('notFound');
        }
    } else {
        showView('redirect');

        const initialDataElement = document.getElementById('initial-data');
        if (initialDataElement) {
            try {
                const initialData = JSON.parse(initialDataElement.textContent);
                initialDataElement.remove();
                return handleInitialData(initialData, code, hash);
            } catch {
                // Invalid JSON, continue with fetch
            }
        }

        try {
            const response = await fetch(`/api/links/${code}/preview`);
            if (response.status === 429) {
                return showView('rateLimit');
            }

            if (!response.ok) return showView('notFound');

            const link = await response.json();

            if (link.error) {
                return showView('notFound');
            }

            if (link.token && link.image && link.rounds) {
                return showCaptchaPage(link, code, false);
            }

            if (!link.original_url) {
                return showView('notFound');
            }

            if (link.encrypted) {
                const token = hash || storage.get(code);
                if (token) {
                    try {
                        const url = await decryptUrl(link.original_url, token);

                        if (link.signature) {
                            const valid = await verifySignature(url, token, link.signature);
                            if (!valid) {
                                document.getElementById('redirect-msg').textContent =
                                    'Verification Failed';
                                document.getElementById('redirect-url').textContent =
                                    'Link integrity check failed. The link may have been tampered with.';
                                return;
                            }
                        }

                        if (!validateUrl(url)) {
                            document.getElementById('redirect-msg').textContent = 'Invalid URL';
                            document.getElementById('redirect-url').textContent =
                                'Decrypted URL is invalid';
                            return;
                        }
                        const sanitized = sanitizeUrl(url);
                        if (!sanitized) {
                            document.getElementById('redirect-msg').textContent = 'Invalid URL';
                            document.getElementById('redirect-url').textContent =
                                'Decrypted URL is invalid';
                            return;
                        }
                        document.getElementById('redirect-msg').textContent =
                            'Redirecting you now...';
                        document.getElementById('redirect-url').textContent = sanitized;
                        setTimeout(() => (window.location.href = sanitized), 1500);
                    } catch {
                        document.getElementById('redirect-msg').textContent = 'Decryption Failed';
                        document.getElementById('redirect-url').textContent =
                            'Invalid decryption key provided. Please check your link.';
                    }
                } else {
                    showView('encrypted');
                    document.getElementById('decrypt-key').dataset.code = code;
                }
            } else {
                if (!validateUrl(link.original_url)) return showView('notFound');
                const sanitized = sanitizeUrl(link.original_url);
                if (!sanitized) return showView('notFound');
                document.getElementById('redirect-msg').textContent = 'Redirecting you now...';
                document.getElementById('redirect-url').textContent = sanitized;
                setTimeout(() => (window.location.href = sanitized), 1000);
            }
        } catch {
            showView('notFound');
        }
    }
}

async function handleInitialData(data, code, hash) {
    if (data.token && data.image && data.rounds) {
        return showCaptchaPage(data, code, false);
    }

    if (!data.original_url) {
        return showView('notFound');
    }

    if (data.encrypted) {
        const token = hash || storage.get(code);
        if (token) {
            try {
                const url = await decryptUrl(data.original_url, token);

                if (data.signature) {
                    const valid = await verifySignature(url, token, data.signature);
                    if (!valid) {
                        document.getElementById('redirect-msg').textContent = 'Verification Failed';
                        document.getElementById('redirect-url').textContent =
                            'Link integrity check failed. The link may have been tampered with.';
                        return;
                    }
                }

                if (!validateUrl(url)) {
                    document.getElementById('redirect-msg').textContent = 'Invalid URL';
                    document.getElementById('redirect-url').textContent =
                        'Decrypted URL is invalid';
                    return;
                }

                const sanitized = sanitizeUrl(url);
                if (!sanitized) {
                    document.getElementById('redirect-msg').textContent = 'Invalid URL';
                    document.getElementById('redirect-url').textContent =
                        'Decrypted URL is invalid';
                    return;
                }

                document.getElementById('redirect-msg').textContent = 'Redirecting you now...';
                document.getElementById('redirect-url').textContent = sanitized;
                setTimeout(() => (window.location.href = sanitized), 1500);
            } catch {
                document.getElementById('redirect-msg').textContent = 'Decryption Failed';
                document.getElementById('redirect-url').textContent =
                    'Invalid decryption key provided. Please check your link.';
            }
        } else {
            showView('encrypted');
            document.getElementById('decrypt-key').dataset.code = code;
        }
    } else {
        if (!validateUrl(data.original_url)) return showView('notFound');
        const sanitized = sanitizeUrl(data.original_url);
        if (!sanitized) return showView('notFound');
        document.getElementById('redirect-msg').textContent = 'Redirecting you now...';
        document.getElementById('redirect-url').textContent = sanitized;
        setTimeout(() => (window.location.href = sanitized), 1000);
    }
}

function showCaptchaPage(captchaData, code, isPreview) {
    showView('captchaPage');
    const content = document.getElementById('captcha-page-content');
    const errorDiv = document.getElementById('captcha-page-error');
    errorDiv.classList.remove('show');

    window.captchaPageHandler = new CaptchaPageHandler(
        captchaData,
        code,
        isPreview,
        content,
        errorDiv
    );
}

document.getElementById('decrypt-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const keyInput = document.getElementById('decrypt-key');
    const errorDiv = document.getElementById('decrypt-error');
    const code = keyInput.dataset.code;
    const key = keyInput.value.trim();

    errorDiv.classList.remove('show');

    if (!key) {
        errorDiv.textContent = 'Please enter a decryption key';
        errorDiv.classList.add('show');
        return;
    }

    try {
        const response = await fetch(`/api/links/${code}/preview`);

        if (!response.ok) {
            const text = await response.text();
            try {
                const data = JSON.parse(text);
                if (data.error) {
                    errorDiv.textContent = data.error;
                    errorDiv.classList.add('show');
                    return;
                }
            } catch {}
            return showView('notFound');
        }

        const link = await response.json();
        if (link.error || !link.original_url) return showView('notFound');

        const url = await decryptUrl(link.original_url, key);

        if (link.signature) {
            const valid = await verifySignature(url, key, link.signature);
            if (!valid) {
                errorDiv.textContent = 'Verification failed - link may be tampered';
                errorDiv.classList.add('show');
                return;
            }
        }

        if (!validateUrl(url)) {
            errorDiv.textContent = 'Decrypted URL is invalid';
            errorDiv.classList.add('show');
            return;
        }

        const sanitized = sanitizeUrl(url);
        if (!sanitized) {
            errorDiv.textContent = 'Decrypted URL is invalid';
            errorDiv.classList.add('show');
            return;
        }

        storage.set(code, key);
        showView('redirect');
        document.getElementById('redirect-msg').textContent = 'Redirecting you now...';
        document.getElementById('redirect-url').textContent = sanitized;
        setTimeout(() => (window.location.href = sanitized), 1500);
    } catch (err) {
        errorDiv.textContent = err.message || 'Invalid decryption key';
        errorDiv.classList.add('show');
    }
});

document.getElementById('retry-btn').addEventListener('click', () => {
    handlePath();
});

updateCsrfToken();
handlePath();
