document.addEventListener('DOMContentLoaded', () => {
    const elements = {
        urlForm: document.getElementById('url-form'),
        urlInput: document.getElementById('url-input'),
        clearBtn: document.getElementById('clear-btn'),
        encryptToggle: document.getElementById('encrypt-toggle'),
        shortenBtn: document.getElementById('shorten-btn'),
        resultContainer: document.getElementById('result-container'),
        errorContainer: document.getElementById('error-container'),
        urlsList: document.getElementById('urls-list'),
        deletePopup: document.getElementById('delete-popup'),
        deleteConfirmBtn: document.getElementById('delete-confirm-btn'),
        deleteCancelBtn: document.getElementById('delete-cancel-btn'),
        deleteErrorContainer: document.getElementById('delete-error-container'),
        editPopup: document.getElementById('edit-popup'),
        editUrlInput: document.getElementById('edit-url-input'),
        editConfirmBtn: document.getElementById('edit-confirm-btn'),
        editCancelBtn: document.getElementById('edit-cancel-btn'),
        editErrorContainer: document.getElementById('edit-error-container'),
        redirectDestination: document.getElementById('redirect-destination'),
        infoContent: document.getElementById('info-content'),
        linksPage: document.getElementById('links-page'),
    };

    let pendingDeleteId = null;
    let pendingEditId = null;
    let infoPageSource = 'home-page';
    let hcaptchaWidget = null;
    let pendingUrlSubmission = null;

    const PAGES = ['home-page', 'links-page', 'info-page', 'redirect-page'];
    const COPY_TIMEOUT = 2000;
    const URL_ID_LENGTH = 5;

    const HCAPTCHA_SITE_KEY = document.querySelector('meta[name="hcaptcha-site-key"]')?.content;

    const SVG_ICONS = {
        copy: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>`,
        check: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>`,
        link: `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
                <line x1="8" y1="2" x2="8" y2="5"></line>
                <line x1="2" y1="8" x2="5" y2="8"></line>
                <line x1="16" y1="19" x2="16" y2="22"></line>
                <line x1="19" y1="16" x2="22" y2="16"></line>
            </svg>`,
        error: `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>`,
    };

    init();

    /**
     * Initialize the application
     */
    function init() {
        setupEventListeners();
        checkInitialState();
        updateClearButtonVisibility();
        setTimeout(updateClearButtonVisibility, 500);
    }

    /**
     * Set up all event listeners
     */
    function setupEventListeners() {
        elements.urlForm?.addEventListener('submit', handleUrlSubmit);
        elements.clearBtn?.addEventListener('click', () => {
            elements.urlInput.value = '';
            elements.urlInput.focus();
            updateClearButtonVisibility();
        });

        elements.urlInput?.addEventListener('input', updateClearButtonVisibility);

        document.addEventListener('click', handleButtonClicks);
        setupPageNavigation();
        setupPopupEvents();
    }

    /**
     * Setup popup event listeners
     */
    function setupPopupEvents() {
        elements.deleteCancelBtn?.addEventListener('click', () => {
            closePopup(elements.deletePopup);
            pendingDeleteId = null;
        });

        elements.deleteConfirmBtn?.addEventListener('click', () => {
            if (pendingDeleteId) {
                deleteUrl(pendingDeleteId);
            }
        });

        elements.editCancelBtn?.addEventListener('click', () => {
            closePopup(elements.editPopup);
            pendingEditId = null;
        });

        elements.editConfirmBtn?.addEventListener('click', () => {
            if (pendingEditId) {
                const newUrl = elements.editUrlInput.value.trim();
                if (newUrl) {
                    updateUrl(pendingEditId, newUrl);
                }
            }
        });

        elements.editUrlInput?.addEventListener('input', function () {
            this.style.height = 'auto';
            this.style.height = this.scrollHeight + 'px';
        });

        elements.editUrlInput?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                elements.editConfirmBtn.click();
            }
        });

        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('popup-overlay')) {
                closePopup(e.target);
                pendingDeleteId = null;
                pendingEditId = null;
            }
        });
    }

    /**
     * Show a popup
     */
    function showPopup(popup) {
        if (popup) {
            popup.classList.remove('hidden');

            if (popup === elements.editPopup && elements.editErrorContainer) {
                elements.editErrorContainer.classList.add('hidden');
                elements.editErrorContainer.textContent = '';
            }

            if (popup === elements.deletePopup && elements.deleteErrorContainer) {
                elements.deleteErrorContainer.classList.add('hidden');
                elements.deleteErrorContainer.textContent = '';
            }
        }
    }

    /**
     * Close a popup
     */
    function closePopup(popup) {
        if (popup) {
            popup.classList.add('hidden');
        }
    }

    /**
     * Handle all button click events using event delegation
     */
    function handleButtonClicks(e) {
        if (e.target.closest('.copy-btn')) {
            const button = e.target.closest('.copy-btn');
            copyToClipboard(button.dataset.url, button);
        }

        if (e.target.classList.contains('action-btn-delete')) {
            const urlId = e.target.dataset.id;
            pendingDeleteId = urlId;
            showPopup(elements.deletePopup);
        }

        if (e.target.classList.contains('action-btn-edit')) {
            const urlItem = e.target.closest('.url-item');
            const urlId = e.target.dataset.id;
            pendingEditId = urlId;

            const longUrl = urlItem.querySelector('.url-item-long-url').textContent.trim();
            elements.editUrlInput.value = longUrl;

            setTimeout(() => {
                elements.editUrlInput.style.height = 'auto';
                elements.editUrlInput.style.height = elements.editUrlInput.scrollHeight + 'px';
            }, 0);

            showPopup(elements.editPopup);
            elements.editUrlInput.focus();
            elements.editUrlInput.select();
        }

        if (e.target.classList.contains('action-btn-info')) {
            infoPageSource = 'links-page';
            showPage('info-page', true, e.target.dataset.id + '+');
            loadUrlInfo(e.target.dataset.id, true);
        }

        if (e.target.classList.contains('visit-url-btn')) {
            const { url: targetUrl } = e.target.dataset;
            if (targetUrl) {
                handleRedirect(null, targetUrl, false);
                e.preventDefault();
            }
        }
    }

    /**
     * Setup page navigation
     */
    function setupPageNavigation() {
        document.querySelectorAll('[data-page]').forEach((link) => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetPage = link.getAttribute('data-page');
                showPage(targetPage);

                hideContainers();

                if (targetPage === 'links-page') {
                    loadUserUrls();
                }
            });
        });

        document.querySelectorAll('.back-button').forEach((button) => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const infoPage = document.getElementById('info-page');
                if (infoPage && !infoPage.classList.contains('hidden')) {
                    showPage(infoPageSource);
                    if (infoPageSource === 'links-page') {
                        loadUserUrls();
                    }
                } else {
                    showPage('home-page');
                }
                hideContainers();
            });
        });

        window.addEventListener('popstate', (e) => {
            const pageId = e.state?.page || 'home-page';
            const previousPage = e.state?.previousPage;
            const hash = window.location.hash.substring(1);

            if (hash.endsWith('+')) {
                const urlId = hash.slice(0, -1);
                infoPageSource = previousPage || 'home-page';
                showPage('info-page', false);
                loadUrlInfo(urlId, true);
            } else if (pageId === 'info-page' && previousPage === 'links-page') {
                showPage('links-page', false);
                loadUserUrls();
            } else {
                showPage(pageId, false);
            }
            hideContainers();
        });
    }

    /**
     * Hide error and result containers
     */
    function hideContainers() {
        elements.errorContainer.classList.add('hidden');
        elements.resultContainer.classList.add('hidden');
    }

    /**
     * Show a specific page
     */
    function showPage(pageId, updateHistory = true, customHash = null) {
        if (pageId === 'info-page') {
            PAGES.forEach((page) => {
                const element = document.getElementById(page);
                if (element && !element.classList.contains('hidden') && page !== 'info-page') {
                    infoPageSource = page;
                }
            });
        }

        PAGES.forEach((page) => {
            const element = document.getElementById(page);
            if (element) {
                element.classList.toggle('hidden', page !== pageId);
            }
        });

        if (updateHistory) {
            let historyUrl =
                pageId !== 'home-page' && pageId !== 'redirect-page' ? `#${pageId}` : '/';
            if (customHash && pageId === 'info-page') {
                historyUrl = `#${customHash}`;
            }
            let previousPage = infoPageSource;
            if (pageId !== 'info-page') {
                PAGES.forEach((page) => {
                    const element = document.getElementById(page);
                    if (element && !element.classList.contains('hidden')) {
                        previousPage = page;
                    }
                });
            }
            history.pushState({ page: pageId, previousPage: previousPage }, '', historyUrl);
        }
    }

    /**
     * Check initial state (URL hash, query params)
     */
    function checkInitialState() {
        const urlParams = new URLSearchParams(window.location.search);
        const errorParam = urlParams.get('error');
        if (errorParam) {
            showError(errorParam);
        }

        const hash = window.location.hash.substring(1);
        if (!hash) return;

        if (hash === 'links-page') {
            showPage('links-page', false);
            loadUserUrls();
            return;
        }

        if (hash.endsWith('+')) {
            const urlId = hash.slice(0, -1);
            infoPageSource = 'home-page';
            showPage('info-page', false);
            loadUrlInfo(urlId, true);
            return;
        }

        const shortUrlId = hash;

        let urlId = shortUrlId;
        let token = null;

        if (shortUrlId.length > URL_ID_LENGTH) {
            urlId = shortUrlId.substring(0, URL_ID_LENGTH);
            token = shortUrlId.substring(URL_ID_LENGTH);
        }

        handleRedirect(urlId, token, true);
    }

    /**
     * Get current theme
     */
    function getCurrentTheme() {
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
            ? 'dark'
            : 'light';
    }

    /**
     * Load hCaptcha script
     */
    function loadHCaptchaScript() {
        if (document.getElementById('hcaptcha-script')) {
            return Promise.resolve();
        }

        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.id = 'hcaptcha-script';
            script.src = 'https://js.hcaptcha.com/1/api.js?render=explicit';
            script.async = true;
            script.defer = true;

            script.onload = resolve;
            script.onerror = reject;

            document.head.appendChild(script);
        });
    }

    /**
     * Check if the clearance token cookie exists
     */
    function hasClearanceToken() {
        return document.cookie.split(';').some((c) => {
            return c.trim().startsWith('clearance_token=');
        });
    }

    /**
     * Verify clearance token
     */
    async function verifyClearance() {
        if (hasClearanceToken()) {
            return true;
        }

        elements.shortenBtn.disabled = true;
        elements.shortenBtn.textContent = 'Verifying...';

        try {
            await loadHCaptchaScript();

            return new Promise((resolve) => {
                if (window.hcaptcha && HCAPTCHA_SITE_KEY) {
                    const options = {
                        size: 'invisible',
                        theme: getCurrentTheme(),
                        callback: async (token) => {
                            try {
                                const response = await fetchApi('/api/clearance', {
                                    method: 'POST',
                                    body: { 'h-captcha-response': token },
                                });

                                const data = await response.json();

                                if (response.ok && data.success) {
                                    if (hcaptchaWidget !== null) {
                                        window.hcaptcha.reset(hcaptchaWidget);
                                        window.hcaptcha.remove(hcaptchaWidget);
                                        hcaptchaWidget = null;
                                    }
                                    recreateShortenButton();
                                    elements.shortenBtn.textContent = 'Shorten URL';
                                    resolve(true);
                                } else {
                                    showError(data.error || 'Verification failed');
                                    elements.shortenBtn.disabled = false;
                                    elements.shortenBtn.textContent = 'Shorten URL';
                                    resolve(false);
                                }
                            } catch (error) {
                                console.error('Verification error:', error);
                                showError('Verification failed. Please try again.');
                                elements.shortenBtn.disabled = false;
                                elements.shortenBtn.textContent = 'Shorten URL';
                                resolve(false);
                            }
                        },
                        'error-callback': () => {
                            showError('Verification failed. Please try again.');
                            elements.shortenBtn.disabled = false;
                            elements.shortenBtn.textContent = 'Shorten URL';
                            resolve(false);
                        },
                        'close-callback': () => {
                            elements.shortenBtn.disabled = false;
                            elements.shortenBtn.textContent = 'Shorten URL';
                            resolve(false);
                        },
                    };

                    if (hcaptchaWidget === null) {
                        hcaptchaWidget = window.hcaptcha.render(elements.shortenBtn, {
                            sitekey: HCAPTCHA_SITE_KEY,
                            ...options,
                        });
                    }

                    window.hcaptcha.execute(hcaptchaWidget);
                } else {
                    console.error('hCaptcha not loaded or site key not found');
                    showError('Verification service unavailable. Please try again.');
                    elements.shortenBtn.disabled = false;
                    elements.shortenBtn.textContent = 'Shorten URL';
                    resolve(false);
                }
            });
        } catch (error) {
            console.error('Error loading hCaptcha:', error);
            showError('Verification service unavailable. Please try again.');
            elements.shortenBtn.disabled = false;
            elements.shortenBtn.textContent = 'Shorten URL';
            return false;
        }
    }

    /**
     * Recreate the shorten button to remove all hCaptcha events
     */
    function recreateShortenButton() {
        const oldBtn = elements.shortenBtn;
        if (!oldBtn) return;

        const newBtn = document.createElement('button');
        newBtn.id = 'shorten-btn';
        newBtn.className = oldBtn.className;
        newBtn.textContent = 'Shorten URL';
        newBtn.type = 'submit';

        oldBtn.parentNode.replaceChild(newBtn, oldBtn);
        elements.shortenBtn = newBtn;

        elements.urlForm?.removeEventListener('submit', handleUrlSubmit);
        elements.urlForm?.addEventListener('submit', handleUrlSubmit);
    }

    /**
     * Handle URL form submission
     */
    async function handleUrlSubmit(e) {
        e.preventDefault();
        const url = elements.urlInput.value.trim();
        const isEncrypted = elements.encryptToggle.checked;

        if (!url) {
            showError('Please enter a URL');
            return;
        }

        if (!isValidUrl(url)) {
            showError('Please enter a valid URL');
            return;
        }

        pendingUrlSubmission = {
            url,
            isEncrypted,
        };

        const hasClearance = await verifyClearance();
        if (!hasClearance) {
            return;
        }

        await processUrlSubmission();
    }

    /**
     * Process URL submission after clearance is verified
     */
    async function processUrlSubmission() {
        if (!pendingUrlSubmission) return;

        const { url, isEncrypted } = pendingUrlSubmission;
        pendingUrlSubmission = null;

        elements.shortenBtn.disabled = true;
        elements.shortenBtn.textContent = 'Shortening...';

        try {
            let response, data, shortUrl;

            if (isEncrypted) {
                const token = generateEncryptionToken();
                const encryptedUrl = await encryptUrl(url, token);

                response = await fetchApi('/api/shorten', {
                    method: 'POST',
                    body: { url: encryptedUrl, is_encrypted: true },
                });

                data = await response.json();

                if (response.ok) {
                    shortUrl = `${window.location.origin}/#${data.url_id}${token}`;
                    showResult(shortUrl, true);
                } else {
                    if (data.error === 'Valid clearance token required') {
                        const hasClearance = await verifyClearance();
                        if (hasClearance) {
                            pendingUrlSubmission = { url, isEncrypted };
                            await processUrlSubmission();
                            return;
                        }
                    }
                    showError(data.error || 'An error occurred');
                }
            } else {
                response = await fetchApi('/api/shorten', {
                    method: 'POST',
                    body: { url, is_encrypted: false },
                });

                data = await response.json();

                if (response.ok) {
                    shortUrl = `${window.location.origin}/#${data.url_id}`;
                    showResult(shortUrl, false);
                } else {
                    if (data.error === 'Valid clearance token required') {
                        const hasClearance = await verifyClearance();
                        if (hasClearance) {
                            pendingUrlSubmission = { url, isEncrypted };
                            await processUrlSubmission();
                            return;
                        }
                    }
                    showError(data.error || 'An error occurred');
                }
            }
        } catch (error) {
            console.error('Error:', error);
            showError('An error occurred. Please try again.');
        } finally {
            elements.shortenBtn.disabled = false;
            elements.shortenBtn.textContent = 'Shorten URL';
        }
    }

    /**
     * Helper function for API requests
     */
    async function fetchApi(url, { method = 'GET', body = null } = {}) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };

        if (body) {
            options.body = JSON.stringify(body);
        }

        return fetch(url, options);
    }

    /**
     * Generate secure encryption token (14 characters, base62)
     */
    function generateEncryptionToken() {
        const array = new Uint8Array(14);
        window.crypto.getRandomValues(array);
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        return Array.from(array, (byte) => charset[byte % 64]).join('');
    }

    /**
     * Encrypt a URL with the given token using AES-GCM
     */
    async function encryptUrl(url, token) {
        try {
            const encoder = new TextEncoder();
            const tokenData = encoder.encode(token.padEnd(16, '_'));

            const keyMaterial = await window.crypto.subtle.importKey(
                'raw',
                tokenData,
                { name: 'PBKDF2' },
                false,
                ['deriveBits', 'deriveKey']
            );

            const salt = encoder.encode('Redux URL Salt');
            const key = await window.crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt,
                    iterations: 100000,
                    hash: 'SHA-256',
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );

            const iv = new Uint8Array(12);
            window.crypto.getRandomValues(iv);

            const urlData = encoder.encode(url);
            const encryptedData = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                urlData
            );

            const encryptedArray = new Uint8Array(iv.length + encryptedData.byteLength);
            encryptedArray.set(iv, 0);
            encryptedArray.set(new Uint8Array(encryptedData), iv.length);

            return btoa(String.fromCharCode(...encryptedArray))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt URL');
        }
    }

    /**
     * Decrypt a URL with the given token
     */
    async function decryptUrl(encryptedBase64, token) {
        try {
            const encryptedString = atob(encryptedBase64.replace(/-/g, '+').replace(/_/g, '/'));
            const encryptedBytes = new Uint8Array([...encryptedString].map((c) => c.charCodeAt(0)));

            const iv = encryptedBytes.slice(0, 12);
            const encryptedData = encryptedBytes.slice(12);

            const encoder = new TextEncoder();
            const tokenData = encoder.encode(token.padEnd(16, '_'));

            const keyMaterial = await window.crypto.subtle.importKey(
                'raw',
                tokenData,
                { name: 'PBKDF2' },
                false,
                ['deriveBits', 'deriveKey']
            );

            const salt = encoder.encode('Redux URL Salt');
            const key = await window.crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt,
                    iterations: 100000,
                    hash: 'SHA-256',
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            const decryptedData = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                encryptedData
            );

            return new TextDecoder().decode(decryptedData);
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt URL');
        }
    }

    /**
     * Handle redirect for a URL
     */
    async function handleRedirect(urlId, token, isShortUrl) {
        const directUrl = !isShortUrl ? token : null;

        showPage('redirect-page', false);

        try {
            let finalUrl = directUrl;

            if (isShortUrl && urlId) {
                const response = await fetchApi(`/api/redirect/${urlId}`);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'URL not found');
                }

                if (data.is_encrypted) {
                    if (token) {
                        try {
                            finalUrl = await decryptUrl(data.url, token);

                            if (elements.redirectDestination) {
                                elements.redirectDestination.textContent = finalUrl;
                            }

                            window.location.href = finalUrl;
                        } catch (error) {
                            throw new Error('Failed to decrypt URL with the provided token');
                        }
                    } else {
                        showError(
                            'This link is encrypted and cannot be viewed directly. Please use the complete URL with decryption token.'
                        );
                        showPage('home-page', false);
                        return;
                    }
                } else {
                    finalUrl = data.url;

                    if (elements.redirectDestination) {
                        elements.redirectDestination.textContent = finalUrl;
                    }

                    window.location.href = finalUrl;
                }
            } else if (directUrl) {
                if (elements.redirectDestination) {
                    elements.redirectDestination.textContent = directUrl;
                }

                window.location.href = directUrl;
            }
        } catch (error) {
            console.error('Redirect error:', error);
            showError(error.message || 'Failed to redirect. The link may be invalid or expired.');
            showPage('home-page', false);
        }
    }

    /**
     * Create empty state message with icon
     */
    function createEmptyState(message, iconType = 'link') {
        return `
            <div class="empty-state">
                ${SVG_ICONS[iconType]}
                <p>${message}</p>
            </div>
        `;
    }

    /**
     * Load URL information
     */
    async function loadUrlInfo(urlId, isInfoRequest = false) {
        if (!elements.infoContent) return;

        elements.infoContent.innerHTML = '<p>Loading information...</p>';

        try {
            let token = null;
            let originalUrlId = urlId;

            if (urlId.length > URL_ID_LENGTH) {
                token = urlId.substring(URL_ID_LENGTH);
                urlId = urlId.substring(0, URL_ID_LENGTH);
            }

            const hash = window.location.hash.substring(1);
            if (hash.endsWith('+')) {
                isInfoRequest = true;
                const fullUrlId = hash.slice(0, -1);
                if (fullUrlId.length > URL_ID_LENGTH) {
                    token = fullUrlId.substring(URL_ID_LENGTH);
                    urlId = fullUrlId.substring(0, URL_ID_LENGTH);
                    originalUrlId = urlId;
                } else {
                    originalUrlId = fullUrlId;
                }
            }

            const endpoint = isInfoRequest ? 'url' : 'redirect';
            const response = await fetchApi(`/api/${endpoint}/${urlId}`);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'URL not found');
            }

            displayUrlInfo(urlId, data, token, originalUrlId);
        } catch (error) {
            console.error('Error:', error);
            elements.infoContent.innerHTML = createAlertMessage(
                'Failed to load URL information.',
                'error'
            );
        }
    }

    /**
     * Display URL information with fetched data
     */
    async function displayUrlInfo(urlId, data, token = null, originalUrlId = null) {
        if (!elements.infoContent) return;

        if (!originalUrlId) {
            originalUrlId = token ? urlId + token : urlId;
        }

        const createdDate = new Date(data.created_at * 1000).toLocaleDateString();
        const fullShortUrl = `${window.location.origin}/#${originalUrlId}`;
        const isMyUrl = data.created_at && data.visits !== undefined;

        const cardTitle = document.querySelector('#info-page .card-header h2');
        if (cardTitle) {
            cardTitle.textContent =
                data.is_encrypted && token ? 'Decrypted URL Information' : 'URL Information';
        }

        let displayUrl = data.url;

        if (data.is_encrypted) {
            if (token) {
                try {
                    displayUrl = await decryptUrl(data.url, token);
                } catch (error) {
                    console.error('Decryption failed:', error);
                    displayUrl = '⚠️ Decryption failed with the provided token';
                }
            } else {
                displayUrl = '(Encrypted content)';
            }
        }

        let html = buildUrlInfoHeader(fullShortUrl, data.is_encrypted);

        html += buildUrlInfoContent(displayUrl);

        if (isMyUrl) {
            html += `
                <div class="url-item-stats">
                    <span>Created: ${createdDate}</span>
                    <span>Visits: ${data.visits}</span>
                </div>
                <div class="url-item-actions">
                    ${
                        !data.is_encrypted
                            ? `<button class="action-btn action-btn-edit" data-id="${urlId}">Edit</button>`
                            : ''
                    }
                    <button class="action-btn action-btn-delete" data-id="${urlId}">Delete</button>
                </div>
            `;
        }

        html += buildVisitButton(displayUrl, data.is_encrypted, token);
        html += `</div>`;

        elements.infoContent.innerHTML = html;
    }

    /**
     * Create a copy button with consistent markup
     */
    function createCopyButton(url) {
        return `<button type="button" class="copy-btn" data-url="${url}">${SVG_ICONS.copy}</button>`;
    }

    /**
     * Build URL info header HTML
     */
    function buildUrlInfoHeader(fullShortUrl, isEncrypted) {
        return `
            <div class="url-item">
                <div class="url-item-header">
                    <span class="url-item-link">${fullShortUrl}</span>
                    ${createCopyButton(fullShortUrl)}
                    ${isEncrypted ? '<span class="url-item-encrypted">Encrypted</span>' : ''}
                </div>
        `;
    }

    /**
     * Build URL info content HTML
     */
    function buildUrlInfoContent(displayUrl) {
        if (!displayUrl) {
            return '';
        }

        return `
            <div class="url-item-long-url">
                ${displayUrl}
                ${createCopyButton(displayUrl)}
            </div>
        `;
    }

    /**
     * Build visit button HTML
     */
    function buildVisitButton(displayUrl, isEncrypted, token) {
        if (isEncrypted && !token) {
            return '';
        }

        return `
            <div class="info-visit-action">
                <a href="#" class="button visit-url-btn" data-url="${displayUrl}">Visit URL</a>
            </div>
        `;
    }

    /**
     * Show error message in a popup
     */
    function showPopupError(container, message) {
        if (container) {
            container.textContent = message;
            container.classList.remove('hidden');
        }
    }

    /**
     * Delete a URL
     */
    async function deleteUrl(urlId) {
        try {
            elements.deleteConfirmBtn.disabled = true;
            elements.deleteConfirmBtn.textContent = 'Deleting...';

            const response = await fetchApi(`/api/url/${urlId}`, { method: 'DELETE' });
            const data = await response.json();

            if (response.ok && data.success) {
                closePopup(elements.deletePopup);

                if (!elements.linksPage.classList.contains('hidden')) {
                    loadUserUrls();
                } else {
                    showPage('home-page');
                }
            } else {
                showPopupError(elements.deleteErrorContainer, data.error || 'Failed to delete URL');
            }
        } catch (error) {
            console.error('Error:', error);
            showPopupError(
                elements.deleteErrorContainer,
                'An error occurred while deleting the URL'
            );
        } finally {
            elements.deleteConfirmBtn.disabled = false;
            elements.deleteConfirmBtn.textContent = 'Delete';
        }
    }

    /**
     * Update a URL
     */
    async function updateUrl(urlId, newUrl) {
        if (!isValidUrl(newUrl)) {
            showPopupError(elements.editErrorContainer, 'Please enter a valid URL');
            return;
        }

        try {
            elements.editConfirmBtn.disabled = true;
            elements.editConfirmBtn.textContent = 'Saving...';

            const response = await fetchApi(`/api/url/${urlId}`, {
                method: 'PUT',
                body: { url: newUrl },
            });

            const data = await response.json();

            if (response.ok && data.success) {
                closePopup(elements.editPopup);
                loadUserUrls();
            } else {
                showPopupError(elements.editErrorContainer, data.error || 'Failed to update URL');
            }
        } catch (error) {
            console.error('Error:', error);
            showPopupError(elements.editErrorContainer, 'An error occurred while updating the URL');
        } finally {
            elements.editConfirmBtn.disabled = false;
            elements.editConfirmBtn.textContent = 'Save';
        }
    }

    /**
     * Create an alert message with consistent formatting
     */
    function createAlertMessage(message, type = 'error') {
        return `<div class="alert alert-${type}">${message}</div>`;
    }

    /**
     * Show error message
     */
    function showError(message) {
        elements.resultContainer.classList.add('hidden');
        elements.errorContainer.innerHTML = createAlertMessage(message, 'error');
        elements.errorContainer.classList.remove('hidden');
    }

    /**
     * Show result after successful URL shortening
     */
    function showResult(url, isEncrypted) {
        elements.errorContainer.classList.add('hidden');

        elements.resultContainer.innerHTML = `
            ${createAlertMessage('URL shortened successfully!', 'success')}
            <div class="shortened-url">
                <span>${url}</span>
                ${createCopyButton(url)}
            </div>
            ${isEncrypted ? '<p class="text-center">This URL is end-to-end encrypted. The destination is never sent to our servers.</p>' : ''}
        `;
        elements.resultContainer.classList.remove('hidden');
    }

    /**
     * Copy text to clipboard
     */
    function copyToClipboard(text, button) {
        if (!button.dataset.originalSvg) {
            button.dataset.originalSvg = button.innerHTML;
        }

        button.disabled = true;

        navigator.clipboard
            .writeText(text)
            .then(() => {
                button.innerHTML = SVG_ICONS.check;
                button.classList.add('copied');

                if (button.timeout) clearTimeout(button.timeout);

                button.timeout = setTimeout(() => {
                    button.innerHTML = button.dataset.originalSvg;
                    button.classList.remove('copied');
                    button.disabled = false;
                    button.timeout = null;
                }, COPY_TIMEOUT);
            })
            .catch((err) => {
                console.error('Failed to copy:', err);
                button.disabled = false;
            });
    }

    /**
     * Validate URL format
     */
    function isValidUrl(url) {
        try {
            new URL(url);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Load the user's URLs
     */
    async function loadUserUrls() {
        if (!elements.urlsList) return;

        elements.urlsList.innerHTML = '';

        let loadingEl = document.getElementById('urls-loading');
        if (!loadingEl) {
            loadingEl = document.createElement('div');
            loadingEl.id = 'urls-loading';
            loadingEl.className = 'urls-message';
            loadingEl.innerHTML = '<p>Loading your URLs...</p>';
            elements.urlsList.parentNode.appendChild(loadingEl);
        } else {
            loadingEl.classList.remove('hidden');
        }

        const emptyEl = document.getElementById('urls-empty');
        if (emptyEl) {
            emptyEl.classList.add('hidden');
        }

        try {
            const response = await fetchApi('/api/urls');
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to load URLs');
            }

            const urls = Array.isArray(data) ? data : [];

            loadingEl.classList.add('hidden');

            if (urls.length === 0) {
                let emptyStateEl = document.getElementById('urls-empty');
                if (!emptyStateEl) {
                    emptyStateEl = document.createElement('div');
                    emptyStateEl.id = 'urls-empty';
                    emptyStateEl.className = 'urls-message';
                    emptyStateEl.innerHTML = createEmptyState("You haven't created any URLs yet.");
                    elements.urlsList.parentNode.appendChild(emptyStateEl);
                } else {
                    emptyStateEl.classList.remove('hidden');
                }

                elements.urlsList.classList.add('hidden');
                return;
            }

            elements.urlsList.classList.remove('hidden');
            displayUrls(urls);
        } catch (error) {
            console.error('Error:', error);
            loadingEl.innerHTML = createEmptyState(
                'Failed to load your URLs. Please try again.',
                'error'
            );
            elements.urlsList.classList.add('hidden');
        }
    }

    /**
     * Display URLs in the list
     */
    function displayUrls(urls) {
        elements.urlsList.innerHTML = '';

        urls.forEach((url) => {
            const createdDate = new Date(url.created_at * 1000).toLocaleDateString();
            const shortUrl = `${window.location.origin}/#${url.url_id}`;

            elements.urlsList.innerHTML += `
                <li class="url-item">
                    <div class="url-item-header">
                        <a href="${shortUrl}" class="url-item-link" target="_blank">
                            ${shortUrl}
                        </a>
                        ${createCopyButton(shortUrl)}
                        ${url.is_encrypted ? '<span class="url-item-encrypted">Encrypted</span>' : ''}
                    </div>
                    <div class="url-item-stats">
                        <span>Created: ${createdDate}</span>
                        <span>Visits: ${url.visits}</span>
                    </div>
                    ${
                        !url.is_encrypted
                            ? `
                    <div class="url-item-long-url">
                        ${url.url}
                        ${createCopyButton(url.url)}
                    </div>`
                            : ''
                    }
                    <div class="url-item-actions">
                        <button class="action-btn action-btn-info" data-id="${url.url_id}">Info</button>
                        ${!url.is_encrypted ? `<button class="action-btn action-btn-edit" data-id="${url.url_id}">Edit</button>` : ''}
                        <button class="action-btn action-btn-delete" data-id="${url.url_id}">Delete</button>
                    </div>
                </li>
            `;
        });
    }

    /**
     * Update the visibility of the clear button based on input content
     */
    function updateClearButtonVisibility() {
        if (elements.clearBtn && elements.urlInput) {
            if (elements.urlInput.value.trim().length > 0) {
                elements.clearBtn.classList.remove('hidden');
            } else {
                elements.clearBtn.classList.add('hidden');
            }
        }
    }
});
