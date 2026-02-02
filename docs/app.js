// gitText - WASM-powered text editor with syntax highlighting
// Features: LZSS compression, AES-256 encryption, QR code, IndexedDB, syntax highlighting

let wasm = null;
let wasmMemory = null;
let memoryView = null;
let isEncrypted = false;
let db = null;
let currentDocId = null;
let storageMode = 'url';
let currentLanguage = 0;
let highlightEnabled = true;
let highlightTimeout = null;

const DB_NAME = 'gittext-db';
const DB_VERSION = 1;
const STORE_NAME = 'documents';
const URL_SIZE_LIMIT = 32000;
const TOKEN_SIZE = 9;

// Token types (must match Zig)
const TokenType = {
    keyword: 1,
    string: 2,
    number: 3,
    comment: 4,
    operator: 5,
    punctuation: 6,
    function_name: 7,
    type_name: 8,
    variable: 9,
    tag: 10,
    attribute: 11,
    property: 12,
};

// Language types
const Language = {
    plain: 0,
    javascript: 1,
    json: 2,
    html: 3,
    css: 4,
    python: 5,
    markdown: 6,
    zig: 7,
};

const LanguageNames = ['Plain', 'JavaScript', 'JSON', 'HTML', 'CSS', 'Python', 'Markdown', 'Zig'];

const dom = {};
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

let saveTimeout = null;
let currentPassword = null;

function initDom() {
    const ids = [
        'editor', 'editor-wrapper', 'highlight-layer', 'line-numbers', 'loading',
        'copy-btn', 'clear-btn', 'encrypt-btn', 'qr-btn', 'docs-btn', 'download-btn', 'lang-btn',
        'stats', 'status-dot', 'status-text', 'url-size', 'toast',
        'modal', 'modal-content', 'modal-close', 'modal-title',
        'password-form', 'password-input', 'password-confirm', 'password-submit',
        'qr-canvas', 'docs-list', 'storage-mode'
    ];
    ids.forEach(id => {
        dom[id.replace(/-/g, '_')] = document.getElementById(id);
    });
}

function initDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => { db = request.result; resolve(db); };
        request.onupgradeneeded = (e) => {
            const database = e.target.result;
            if (!database.objectStoreNames.contains(STORE_NAME)) {
                const store = database.createObjectStore(STORE_NAME, { keyPath: 'id' });
                store.createIndex('created', 'created', { unique: false });
                store.createIndex('title', 'title', { unique: false });
            }
        };
    });
}

async function initWasm() {
    try {
        await Promise.all([
            fetch('editor.wasm').then(r => r.arrayBuffer()).then(bytes =>
                WebAssembly.instantiate(bytes, { env: {} })
            ).then(module => {
                wasm = module.instance.exports;
                wasmMemory = wasm.memory;
                updateMemoryView();
            }),
            initDB().catch(e => console.warn('IndexedDB unavailable:', e))
        ]);

        dom.loading.style.display = 'none';
        dom.editor_wrapper.style.display = 'flex';
        dom.copy_btn.disabled = false;
        dom.encrypt_btn.disabled = false;
        dom.qr_btn.disabled = false;
        dom.docs_btn.disabled = false;
        dom.download_btn.disabled = false;
        dom.lang_btn.disabled = false;

        await loadFromUrl();
        setupEventListeners();
        updateStats();
        updateLineNumbers();
        scheduleHighlight();
    } catch (error) {
        console.error('Failed to load WASM:', error);
        dom.loading.textContent = 'Failed to load editor. Please refresh.';
    }
}

function updateMemoryView() {
    memoryView = new Uint8Array(wasmMemory.buffer);
}

function writeToWasm(bytes) {
    const ptr = wasm.alloc(bytes.length);
    if (!ptr) throw new Error('Failed to allocate WASM memory');
    if (memoryView.buffer !== wasmMemory.buffer) updateMemoryView();
    memoryView.set(bytes, ptr);
    return { ptr, len: bytes.length };
}

function readFromWasm(packed) {
    const ptr = Number(packed >> 32n);
    const len = Number(packed & 0xFFFFFFFFn);
    if (ptr === 0 || len === 0) return null;
    if (memoryView.buffer !== wasmMemory.buffer) updateMemoryView();
    return memoryView.subarray(ptr, ptr + len);
}

// ============================================================================
// SYNTAX HIGHLIGHTING
// ============================================================================

function detectLanguage(text) {
    if (!text || text.length < 10) return Language.plain;
    
    wasm.reset_heap();
    const bytes = textEncoder.encode(text.slice(0, 2000));
    const { ptr, len } = writeToWasm(bytes);
    return wasm.detect_language(ptr, len);
}

function tokenize(text, lang) {
    if (!text || lang === Language.plain) return [];
    
    wasm.reset_heap();
    const bytes = textEncoder.encode(text);
    const { ptr, len } = writeToWasm(bytes);
    const result = wasm.tokenize(ptr, len, lang);
    const tokenData = readFromWasm(result);
    
    if (!tokenData) return [];
    
    const tokens = [];
    const view = new DataView(tokenData.buffer, tokenData.byteOffset, tokenData.byteLength);
    
    for (let i = 0; i + TOKEN_SIZE <= tokenData.length; i += TOKEN_SIZE) {
        const start = view.getUint32(i, true);
        const length = view.getUint32(i + 4, true);
        const type = tokenData[i + 8];
        tokens.push({ start, length, type });
    }
    
    return tokens;
}

function getTokenClass(type) {
    switch (type) {
        case TokenType.keyword: return 'tok-kw';
        case TokenType.string: return 'tok-str';
        case TokenType.number: return 'tok-num';
        case TokenType.comment: return 'tok-cmt';
        case TokenType.operator: return 'tok-op';
        case TokenType.punctuation: return 'tok-punc';
        case TokenType.function_name: return 'tok-fn';
        case TokenType.type_name: return 'tok-type';
        case TokenType.tag: return 'tok-tag';
        case TokenType.attribute: return 'tok-attr';
        case TokenType.property: return 'tok-prop';
        default: return '';
    }
}

function highlightCode() {
    if (!highlightEnabled || !dom.highlight_layer) return;
    
    const text = dom.editor.value;
    if (!text) {
        dom.highlight_layer.innerHTML = '<br>';
        return;
    }
    
    // Auto-detect language if not set
    if (currentLanguage === Language.plain) {
        currentLanguage = detectLanguage(text);
        updateLanguageButton();
    }
    
    if (currentLanguage === Language.plain) {
        dom.highlight_layer.textContent = text;
        return;
    }
    
    const tokens = tokenize(text, currentLanguage);
    
    if (tokens.length === 0) {
        dom.highlight_layer.textContent = text;
        return;
    }
    
    // Build highlighted HTML
    let html = '';
    let lastEnd = 0;
    
    for (const token of tokens) {
        // Add text before token
        if (token.start > lastEnd) {
            html += escapeHtml(text.slice(lastEnd, token.start));
        }
        
        // Add token with class
        const tokenText = text.slice(token.start, token.start + token.length);
        const cls = getTokenClass(token.type);
        if (cls) {
            html += `<span class="${cls}">${escapeHtml(tokenText)}</span>`;
        } else {
            html += escapeHtml(tokenText);
        }
        
        lastEnd = token.start + token.length;
    }
    
    // Add remaining text
    if (lastEnd < text.length) {
        html += escapeHtml(text.slice(lastEnd));
    }
    
    dom.highlight_layer.innerHTML = html || '<br>';
}

function scheduleHighlight() {
    if (highlightTimeout) cancelAnimationFrame(highlightTimeout);
    highlightTimeout = requestAnimationFrame(highlightCode);
}

function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// ============================================================================
// LINE NUMBERS
// ============================================================================

function updateLineNumbers() {
    const text = dom.editor.value;
    const lines = text.split('\n').length;
    
    let html = '';
    for (let i = 1; i <= lines; i++) {
        html += i + '\n';
    }
    
    dom.line_numbers.textContent = html;
}

function syncScroll() {
    const scrollTop = dom.editor.scrollTop;
    const scrollLeft = dom.editor.scrollLeft;
    
    dom.line_numbers.scrollTop = scrollTop;
    dom.highlight_layer.scrollTop = scrollTop;
    dom.highlight_layer.scrollLeft = scrollLeft;
}

// ============================================================================
// DOWNLOAD
// ============================================================================

function downloadFile(format = 'txt') {
    const text = dom.editor.value;
    if (!text) {
        showToast('Nothing to download');
        return;
    }
    
    let blob, filename;
    const timestamp = new Date().toISOString().slice(0, 10);
    
    if (format === 'compressed') {
        const compressed = compressData(textEncoder.encode(text));
        if (compressed) {
            blob = new Blob([compressed], { type: 'application/octet-stream' });
            filename = `gittext-${timestamp}.lzss`;
        } else {
            showToast('Compression failed');
            return;
        }
    } else {
        const ext = getFileExtension();
        blob = new Blob([text], { type: 'text/plain' });
        filename = `gittext-${timestamp}.${ext}`;
    }
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    
    showToast(`Downloaded: ${filename}`);
}

function getFileExtension() {
    switch (currentLanguage) {
        case Language.javascript: return 'js';
        case Language.json: return 'json';
        case Language.html: return 'html';
        case Language.css: return 'css';
        case Language.python: return 'py';
        case Language.markdown: return 'md';
        case Language.zig: return 'zig';
        default: return 'txt';
    }
}

function showDownloadMenu() {
    dom.modal_title.textContent = 'Download';
    dom.password_form.style.display = 'none';
    dom.qr_canvas.style.display = 'none';
    dom.docs_list.style.display = 'block';
    
    const ext = getFileExtension();
    dom.docs_list.innerHTML = `
        <div class="download-options">
            <button class="download-option" data-format="txt">
                <span class="download-icon">📄</span>
                <span>Text File (.${ext})</span>
            </button>
            <button class="download-option" data-format="compressed">
                <span class="download-icon">📦</span>
                <span>Compressed (.lzss)</span>
            </button>
        </div>
    `;
    
    dom.docs_list.querySelectorAll('.download-option').forEach(btn => {
        btn.onclick = () => {
            downloadFile(btn.dataset.format);
            closeModal();
        };
    });
    
    dom.modal.classList.add('show');
}

// ============================================================================
// LANGUAGE SELECTION
// ============================================================================

function cycleLanguage() {
    currentLanguage = (currentLanguage + 1) % LanguageNames.length;
    updateLanguageButton();
    scheduleHighlight();
}

function updateLanguageButton() {
    dom.lang_btn.textContent = LanguageNames[currentLanguage];
}

// ============================================================================
// COMPRESSION & ENCRYPTION (unchanged)
// ============================================================================

function generateShareCode(data) {
    wasm.reset_heap();
    const { ptr, len } = writeToWasm(data);
    const result = wasm.hash_data(ptr, len);
    const code = readFromWasm(result);
    return code ? textDecoder.decode(code) : null;
}

function compressData(data) {
    wasm.reset_heap();
    const { ptr, len } = writeToWasm(data);
    const result = wasm.compress(ptr, len);
    const compressed = readFromWasm(result);
    return compressed ? compressed.slice() : null;
}

function decompressData(data) {
    wasm.reset_heap();
    const { ptr, len } = writeToWasm(data);
    const result = wasm.decompress(ptr, len);
    const decompressed = readFromWasm(result);
    return decompressed ? decompressed.slice() : null;
}

function generateNonce() {
    const seed = new Uint8Array(16);
    const view = new DataView(seed.buffer);
    view.setBigUint64(0, BigInt(Date.now()), true);
    crypto.getRandomValues(seed.subarray(8));
    wasm.reset_heap();
    const { ptr, len } = writeToWasm(seed);
    const result = wasm.generate_nonce(ptr, len);
    const nonce = readFromWasm(result);
    return nonce ? nonce.slice() : null;
}

function encryptData(data, password) {
    const nonce = generateNonce();
    if (!nonce) return null;
    wasm.reset_heap();
    const { ptr: dataPtr, len: dataLen } = writeToWasm(data);
    const { ptr: pwPtr, len: pwLen } = writeToWasm(textEncoder.encode(password));
    const { ptr: noncePtr } = writeToWasm(nonce);
    const result = wasm.aes_ctr_encrypt(dataPtr, dataLen, pwPtr, pwLen, noncePtr);
    const encrypted = readFromWasm(result);
    return encrypted ? encrypted.slice() : null;
}

function decryptData(data, password) {
    wasm.reset_heap();
    const { ptr: dataPtr, len: dataLen } = writeToWasm(data);
    const { ptr: pwPtr, len: pwLen } = writeToWasm(textEncoder.encode(password));
    const result = wasm.aes_ctr_decrypt(dataPtr, dataLen, pwPtr, pwLen);
    const decrypted = readFromWasm(result);
    return decrypted ? decrypted.slice() : null;
}

function base64UrlEncode(data) {
    wasm.reset_heap();
    const { ptr, len } = writeToWasm(data);
    const result = wasm.base64url_encode(ptr, len);
    const encoded = readFromWasm(result);
    return encoded ? textDecoder.decode(encoded) : '';
}

function base64UrlDecode(str) {
    wasm.reset_heap();
    const { ptr, len } = writeToWasm(textEncoder.encode(str));
    const result = wasm.base64url_decode(ptr, len);
    const decoded = readFromWasm(result);
    return decoded ? decoded.slice() : null;
}

// ============================================================================
// INDEXEDDB STORAGE
// ============================================================================

async function saveToIndexedDB(text, password = null) {
    if (!db) return null;
    let data = textEncoder.encode(text);
    if (password) {
        data = encryptData(data, password);
        if (!data) return null;
    }
    const compressed = compressData(data);
    if (!compressed) return null;
    const id = generateShareCode(compressed);
    if (!id) return null;
    const firstLine = text.split('\n')[0].slice(0, 50) || 'Untitled';
    const doc = {
        id, title: firstLine, data: compressed, encrypted: !!password,
        size: text.length, compressedSize: compressed.length,
        created: Date.now(), modified: Date.now()
    };
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const request = store.put(doc);
        request.onsuccess = () => resolve(id);
        request.onerror = () => reject(request.error);
    });
}

async function loadFromIndexedDB(id, password = null) {
    if (!db) return null;
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const request = store.get(id);
        request.onsuccess = () => {
            const doc = request.result;
            if (!doc) { resolve(null); return; }
            let data = decompressData(doc.data);
            if (!data) { resolve(null); return; }
            if (doc.encrypted) {
                if (!password) { resolve({ needsPassword: true, doc }); return; }
                data = decryptData(data, password);
                if (!data) { resolve({ wrongPassword: true }); return; }
            }
            resolve({ text: textDecoder.decode(data), doc });
        };
        request.onerror = () => reject(request.error);
    });
}

async function getAllDocuments() {
    if (!db) return [];
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const index = store.index('created');
        const request = index.openCursor(null, 'prev');
        const docs = [];
        request.onsuccess = (e) => {
            const cursor = e.target.result;
            if (cursor) {
                docs.push({
                    id: cursor.value.id, title: cursor.value.title,
                    size: cursor.value.size, encrypted: cursor.value.encrypted,
                    created: cursor.value.created
                });
                cursor.continue();
            } else resolve(docs);
        };
        request.onerror = () => reject(request.error);
    });
}

async function deleteDocument(id) {
    if (!db) return false;
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const request = store.delete(id);
        request.onsuccess = () => resolve(true);
        request.onerror = () => reject(request.error);
    });
}

// ============================================================================
// URL ENCODING
// ============================================================================

function encodeTextForUrl(text, password = null) {
    if (!text) return '';
    let data = textEncoder.encode(text);
    if (password) {
        data = encryptData(data, password);
        if (!data) return '';
    }
    const compressed = compressData(data);
    if (!compressed) return '';
    const encoded = base64UrlEncode(compressed);
    return (password ? 'e' : '') + encoded;
}

function decodeTextFromUrl(encoded, password = null) {
    if (!encoded) return '';
    const wasEncrypted = encoded.startsWith('e');
    if (wasEncrypted) encoded = encoded.slice(1);
    const decoded = base64UrlDecode(encoded);
    if (!decoded) return '';
    let data = decompressData(decoded);
    if (!data) return '';
    if (wasEncrypted) {
        if (!password) return { needsPassword: true };
        data = decryptData(data, password);
        if (!data) return { wrongPassword: true };
    }
    return textDecoder.decode(data);
}

// ============================================================================
// SAVE/LOAD
// ============================================================================

async function saveDocument() {
    const text = dom.editor.value;
    if (!text) {
        history.replaceState(null, '', location.pathname);
        currentDocId = null;
        storageMode = 'url';
        updateStorageModeDisplay();
        updateUrlStats(0);
        return;
    }
    setStatus('saving');
    try {
        const testEncoded = encodeTextForUrl(text, currentPassword);
        if (testEncoded.length < URL_SIZE_LIMIT) {
            storageMode = 'url';
            currentDocId = null;
            history.replaceState(null, '', `${location.pathname}#${testEncoded}`);
            updateUrlStats(testEncoded.length);
        } else {
            storageMode = 'local';
            const id = await saveToIndexedDB(text, currentPassword);
            if (id) {
                currentDocId = id;
                history.replaceState(null, '', `${location.pathname}#d:${id}`);
                updateUrlStats(id.length + 2);
            }
        }
        updateStorageModeDisplay();
        setStatus('saved');
    } catch (error) {
        console.error('Failed to save:', error);
        setStatus('error');
    }
}

async function loadFromUrl() {
    const hash = location.hash.slice(1);
    if (!hash) return;
    if (hash.startsWith('d:')) {
        const docId = hash.slice(2);
        currentDocId = docId;
        storageMode = 'local';
        const result = await loadFromIndexedDB(docId);
        if (!result) { showToast('Document not found'); return; }
        if (result.needsPassword) {
            isEncrypted = true;
            showPasswordPrompt('decrypt-local', docId);
            return;
        }
        dom.editor.value = result.text;
        isEncrypted = result.doc.encrypted;
        updateStorageModeDisplay();
        updateUrlStats(docId.length + 2);
        currentLanguage = Language.plain;
        updateLineNumbers();
        scheduleHighlight();
        return;
    }
    storageMode = 'url';
    const wasEncrypted = hash.startsWith('e');
    if (wasEncrypted) {
        isEncrypted = true;
        showPasswordPrompt('decrypt');
        return;
    }
    try {
        const text = decodeTextFromUrl(hash);
        if (typeof text === 'string' && text) {
            dom.editor.value = text;
            updateUrlStats(hash.length);
            currentLanguage = Language.plain;
            updateLineNumbers();
            scheduleHighlight();
        }
    } catch (error) {
        console.error('Failed to load from URL:', error);
    }
    updateStorageModeDisplay();
}

// ============================================================================
// UI
// ============================================================================

function updateStats() {
    const text = dom.editor.value;
    const chars = text.length;
    const bytes = textEncoder.encode(text).length;
    const lines = text.split('\n').length;
    dom.stats.textContent = `${lines} lines | ${chars.toLocaleString()} chars | ${formatBytes(bytes)}`;
}

function updateUrlStats(size) {
    dom.url_size.textContent = `URL: ${formatBytes(size)}`;
}

function updateStorageModeDisplay() {
    const mode = storageMode === 'local' ? 'Local' : 'URL';
    const icon = storageMode === 'local' ? '💾' : '🔗';
    dom.storage_mode.textContent = `${icon} ${mode}`;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function setStatus(status) {
    const dot = dom.status_dot;
    const text = dom.status_text;
    switch (status) {
        case 'saving': dot.classList.add('saving'); text.textContent = 'Saving...'; break;
        case 'saved': dot.classList.remove('saving'); text.textContent = isEncrypted ? 'Encrypted' : 'Saved'; break;
        case 'error': dot.classList.remove('saving'); text.textContent = 'Error'; break;
        default: dot.classList.remove('saving'); text.textContent = 'Ready';
    }
}

function showToast(message) {
    dom.toast.textContent = message;
    dom.toast.classList.add('show');
    setTimeout(() => dom.toast.classList.remove('show'), 2000);
}

function closeModal() {
    dom.modal.classList.remove('show');
    dom.qr_canvas.style.display = 'none';
    dom.password_form.style.display = 'block';
    dom.docs_list.style.display = 'none';
    dom.docs_list.innerHTML = '';
}

function showPasswordPrompt(mode, docId = null) {
    dom.modal_title.textContent = mode.includes('decrypt') ? 'Enter Password' : 'Set Password';
    dom.password_form.style.display = 'block';
    dom.docs_list.style.display = 'none';
    dom.qr_canvas.style.display = 'none';
    dom.modal.classList.add('show');
    dom.password_input.value = '';
    dom.password_input.focus();
    const isDecrypt = mode.includes('decrypt');
    dom.password_confirm.style.display = isDecrypt ? 'none' : 'block';
    dom.password_confirm.value = '';
    dom.password_submit.textContent = isDecrypt ? 'Decrypt' : 'Encrypt';
    dom.password_submit.onclick = async () => {
        const password = dom.password_input.value;
        if (!password) return;
        if (isDecrypt) {
            if (mode === 'decrypt-local' && docId) {
                const result = await loadFromIndexedDB(docId, password);
                if (result?.wrongPassword) { showToast('Wrong password!'); return; }
                if (result?.text) {
                    currentPassword = password;
                    dom.editor.value = result.text;
                    updateEncryptionUI(true);
                    updateLineNumbers();
                    scheduleHighlight();
                    closeModal();
                }
            } else {
                const hash = location.hash.slice(1);
                const text = decodeTextFromUrl(hash, password);
                if (text?.wrongPassword) { showToast('Wrong password!'); return; }
                if (typeof text === 'string') {
                    currentPassword = password;
                    dom.editor.value = text;
                    updateUrlStats(hash.length);
                    updateEncryptionUI(true);
                    updateLineNumbers();
                    scheduleHighlight();
                    closeModal();
                }
            }
        } else {
            const confirm = dom.password_confirm.value;
            if (password !== confirm) { showToast('Passwords do not match'); return; }
            currentPassword = password;
            isEncrypted = true;
            updateEncryptionUI(true);
            saveDocument();
            closeModal();
            showToast('Encryption enabled!');
        }
    };
}

function updateEncryptionUI(encrypted) {
    isEncrypted = encrypted;
    dom.encrypt_btn.textContent = encrypted ? 'Encrypted' : 'Encrypt';
    dom.encrypt_btn.classList.toggle('active', encrypted);
}

async function showDocumentsList() {
    dom.modal_title.textContent = 'Saved Documents';
    dom.password_form.style.display = 'none';
    dom.qr_canvas.style.display = 'none';
    dom.docs_list.style.display = 'block';
    dom.docs_list.innerHTML = '<div class="loading-docs">Loading...</div>';
    dom.modal.classList.add('show');
    try {
        const docs = await getAllDocuments();
        if (docs.length === 0) {
            dom.docs_list.innerHTML = '<div class="no-docs">No saved documents</div>';
            return;
        }
        dom.docs_list.innerHTML = docs.map(doc => `
            <div class="doc-item" data-id="${doc.id}">
                <div class="doc-info">
                    <span class="doc-title">${escapeHtml(doc.title)}</span>
                    <span class="doc-meta">${formatBytes(doc.size)} ${doc.encrypted ? '🔒' : ''}</span>
                </div>
                <div class="doc-actions">
                    <button class="doc-load" data-id="${doc.id}">Open</button>
                    <button class="doc-delete" data-id="${doc.id}">Del</button>
                </div>
            </div>
        `).join('');
        dom.docs_list.querySelectorAll('.doc-load').forEach(btn => {
            btn.onclick = () => {
                closeModal();
                history.pushState(null, '', `${location.pathname}#d:${btn.dataset.id}`);
                loadFromUrl();
            };
        });
        dom.docs_list.querySelectorAll('.doc-delete').forEach(btn => {
            btn.onclick = async () => {
                if (confirm('Delete this document?')) {
                    await deleteDocument(btn.dataset.id);
                    btn.closest('.doc-item').remove();
                    if (currentDocId === btn.dataset.id) clearEditor();
                    showToast('Document deleted');
                }
            };
        });
    } catch (error) {
        dom.docs_list.innerHTML = '<div class="error">Failed to load documents</div>';
    }
}

function showQrCode() {
    const url = location.href;
    if (url.length > 2000) { showToast('URL too long for QR code'); return; }
    wasm.reset_heap();
    const urlBytes = textEncoder.encode(url);
    const { ptr, len } = writeToWasm(urlBytes);
    const result = wasm.generate_qr(ptr, len);
    if (result === 0n) { showToast('Failed to generate QR code'); return; }
    const dataPtr = Number(result >> 32n);
    const qrSize = Number((result >> 16n) & 0xFFFFn);
    if (memoryView.buffer !== wasmMemory.buffer) updateMemoryView();
    const qrData = memoryView.subarray(dataPtr, dataPtr + qrSize * qrSize);
    const canvas = dom.qr_canvas;
    const scale = 6, border = 4;
    const size = (qrSize + border * 2) * scale;
    canvas.width = size; canvas.height = size;
    canvas.style.display = 'block';
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';
    for (let y = 0; y < qrSize; y++) {
        for (let x = 0; x < qrSize; x++) {
            if (qrData[y * qrSize + x] === 1) {
                ctx.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
            }
        }
    }
    dom.modal_title.textContent = 'QR Code';
    dom.password_form.style.display = 'none';
    dom.docs_list.style.display = 'none';
    dom.modal.classList.add('show');
}

async function copyLink() {
    try {
        await navigator.clipboard.writeText(location.href);
        showToast('Link copied!');
    } catch {
        const ta = document.createElement('textarea');
        ta.value = location.href;
        ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Link copied!');
    }
}

function clearEditor() {
    dom.editor.value = '';
    currentPassword = null;
    currentDocId = null;
    isEncrypted = false;
    storageMode = 'url';
    currentLanguage = Language.plain;
    history.replaceState(null, '', location.pathname);
    updateStats();
    updateUrlStats(0);
    updateEncryptionUI(false);
    updateStorageModeDisplay();
    updateLanguageButton();
    updateLineNumbers();
    dom.highlight_layer.innerHTML = '<br>';
    setStatus('ready');
    dom.editor.focus();
}

function toggleEncryption() {
    if (isEncrypted) {
        currentPassword = null;
        isEncrypted = false;
        updateEncryptionUI(false);
        saveDocument();
        showToast('Encryption disabled');
    } else {
        showPasswordPrompt('encrypt');
    }
}

const scheduleSave = typeof requestIdleCallback === 'function'
    ? () => { if (saveTimeout) cancelIdleCallback(saveTimeout); saveTimeout = requestIdleCallback(saveDocument, { timeout: 800 }); }
    : () => { if (saveTimeout) clearTimeout(saveTimeout); saveTimeout = setTimeout(saveDocument, 800); };

function setupEventListeners() {
    dom.editor.addEventListener('input', () => {
        updateStats();
        updateLineNumbers();
        scheduleHighlight();
        scheduleSave();
    });
    
    dom.editor.addEventListener('scroll', syncScroll);
    
    dom.copy_btn.addEventListener('click', copyLink);
    dom.clear_btn.addEventListener('click', clearEditor);
    dom.encrypt_btn.addEventListener('click', toggleEncryption);
    dom.qr_btn.addEventListener('click', showQrCode);
    dom.docs_btn.addEventListener('click', showDocumentsList);
    dom.download_btn.addEventListener('click', showDownloadMenu);
    dom.lang_btn.addEventListener('click', cycleLanguage);
    dom.modal_close.addEventListener('click', closeModal);
    dom.modal.addEventListener('click', (e) => { if (e.target === dom.modal) closeModal(); });
    dom.password_input.addEventListener('keydown', (e) => { if (e.key === 'Enter') dom.password_submit.click(); });
    dom.password_confirm.addEventListener('keydown', (e) => { if (e.key === 'Enter') dom.password_submit.click(); });
    window.addEventListener('popstate', () => { loadFromUrl(); updateStats(); });
    
    document.addEventListener('keydown', (e) => {
        const isMod = e.ctrlKey || e.metaKey;
        if (isMod && e.key === 's') {
            e.preventDefault();
            if (saveTimeout) typeof requestIdleCallback === 'function' ? cancelIdleCallback(saveTimeout) : clearTimeout(saveTimeout);
            saveDocument();
        }
        if (isMod && e.shiftKey && e.key === 'C') { e.preventDefault(); copyLink(); }
        if (e.key === 'Escape' && dom.modal.classList.contains('show')) closeModal();
    });
    
    dom.editor.addEventListener('dragover', (e) => { e.preventDefault(); dom.editor.classList.add('dragover'); });
    dom.editor.addEventListener('dragleave', () => { dom.editor.classList.remove('dragover'); });
    dom.editor.addEventListener('drop', async (e) => {
        e.preventDefault();
        dom.editor.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) {
            const text = await file.text();
            dom.editor.value = text;
            currentLanguage = detectLanguageFromFilename(file.name);
            updateStats();
            updateLineNumbers();
            updateLanguageButton();
            scheduleHighlight();
            scheduleSave();
            showToast(`Loaded: ${file.name}`);
        }
    });
}

function detectLanguageFromFilename(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    switch (ext) {
        case 'js': case 'jsx': case 'ts': case 'tsx': case 'mjs': return Language.javascript;
        case 'json': return Language.json;
        case 'html': case 'htm': return Language.html;
        case 'css': case 'scss': case 'less': return Language.css;
        case 'py': case 'pyw': return Language.python;
        case 'md': case 'markdown': return Language.markdown;
        case 'zig': return Language.zig;
        default: return Language.plain;
    }
}

initDom();
initWasm();
