/**
 * gitText - Secure WASM Editor with Supabase Sessions
 * Security: CSP-ready, no eval, sanitized HTML, constant-time compare
 */

'use strict';

// Constants
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();
const DB_CONFIG = { name: 'gt', ver: 1, store: 'd' };
const URL_LIMIT = 32000;
const TOKEN_SIZE = 9;
const LANGS = ['Plain','JavaScript','JSON','HTML','CSS','Python','Markdown','Zig'];
const SUPABASE_URL = 'https://aszsbjmhnnecvokbezaa.supabase.co';
const SUPABASE_KEY = 'sb_publishable_QxCN7rqj58WYyZxywRE9Mw_I4fcGsdM';
const TOKEN_CLASSES = {
    1: 'kw', 2: 'str', 3: 'num', 4: 'cmt',
    5: 'op', 6: 'punc', 7: 'fn', 8: 'type',
    10: 'tag', 11: 'attr', 12: 'prop'
};

// State
let wasm, memory, memView, db, supabase, sessionKey, syncInterval;
let currentLang = 0, storageMode = 'url', password = null, docId = null;
let saveTimeout, highlightTimeout;

// DOM Cache
const dom = {};
const getEl = id => document.getElementById(id);
[
    'editor','editor-wrapper','highlight-layer','line-numbers','loading',
    'copy-btn','clear-btn','encrypt-btn','qr-btn','docs-btn','download-btn','lang-btn','session-btn',
    'stats','status-dot','status-text','url-size','toast',
    'modal','modal-content','modal-close','modal-title',
    'password-form','password-input','password-confirm','password-submit',
    'qr-canvas','docs-list','storage-mode'
].forEach(id => { const el = getEl(id); if (el) dom[id.replace(/-/g, '_')] = el; });

// Secure random key generation
const genKey = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => chars[b % chars.length]).join('');
};

// Constant-time string compare (security)
const secureCompare = (a, b) => {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return result === 0;
};

// Sanitize HTML (security)
const escapeHtml = (() => {
    const div = document.createElement('div');
    return str => {
        div.textContent = str;
        return div.innerHTML;
    };
})();

// WASM Memory Management
const updateMemView = () => { memView = new Uint8Array(memory.buffer); };

const toWasm = bytes => {
    const ptr = wasm.alloc(bytes.length);
    if (!ptr) throw new Error('Alloc failed');
    if (memView.buffer !== memory.buffer) updateMemView();
    memView.set(bytes, ptr);
    return { ptr, len: bytes.length };
};

const fromWasm = packed => {
    const ptr = Number(packed >> 32n);
    const len = Number(packed & 0xFFFFFFFFn);
    if (!ptr || !len) return null;
    if (memView.buffer !== memory.buffer) updateMemView();
    return memView.subarray(ptr, ptr + len);
};

const resetHeap = () => wasm.reset_heap();

// WASM Operations
const wasmOps = {
    compress: data => { resetHeap(); return fromWasm(wasm.compress(...Object.values(toWasm(data))))?.slice(); },
    decompress: data => { resetHeap(); return fromWasm(wasm.decompress(...Object.values(toWasm(data))))?.slice(); },
    b64enc: data => { resetHeap(); const r = fromWasm(wasm.base64url_encode(...Object.values(toWasm(data)))); return r ? DECODER.decode(r) : ''; },
    b64dec: str => { resetHeap(); return fromWasm(wasm.base64url_decode(...Object.values(toWasm(ENCODER.encode(str)))))?.slice(); },
    encrypt: (data, pw) => {
        resetHeap();
        const seed = crypto.getRandomValues(new Uint8Array(16));
        const nonce = fromWasm(wasm.generate_nonce(...Object.values(toWasm(seed))));
        if (!nonce) return null;
        const r = wasm.aes_ctr_encrypt(
            ...Object.values(toWasm(data)),
            ...Object.values(toWasm(ENCODER.encode(pw))),
            ...Object.values(toWasm(nonce))
        );
        return fromWasm(r)?.slice();
    },
    decrypt: (data, pw) => {
        resetHeap();
        const r = wasm.aes_ctr_decrypt(
            ...Object.values(toWasm(data)),
            ...Object.values(toWasm(ENCODER.encode(pw)))
        );
        return fromWasm(r)?.slice();
    },
    tokenize: (text, langId) => {
        if (!text || !langId) return [];
        resetHeap();
        const td = fromWasm(wasm.tokenize(...Object.values(toWasm(ENCODER.encode(text))), langId));
        if (!td) return [];
        const view = new DataView(td.buffer, td.byteOffset, td.byteLength);
        const toks = [];
        for (let i = 0; i + TOKEN_SIZE <= td.length; i += TOKEN_SIZE) {
            toks.push({
                s: view.getUint32(i, true),
                l: view.getUint32(i + 4, true),
                t: td[i + 8]
            });
        }
        return toks;
    },
    qrGen: url => {
        resetHeap();
        const r = wasm.generate_qr(...Object.values(toWasm(ENCODER.encode(url))));
        const ptr = Number(r >> 32n);
        const sz = Number((r >> 16n) & 0xFFFFn);
        return ptr ? { data: memView.subarray(ptr, ptr + sz * sz), sz } : null;
    },
    hash: data => {
        resetHeap();
        const r = fromWasm(wasm.hash_data(...Object.values(toWasm(data))));
        return r ? DECODER.decode(r) : null;
    },
    detectLang: text => {
        resetHeap();
        return wasm.detect_language(...Object.values(toWasm(ENCODER.encode(text.slice(0, 2000)))));
    }
};

// IndexedDB
const idb = {
    init: () => new Promise((res, rej) => {
        const req = indexedDB.open(DB_CONFIG.name, DB_CONFIG.ver);
        req.onerror = () => rej(req.error);
        req.onsuccess = () => res(req.result);
        req.onupgradeneeded = e => {
            const d = e.target.result;
            if (!d.objectStoreNames.contains(DB_CONFIG.store)) {
                const s = d.createObjectStore(DB_CONFIG.store, { keyPath: 'id' });
                s.createIndex('c', 'created', { unique: false });
            }
        };
    }),
    save: (text, pw) => new Promise(async (res, rej) => {
        if (!db) return res(null);
        try {
            let data = ENCODER.encode(text);
            if (pw) data = wasmOps.encrypt(data, pw);
            const compressed = wasmOps.compress(data);
            if (!compressed) return res(null);
            const id = wasmOps.hash(compressed);
            if (!id) return res(null);
            const doc = {
                id,
                title: text.split('\n')[0].slice(0, 50) || 'Untitled',
                data: compressed,
                enc: !!pw,
                size: text.length,
                created: Date.now()
            };
            const tx = db.transaction(DB_CONFIG.store, 'readwrite');
            const r = tx.objectStore(DB_CONFIG.store).put(doc);
            r.onsuccess = () => res(id);
            r.onerror = () => rej(r.error);
        } catch (e) { rej(e); }
    }),
    load: (id, pw) => new Promise((res, rej) => {
        if (!db) return res(null);
        const tx = db.transaction(DB_CONFIG.store, 'readonly');
        const r = tx.objectStore(DB_CONFIG.store).get(id);
        r.onsuccess = () => {
            const doc = r.result;
            if (!doc) return res(null);
            let data = wasmOps.decompress(doc.data);
            if (!data) return res(null);
            if (doc.enc) {
                if (!pw) return res({ needPw: true, doc });
                data = wasmOps.decrypt(data, pw);
                if (!data) return res({ badPw: true });
            }
            res({ text: DECODER.decode(data), doc });
        };
        r.onerror = () => rej(r.error);
    }),
    all: () => new Promise((res, rej) => {
        if (!db) return res([]);
        const tx = db.transaction(DB_CONFIG.store, 'readonly');
        const r = tx.objectStore(DB_CONFIG.store).index('c').openCursor(null, 'prev');
        const docs = [];
        r.onsuccess = e => {
            const c = e.target.result;
            if (c) {
                docs.push({ id: c.value.id, title: c.value.title, size: c.value.size, enc: c.value.enc, created: c.value.created });
                c.continue();
            } else res(docs);
        };
        r.onerror = () => rej(r.error);
    }),
    del: id => new Promise((res, rej) => {
        if (!db) return res(false);
        const tx = db.transaction(DB_CONFIG.store, 'readwrite');
        const r = tx.objectStore(DB_CONFIG.store).delete(id);
        r.onsuccess = () => res(true);
        r.onerror = () => rej(r.error);
    })
};

// URL Encoding
const urlEnc = (text, pw) => {
    let data = ENCODER.encode(text);
    if (pw) data = wasmOps.encrypt(data, pw);
    return (pw ? 'e' : '') + wasmOps.b64enc(wasmOps.compress(data));
};

const urlDec = (str, pw) => {
    const isEnc = str[0] === 'e';
    if (isEnc) str = str.slice(1);
    const raw = wasmOps.b64dec(str);
    if (!raw) return null;
    let data = wasmOps.decompress(raw);
    if (!data) return null;
    if (isEnc) {
        if (!pw) return { needPw: true };
        data = wasmOps.decrypt(data, pw);
        if (!data) return { badPw: true };
    }
    return DECODER.decode(data);
};

// Supabase Sessions
const session = {
    create: async pw => {
        if (!supabase) return ui.toast('Supabase not ready');
        const key = genKey();
        const text = dom.editor.value;
        if (!text) return ui.toast('Nothing to share');
        try {
            let data = ENCODER.encode(text);
            if (pw) data = wasmOps.encrypt(data, pw);
            const compressed = wasmOps.compress(data);
            if (!compressed) return ui.toast('Compression failed');
            const payload = {
                k: key,
                d: wasmOps.b64enc(compressed),
                e: !!pw,
                u: new Date().toISOString()
            };
            const { error } = await supabase.from('sessions').upsert(payload);
            if (error) throw error;
            sessionKey = key;
            if (pw) password = pw;
            const url = new URL(location.href);
            url.searchParams.set('s', key);
            history.replaceState(null, '', url);
            session.startSync();
            ui.updateSession(true);
            ui.toast(`Session: ${key}`);
        } catch (e) { console.error(e); ui.toast('Failed to create session'); }
    },
    join: async (key, pw) => {
        if (!supabase) return ui.toast('Supabase not ready');
        try {
            const { data, error } = await supabase.from('sessions').select('d,e').eq('k', key).single();
            if (error || !data) return ui.toast('Session not found');
            const raw = wasmOps.b64dec(data.d);
            if (!raw) return ui.toast('Decode failed');
            let decrypted = wasmOps.decompress(raw);
            if (!decrypted) return ui.toast('Decompress failed');
            if (data.e) {
                if (!pw) return ui.showSessionPw(key);
                decrypted = wasmOps.decrypt(decrypted, pw);
                if (!decrypted) return ui.toast('Wrong password');
            }
            dom.editor.value = DECODER.decode(decrypted);
            sessionKey = key;
            if (pw) password = pw;
            const url = new URL(location.href);
            url.searchParams.set('s', key);
            history.replaceState(null, '', url);
            ui.updateAll();
            session.startSync();
            ui.updateSession(true);
            ui.toast(`Joined: ${key}`);
        } catch (e) { console.error(e); ui.toast('Failed to join session'); }
    },
    syncUp: async () => {
        if (!sessionKey || !supabase) return;
        const text = dom.editor.value;
        if (!text) return;
        try {
            let data = ENCODER.encode(text);
            if (password) data = wasmOps.encrypt(data, password);
            await supabase.from('sessions').upsert({
                k: sessionKey,
                d: wasmOps.b64enc(wasmOps.compress(data)),
                e: !!password,
                u: new Date().toISOString()
            });
            ui.setStatus('saved');
        } catch (e) { console.error(e); }
    },
    syncDown: async () => {
        if (!sessionKey || !supabase) return;
        try {
            const { data } = await supabase.from('sessions').select('d,e').eq('k', sessionKey).single();
            if (!data) return;
            const raw = wasmOps.b64dec(data.d);
            if (!raw) return;
            let decrypted = wasmOps.decompress(raw);
            if (!decrypted) return;
            if (data.e) {
                if (!password) return; // Can't decrypt without password
                decrypted = wasmOps.decrypt(decrypted, password);
                if (!decrypted) return;
            }
            const text = DECODER.decode(decrypted);
            if (text !== dom.editor.value) {
                dom.editor.value = text;
                ui.updateAll();
                ui.toast('Session updated');
            }
        } catch (e) { console.error(e); }
    },
    startSync: () => {
        if (syncInterval) clearInterval(syncInterval);
        syncInterval = setInterval(session.syncDown, 5000);
    },
    stop: () => {
        if (syncInterval) clearInterval(syncInterval);
        syncInterval = null;
        sessionKey = null;
        ui.updateSession(false);
        const url = new URL(location.href);
        url.searchParams.delete('s');
        history.replaceState(null, '', url);
    }
};

// UI Helpers
const ui = {
    toast: msg => {
        dom.toast.textContent = msg;
        dom.toast.classList.add('show');
        setTimeout(() => dom.toast.classList.remove('show'), 2000);
    },
    setStatus: s => {
        dom.status_dot.classList.toggle('saving', s === 'saving');
        dom.status_text.textContent = s === 'saving' ? 'Saving...' : s === 'saved' ? (password ? 'ENCRYPTED' : 'SAVED') : 'READY';
    },
    closeModal: () => {
        dom.modal.classList.remove('show');
        dom.qr_canvas.style.display = 'none';
        dom.password_form.style.display = 'block';
        dom.docs_list.style.display = 'none';
        dom.docs_list.innerHTML = '';
    },
    updateStats: () => {
        const text = dom.editor.value;
        const chars = text.length;
        const bytes = ENCODER.encode(text).length;
        const lines = text.split('\n').length;
        dom.stats.textContent = `${lines}L | ${chars}C | ${ui.fmtBytes(bytes)}`;
    },
    fmtBytes: b => b < 1024 ? `${b}B` : b < 1048576 ? `${(b/1024).toFixed(1)}K` : `${(b/1048576).toFixed(2)}M`,
    updateLines: () => {
        const n = dom.editor.value.split('\n').length;
        dom.line_numbers.textContent = Array.from({length: n}, (_,i) => i + 1).join('\n');
    },
    syncScroll: () => {
        const st = dom.editor.scrollTop;
        dom.line_numbers.scrollTop = st;
        dom.highlight_layer.scrollTop = st;
        dom.highlight_layer.scrollLeft = dom.editor.scrollLeft;
    },
    updateAll: () => { ui.updateStats(); ui.updateLines(); ui.highlight(); },
    updateSession: on => {
        if (dom.session_btn) {
            dom.session_btn.textContent = on ? 'LEAVE' : 'SESSION';
            dom.session_btn.classList.toggle('active', on);
        }
        dom.storage_mode.textContent = on ? '[CLOUD]' : (storageMode === 'local' ? '[LOCAL]' : '[URL]');
    },
    getExt: () => ['txt','js','json','html','css','py','md','zig'][currentLang],
    highlight: () => {
        if (!dom.highlight_layer) return;
        const text = dom.editor.value;
        if (!text) return dom.highlight_layer.innerHTML = '<br>';
        if (!currentLang) {
            currentLang = wasmOps.detectLang(text);
            dom.lang_btn.textContent = LANGS[currentLang];
        }
        if (!currentLang) return dom.highlight_layer.textContent = text;
        const toks = wasmOps.tokenize(text, currentLang);
        if (!toks.length) return dom.highlight_layer.textContent = text;
        let html = '', lastEnd = 0;
        for (const tk of toks) {
            if (tk.s > lastEnd) html += escapeHtml(text.slice(lastEnd, tk.s));
            const cls = TOKEN_CLASSES[tk.t];
            const content = escapeHtml(text.slice(tk.s, tk.s + tk.l));
            html += cls ? `<span class="tok-${cls}">${content}</span>` : content;
            lastEnd = tk.s + tk.l;
        }
        if (lastEnd < text.length) html += escapeHtml(text.slice(lastEnd));
        dom.highlight_layer.innerHTML = html || '<br>';
    },
    scheduleHighlight: () => {
        if (highlightTimeout) cancelAnimationFrame(highlightTimeout);
        highlightTimeout = requestAnimationFrame(ui.highlight);
    },
    showPassword: (mode, id = null) => {
        const isDec = mode.includes('decrypt');
        dom.modal_title.textContent = isDec ? 'DECRYPT' : 'ENCRYPT';
        dom.password_form.style.display = 'block';
        dom.docs_list.style.display = 'none';
        dom.qr_canvas.style.display = 'none';
        dom.modal.classList.add('show');
        dom.password_input.value = '';
        dom.password_confirm.style.display = isDec ? 'none' : 'block';
        dom.password_confirm.value = '';
        dom.password_submit.textContent = isDec ? 'DECRYPT' : 'ENCRYPT';
        dom.password_submit.onclick = async () => {
            const pw = dom.password_input.value;
            if (!pw) return;
            if (isDec) {
                if (mode === 'decrypt-local' && id) {
                    const r = await idb.load(id, pw);
                    if (r?.badPw) return ui.toast('Wrong password');
                    if (r?.text) {
                        password = pw;
                        dom.editor.value = r.text;
                        dom.encrypt_btn.textContent = 'ENCRYPTED';
                        dom.encrypt_btn.classList.add('active');
                        ui.updateAll();
                        ui.closeModal();
                    }
                } else {
                    const t = urlDec(location.hash.slice(1), pw);
                    if (t?.badPw) return ui.toast('Wrong password');
                    if (typeof t === 'string') {
                        password = pw;
                        dom.editor.value = t;
                        dom.encrypt_btn.textContent = 'ENCRYPTED';
                        dom.encrypt_btn.classList.add('active');
                        ui.updateAll();
                        ui.closeModal();
                    }
                }
            } else {
                if (!secureCompare(pw, dom.password_confirm.value)) return ui.toast('Passwords do not match');
                password = pw;
                dom.encrypt_btn.textContent = 'ENCRYPTED';
                dom.encrypt_btn.classList.add('active');
                if (mode === 'sess-enc-create') {
                    session.create(pw);
                } else {
                    doc.save();
                }
                ui.closeModal();
                ui.toast('Encrypted');
            }
        };
    },
    showSessionPw: key => {
        dom.modal_title.textContent = 'SESSION PASSWORD';
        dom.password_form.style.display = 'block';
        dom.docs_list.style.display = 'none';
        dom.qr_canvas.style.display = 'none';
        dom.modal.classList.add('show');
        dom.password_input.value = '';
        dom.password_confirm.style.display = 'none';
        dom.password_submit.textContent = 'JOIN';
        dom.password_submit.onclick = () => {
            session.join(key, dom.password_input.value);
            ui.closeModal();
        };
    },
    showSessionDlg: () => {
        if (sessionKey) { session.stop(); ui.toast('Left session'); return; }
        dom.modal_title.textContent = 'SESSION';
        dom.password_form.style.display = 'none';
        dom.docs_list.style.display = 'block';
        dom.docs_list.innerHTML = `
            <div class="download-options">
                <button class="download-option" id="sc"><span class="download-icon">[NEW]</span><span>CREATE</span></button>
                <button class="download-option" id="se"><span class="download-icon">[ENC]</span><span>ENCRYPTED</span></button>
                <div style="margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border)">
                    <input id="ski" placeholder="ENTER_KEY" style="width:100%;padding:.75rem;background:var(--bg-dark);border:1px solid var(--border);border-radius:6px;color:var(--text);margin-bottom:.5rem;font-family:monospace">
                    <button class="download-option" id="sj" style="width:100%"><span class="download-icon">[JOIN]</span><span>JOIN</span></button>
                </div>
            </div>`;
        dom.modal.classList.add('show');
        getEl('sc').onclick = () => { ui.closeModal(); session.create(); };
        getEl('se').onclick = () => {
            ui.closeModal();
            ui.showPassword('sess-enc-create');
        };
        getEl('sj').onclick = () => {
            const k = getEl('ski').value.trim();
            if (k) { ui.closeModal(); session.join(k); }
        };
    },
    showDocs: async () => {
        dom.modal_title.textContent = 'DOCUMENTS';
        dom.password_form.style.display = 'none';
        dom.docs_list.style.display = 'block';
        dom.docs_list.innerHTML = '<div class="loading-docs">...</div>';
        dom.modal.classList.add('show');
        try {
            const docs = await idb.all();
            if (!docs.length) return dom.docs_list.innerHTML = '<div class="no-docs">NO DOCUMENTS</div>';
            dom.docs_list.innerHTML = docs.map(d => `
                <div class="doc-item" data-id="${escapeHtml(d.id)}">
                    <div class="doc-info">
                        <span class="doc-title">${escapeHtml(d.title)}</span>
                        <span class="doc-meta">${ui.fmtBytes(d.size)} ${d.enc ? '[ENC]' : ''}</span>
                    </div>
                    <div class="doc-actions">
                        <button class="doc-load" data-id="${escapeHtml(d.id)}">OPEN</button>
                        <button class="doc-delete" data-id="${escapeHtml(d.id)}">DEL</button>
                    </div>
                </div>`).join('');
            dom.docs_list.querySelectorAll('.doc-load').forEach(b => b.onclick = () => {
                ui.closeModal();
                history.pushState(null, '', location.pathname + '#d:' + b.dataset.id);
                doc.load();
            });
            dom.docs_list.querySelectorAll('.doc-delete').forEach(b => b.onclick = async () => {
                if (confirm('Delete?')) {
                    await idb.del(b.dataset.id);
                    b.closest('.doc-item').remove();
                    if (docId === b.dataset.id) doc.clear();
                    ui.toast('Deleted');
                }
            });
        } catch (e) { dom.docs_list.innerHTML = '<div class="error">ERROR</div>'; }
    },
    showDL: () => {
        dom.modal_title.textContent = 'DOWNLOAD';
        dom.password_form.style.display = 'none';
        dom.docs_list.style.display = 'block';
        dom.docs_list.innerHTML = `
            <div class="download-options">
                <button class="download-option" data-f="txt"><span class="download-icon">[TXT]</span><span>.${ui.getExt()}</span></button>
                <button class="download-option" data-f="lzss"><span class="download-icon">[LZSS]</span><span>.lzss</span></button>
            </div>`;
        dom.docs_list.querySelectorAll('.download-option').forEach(b => b.onclick = () => {
            const text = dom.editor.value;
            if (!text) return ui.toast('Empty');
            const a = document.createElement('a');
            const ts = new Date().toISOString().slice(0, 10).replace(/-/g, '');
            if (b.dataset.f === 'lzss') {
                const c = wasmOps.compress(ENCODER.encode(text));
                if (!c) return ui.toast('Failed');
                a.href = URL.createObjectURL(new Blob([c]));
                a.download = `gt_${ts}.lzss`;
            } else {
                a.href = URL.createObjectURL(new Blob([text]));
                a.download = `gt_${ts}.${ui.getExt()}`;
            }
            a.click();
            setTimeout(() => URL.revokeObjectURL(a.href), 1000);
            ui.closeModal();
            ui.toast('Downloaded');
        });
        dom.modal.classList.add('show');
    },
    showQR: () => {
        const url = location.href;
        if (url.length > 2000) return ui.toast('URL too long');
        const q = wasmOps.qrGen(url);
        if (!q) return ui.toast('Failed');
        dom.qr_canvas.style.display = 'block';
        dom.qr_canvas.width = dom.qr_canvas.height = (q.sz + 8) * 6;
        const ctx = dom.qr_canvas.getContext('2d');
        ctx.fillStyle = '#000';
        ctx.fillRect(0, 0, dom.qr_canvas.width, dom.qr_canvas.height);
        ctx.fillStyle = '#0f0';
        for (let y = 0; y < q.sz; y++) {
            for (let x = 0; x < q.sz; x++) {
                if (q.data[y * q.sz + x]) ctx.fillRect((x + 4) * 6, (y + 4) * 6, 6, 6);
            }
        }
        dom.modal_title.textContent = 'QR CODE';
        dom.password_form.style.display = 'none';
        dom.docs_list.style.display = 'none';
        dom.modal.classList.add('show');
    }
};

// Document Operations
const doc = {
    save: async () => {
        const text = dom.editor.value;
        if (!text) {
            history.replaceState(null, '', location.pathname);
            docId = null;
            storageMode = 'url';
            dom.storage_mode.textContent = '[URL]';
            dom.url_size.textContent = '0B';
            return;
        }
        ui.setStatus('saving');
        try {
            const encoded = urlEnc(text, password);
            if (encoded.length < URL_LIMIT) {
                storageMode = 'url';
                docId = null;
                history.replaceState(null, '', location.pathname + '#' + encoded);
                dom.url_size.textContent = ui.fmtBytes(encoded.length);
            } else {
                storageMode = 'local';
                const id = await idb.save(text, password);
                if (id) {
                    docId = id;
                    history.replaceState(null, '', location.pathname + '#d:' + id);
                    dom.url_size.textContent = ui.fmtBytes(id.length + 2);
                }
            }
            dom.storage_mode.textContent = storageMode === 'local' ? '[LOCAL]' : '[URL]';
            ui.setStatus('saved');
            if (sessionKey) session.syncUp();
        } catch (e) { console.error(e); ui.setStatus('error'); }
    },
    load: async () => {
        const hash = location.hash.slice(1);
        if (!hash) return;
        if (hash.startsWith('d:')) {
            const id = hash.slice(2);
            docId = id;
            storageMode = 'local';
            const r = await idb.load(id);
            if (!r) return ui.toast('Not found');
            if (r.needPw) return ui.showPassword('decrypt-local', id);
            dom.editor.value = r.text;
            password = r.doc.enc ? password : null;
            dom.storage_mode.textContent = '[LOCAL]';
            dom.url_size.textContent = ui.fmtBytes(id.length + 2);
            ui.updateAll();
            return;
        }
        storageMode = 'url';
        if (hash[0] === 'e') return ui.showPassword('decrypt');
        try {
            const t = urlDec(hash);
            if (typeof t === 'string' && t) {
                dom.editor.value = t;
                dom.url_size.textContent = ui.fmtBytes(hash.length);
                ui.updateAll();
            }
        } catch (e) { console.error(e); }
        dom.storage_mode.textContent = '[URL]';
    },
    clear: () => {
        dom.editor.value = '';
        password = null;
        docId = null;
        storageMode = 'url';
        currentLang = 0;
        history.replaceState(null, '', location.pathname);
        ui.updateAll();
        dom.encrypt_btn.textContent = 'ENCRYPT';
        dom.encrypt_btn.classList.remove('active');
        dom.highlight_layer.innerHTML = '<br>';
        ui.setStatus('ready');
        dom.editor.focus();
    }
};

// Actions
const actions = {
    copy: async () => {
        try {
            await navigator.clipboard.writeText(location.href);
            ui.toast('Copied');
        } catch {
            const t = document.createElement('textarea');
            t.value = location.href;
            t.style.cssText = 'position:fixed;opacity:0';
            document.body.appendChild(t);
            t.select();
            document.execCommand('copy');
            document.body.removeChild(t);
            ui.toast('Copied');
        }
    },
    toggleEnc: () => {
        if (password) {
            password = null;
            dom.encrypt_btn.textContent = 'ENCRYPT';
            dom.encrypt_btn.classList.remove('active');
            doc.save();
            ui.toast('Decrypted');
        } else ui.showPassword('encrypt');
    },
    cycleLang: () => {
        currentLang = (currentLang + 1) % LANGS.length;
        dom.lang_btn.textContent = LANGS[currentLang];
        ui.scheduleHighlight();
    }
};

// Initialization
const init = async () => {
    try {
        supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
        const [wasmResult] = await Promise.all([
            fetch('editor.wasm')
                .then(r => r.arrayBuffer())
                .then(b => WebAssembly.instantiate(b, { env: {} }))
                .then(m => {
                    wasm = m.instance.exports;
                    memory = wasm.memory;
                    updateMemView();
                }),
            idb.init().then(d => db = d).catch(e => console.warn('IDB:', e))
        ]);

        dom.loading.style.display = 'none';
        dom.editor_wrapper.style.display = 'flex';
        ['copy_btn','clear_btn','encrypt_btn','qr_btn','docs_btn','download_btn','lang_btn','session_btn']
            .forEach(b => dom[b] && (dom[b].disabled = false));

        await doc.load();

        // Event Listeners
        dom.editor.addEventListener('input', () => { ui.updateAll(); doc.save(); });
        dom.editor.addEventListener('scroll', ui.syncScroll);
        dom.copy_btn.onclick = actions.copy;
        dom.clear_btn.onclick = doc.clear;
        dom.encrypt_btn.onclick = actions.toggleEnc;
        dom.qr_btn.onclick = ui.showQR;
        dom.docs_btn.onclick = ui.showDocs;
        dom.download_btn.onclick = ui.showDL;
        dom.lang_btn.onclick = actions.cycleLang;
        if (dom.session_btn) dom.session_btn.onclick = ui.showSessionDlg;
        dom.modal_close.onclick = ui.closeModal;
        dom.modal.onclick = e => { if (e.target === dom.modal) ui.closeModal(); };
        dom.password_input.onkeydown = dom.password_confirm.onkeydown = e => {
            if (e.key === 'Enter') dom.password_submit.click();
        };
        window.onpopstate = () => { doc.load(); ui.updateStats(); };
        document.onkeydown = e => {
            const mod = e.ctrlKey || e.metaKey;
            if (mod && e.key === 's') {
                e.preventDefault();
                if (saveTimeout) clearTimeout(saveTimeout);
                doc.save();
            }
            if (mod && e.shiftKey && e.key === 'C') { e.preventDefault(); actions.copy(); }
            if (e.key === 'Escape' && dom.modal.classList.contains('show')) ui.closeModal();
        };
        dom.editor.ondragover = e => { e.preventDefault(); dom.editor.classList.add('dragover'); };
        dom.editor.ondragleave = () => dom.editor.classList.remove('dragover');
        dom.editor.ondrop = async e => {
            e.preventDefault();
            dom.editor.classList.remove('dragover');
            const f = e.dataTransfer.files[0];
            if (f) {
                dom.editor.value = await f.text();
                const ext = f.name.split('.').pop().toLowerCase();
                currentLang = { js: 1, jsx: 1, ts: 1, tsx: 1, mjs: 1, json: 2, html: 3, htm: 3, css: 4, scss: 4, less: 4, py: 5, pyw: 5, md: 6, markdown: 6, zig: 7 }[ext] || 0;
                dom.lang_btn.textContent = LANGS[currentLang];
                ui.updateAll();
                doc.save();
                ui.toast(f.name);
            }
        };

        // Check for session in URL
        const url = new URL(location.href);
        const sKey = url.searchParams.get('s');
        if (sKey) await session.join(sKey);

    } catch (e) {
        console.error(e);
        dom.loading.textContent = 'ERROR LOADING';
    }
};

init();
