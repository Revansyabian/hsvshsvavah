(function () {
    'use strict';

    var SERVER_KEY_URL = '/api/webtopupbussid?action=key';
    var CHECK_MAINTENANCE_URL = '/api/webtopupbussid?action=cek-maintece';
    var CHECK_BLOCK_URL = '/api/webtopupbussid?action=cek-block';
    var STORAGE_KEY = '__webtopup_storage__';
    var CLIENT_KEY_SESSION = '__webtopup_client_key__';
    var originalFetch = window.fetch.bind(window);
    var originalSetItem = Storage.prototype.setItem;
    var originalGetItem = Storage.prototype.getItem;
    var originalRemoveItem = Storage.prototype.removeItem;
    var clientKeysPromise = null;
    var serverPublicKeyPromise = null;

    function b64u(bytes) {
        var s = '';
        var arr = new Uint8Array(bytes);
        for (var i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }
    function unb64u(s) {
        s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        var raw = atob(s), out = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    }
    function pemToDer(pem) {
        var clean = String(pem).replace(/-----BEGIN PUBLIC KEY-----/g, '').replace(/-----END PUBLIC KEY-----/g, '').replace(/\s/g, '');
        return unb64u(clean);
    }
    function bytesToPem(bytes) {
        var raw = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(bytes))));
        var out = '';
        for (var i = 0; i < raw.length; i += 64) out += raw.slice(i, i + 64) + '\n';
        return '-----BEGIN PUBLIC KEY-----\n' + out + '-----END PUBLIC KEY-----';
    }
    function randomString(size) {
        var bytes = new Uint8Array(size);
        crypto.getRandomValues(bytes);
        return b64u(bytes);
    }

    async function getClientKeys() {
        if (clientKeysPromise) return clientKeysPromise;
        clientKeysPromise = crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt'])
            .then(async function (keys) {
                var pub = await crypto.subtle.exportKey('spki', keys.publicKey);
                var pubPem = bytesToPem(pub);
                return { publicKey: keys.publicKey, privateKey: keys.privateKey, publicPem: pubPem, publicB64: b64u(pub) };
            });
        return clientKeysPromise;
    }

    async function getServerPublicKey() {
        if (serverPublicKeyPromise) return serverPublicKeyPromise;
        serverPublicKeyPromise = originalFetch(SERVER_KEY_URL, { credentials: 'same-origin', cache: 'no-store' })
            .then(function (r) { if (!r.ok) throw new Error('Gagal mengambil public key'); return r.json(); })
            .then(function (data) {
                return crypto.subtle.importKey('spki', pemToDer(data.publicKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
            });
        return serverPublicKeyPromise;
    }

    async function encryptEnvelope(data) {
        var keys = await getClientKeys();
        var serverKey = await getServerPublicKey();
        var aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
        var iv = crypto.getRandomValues(new Uint8Array(12));
        var plain = new TextEncoder().encode(JSON.stringify(data));
        var cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, aesKey, plain);
        var rawAes = await crypto.subtle.exportKey('raw', aesKey);
        var wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, serverKey, rawAes);
        var cipherBytes = new Uint8Array(cipher);
        var tag = cipherBytes.slice(cipherBytes.length - 16);
        var body = cipherBytes.slice(0, cipherBytes.length - 16);
        return { envelope: { v: 1, alg: 'RSA-OAEP-256/AES-256-GCM', key: b64u(wrapped), iv: b64u(iv), tag: b64u(tag), data: b64u(body) }, publicPem: keys.publicPem };
    }

    async function decryptEnvelope(envelope) {
        if (!envelope || envelope.v !== 1) throw new Error('Encrypted response tidak valid');
        var keys = await getClientKeys();
        var wrapped = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, keys.privateKey, unb64u(envelope.key));
        var aesKey = await crypto.subtle.importKey('raw', wrapped, { name: 'AES-GCM' }, false, ['decrypt']);
        var body = unb64u(envelope.data), tag = unb64u(envelope.tag);
        var combined = new Uint8Array(body.length + tag.length);
        combined.set(body); combined.set(tag, body.length);
        var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(envelope.iv), tagLength: 128 }, aesKey, combined);
        return JSON.parse(new TextDecoder().decode(plain));
    }

    function storageKey() {
        var key = sessionStorage.getItem(CLIENT_KEY_SESSION);
        if (!key) {
            key = randomString(32);
            sessionStorage.setItem(CLIENT_KEY_SESSION, key);
        }
        return key;
    }
    function storageEncrypt(value) {
        if (!window.CryptoJS) return value;
        var iv = CryptoJS.lib.WordArray.random(16);
        var key = CryptoJS.SHA256(storageKey());
        var encrypted = CryptoJS.AES.encrypt(String(value), key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
        return 'v1.' + iv.toString(CryptoJS.enc.Base64) + '.' + encrypted.ciphertext.toString(CryptoJS.enc.Base64);
    }
    function storageDecrypt(value) {
        if (!value || !window.CryptoJS || value.indexOf('v1.') !== 0) return value;
        try {
            var parts = value.split('.');
            var iv = CryptoJS.enc.Base64.parse(parts[1]);
            var cipher = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(parts[2]) });
            var key = CryptoJS.SHA256(storageKey());
            return CryptoJS.AES.decrypt(cipher, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
        } catch (e) { return null; }
    }
    function isLocalStorage(target) { return target === window.localStorage; }

    Storage.prototype.setItem = function (key, value) {
        if (isLocalStorage(this) && key !== STORAGE_KEY) return originalSetItem.call(this, key, storageEncrypt(value));
        return originalSetItem.call(this, key, value);
    };
    Storage.prototype.getItem = function (key) {
        var value = originalGetItem.call(this, key);
        if (isLocalStorage(this) && key !== STORAGE_KEY) return storageDecrypt(value);
        return value;
    };
    Storage.prototype.removeItem = function (key) {
        return originalRemoveItem.call(this, key);
    };

    window.fetch = async function (input, init) {
        var url = typeof input === 'string' ? input : input.url;
        var absolute = new URL(url, location.href);
        var sameApi = absolute.origin === location.origin && absolute.pathname.indexOf('/api/') === 0;
        var exempt = absolute.pathname === '/api/rvnstore' || ((absolute.pathname === '/api/webtopup' || absolute.pathname === '/api/webtopupbussid') && absolute.searchParams.get('action') === 'key');
        if (!sameApi || exempt) return originalFetch(input, init);

        var options = init ? Object.assign({}, init) : {};
        var headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined));
        headers.set('Content-Type', 'application/json');
        var keys = await getClientKeys();
        headers.set('X-Client-Key', keys.publicB64);
        headers.set('X-Fingerprint', await getFingerprintSafe());

        if (options.body && typeof options.body === 'string') {
            try {
                var data = JSON.parse(options.body);
                var enc = await encryptEnvelope(data);
                options.body = JSON.stringify(enc.envelope);
            } catch (e) {}
        }
        options.headers = headers;
        var response = await originalFetch(input, options);
        var text = await response.text();
        if (!text) return new Response('', { status: response.status, statusText: response.statusText, headers: response.headers });
        var parsed;
        try { parsed = JSON.parse(text); } catch (e) { return new Response(text, { status: response.status, statusText: response.statusText, headers: response.headers }); }
        if (!parsed || parsed.v !== 1 || !parsed.data || !parsed.key) return new Response(text, { status: response.status, statusText: response.statusText, headers: response.headers });
        try {
            var plain = await decryptEnvelope(parsed);
            if (plain && Object.prototype.hasOwnProperty.call(plain, 'data')) {
                plain = plain.data;
            }
            return new Response(JSON.stringify(plain), { status: response.status, statusText: response.statusText, headers: response.headers });
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Gagal mendekripsi response' }), { status: 502, headers: { 'Content-Type': 'application/json' } });
        }
    };

    async function periodicSecurityCheck() {
        try {
            var keys = await getClientKeys();
            var fp = await getFingerprintSafe();
            var headers = { 'X-Fingerprint': fp, 'X-Client-Key': keys.publicPem };
            var blockRes = await originalFetch(CHECK_BLOCK_URL, { credentials: 'same-origin', cache: 'no-store', headers: headers });
            if (blockRes.ok) {
                var blockData = await decryptDirect(blockRes);
                if (blockData && blockData.blocked) showSecurityBlock();
            }
            var maintenanceRes = await originalFetch(CHECK_MAINTENANCE_URL, { credentials: 'same-origin', cache: 'no-store', headers: headers });
            if (maintenanceRes.ok) {
                var maintenanceData = await decryptDirect(maintenanceRes);
                window.dispatchEvent(new CustomEvent('webtopup:maintenance', { detail: maintenanceData }));
                if (maintenanceData && maintenanceData.maintenance) showMaintenance(maintenanceData);
            }
        } catch (e) {}
    }
    async function decryptDirect(response) {
        var data = await response.json();
        return decryptEnvelope(data);
    }
    async function getFingerprintSafe() {
        if (window.getFingerprint && typeof window.getFingerprint === 'function') {
            try { return await window.getFingerprint(); } catch (e) {}
        }
        var raw = [navigator.userAgent, navigator.language, screen.width, screen.height, screen.colorDepth, new Date().getTimezoneOffset(), navigator.hardwareConcurrency || '', navigator.deviceMemory || '', navigator.platform || ''].join('|');
        var digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
        return Array.from(new Uint8Array(digest)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    }
    function showSecurityBlock() {
        if (document.getElementById('__webtopup_block__')) return;
        var div = document.createElement('div'); div.id = '__webtopup_block__'; div.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:#fff;display:flex;align-items:center;justify-content:center;padding:24px;text-align:center;font-family:Arial,sans-serif';
        div.innerHTML = '<div><h2>Akses Ditangguhkan</h2><p>IP atau fingerprint perangkat ini diblokir.</p></div>';
        document.documentElement.appendChild(div);
    }
    function showMaintenance(data) {
        if (document.getElementById('__webtopup_maintenance__')) return;
        var div = document.createElement('div'); div.id = '__webtopup_maintenance__'; div.style.cssText = 'position:fixed;inset:0;z-index:2147483646;background:#fff;display:flex;align-items:center;justify-content:center;padding:24px;text-align:center;font-family:Arial,sans-serif';
        div.innerHTML = '<div><h2>' + escapeHtml(data.title || 'Maintenance') + '</h2><p>' + escapeHtml(data.message || 'Website sedang dalam perbaikan.') + '</p></div>';
        document.documentElement.appendChild(div);
    }
    function escapeHtml(s) { return String(s || '').replace(/[&<>'"]/g, function (c) { return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[c]; }); }

    window.webtopupSecurity = { check: periodicSecurityCheck, getFingerprint: getFingerprintSafe };
    setTimeout(periodicSecurityCheck, 300);
    setInterval(periodicSecurityCheck, 60000);
})();
