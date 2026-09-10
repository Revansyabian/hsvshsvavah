var API_REVANSTORE = '/api/revanstoreV2';
var API_TOPUPBUSSID = '/api/topupbussid';
var WHATSAPP_NUMBER = "6285199120995";
var MAX_TOPUP_AMOUNT = 2147483647;
var RECAPTCHA_V3_SITE_KEY = '6LcVBn4tAAAAAINTTIleUbUZr1ZykvyB6WA-oOfT';

var currentUser = null;
var currentAccount = null;
var currentAuthToken = null;
var pendingAction = null;
var pendingData = null;
var lastDeviceId = null;
var fingerprint = '';
var alertTimeout = null;
var isBlocked = false;
var blockedChecked = false;
var loginInProgress = false;
var statusCheckInterval = null;
var currentHistoryData = [];

var STORAGE_KEY = 'app_data';

function storageSet(key, value) {
    try {
        var allData = storageGetAll(); allData[key] = value;
        localStorage.setItem(STORAGE_KEY, JSON.stringify(allData));
    } catch (e) {}
}
function storageGet(key) {
    var allData = storageGetAll();
    return allData[key] !== undefined ? allData[key] : null;
}
function storageRemove(key) {
    var allData = storageGetAll(); delete allData[key];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(allData));
}
function storageGetAll() {
    try {
        var raw = localStorage.getItem(STORAGE_KEY);
        return raw ? (JSON.parse(raw) || {}) : {};
    } catch (e) { return {}; }
}

function getBlockKey(username) {
    return 'blok_' + (username || 'global');
}

function getBlockData(username) {
    var data = storageGet(getBlockKey(username));
    if (data) {
        try {
            if (data.blockedUntil && Date.now() > data.blockedUntil) {
                storageRemove(getBlockKey(username));
                return { attempts: 0, blockedUntil: null, level: 0 };
            }
            return data;
        } catch (e) {
            return { attempts: 0, blockedUntil: null, level: 0 };
        }
    }
    return { attempts: 0, blockedUntil: null, level: 0 };
}

function saveBlockData(username, data) {
    storageSet(getBlockKey(username), data);
}

function sanitize(str) {
    if (!str) return '';
    return String(str).replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

function safeSetHTML(element, html) {
    if (!element) return;
    if (window.DOMPurify) {
        element.innerHTML = DOMPurify.sanitize(html, {
            ALLOWED_TAGS: ['div', 'span', 'p', 'h1', 'h2', 'h3', 'button', 'i', 'b', 'br'],
            ALLOWED_ATTR: ['class', 'style', 'onclick', 'id']
        });
    } else {
        element.textContent = html;
    }
}

async function getFingerprint() {
    var fp = '';
    fp += navigator.userAgent || '';
    fp += navigator.language || '';
    fp += (screen.width || 0) + 'x' + (screen.height || 0);
    fp += screen.colorDepth || '';
    fp += new Date().getTimezoneOffset();
    fp += navigator.hardwareConcurrency || '';
    fp += navigator.deviceMemory || '';
    fp += navigator.platform || '';
    const data = new TextEncoder().encode(fp);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function getBlockDuration(attempts) {
    if (attempts >= 15) return 1440;
    if (attempts >= 10) return 60;
    if (attempts >= 5) return 15;
    return 0;
}

async function getRecaptchaV3Token(action) {
    try {
        return await grecaptcha.execute(RECAPTCHA_V3_SITE_KEY, { action: action });
    } catch (e) {
        return null;
    }
}

async function checkIfBlocked() {
    if (blockedChecked) return isBlocked;
    if (!fingerprint) fingerprint = await getFingerprint();
    try {
        var captchaToken = await getRecaptchaV3Token('check_blocked');
        var payload = {
            path: 'check_blocked',
            method: 'POST',
            data: {
                fingerprint: fingerprint,
                captchaToken: captchaToken
            },
            timestamp: Date.now()
        };
        var requestBody = payload;
        var res = await fetch(API_REVANSTORE, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-Fingerprint': fingerprint
            },
            body: JSON.stringify(requestBody)
        });
        var result = await res.json();
        if (result && result.blocked) {
            isBlocked = true;
            storageSet('perangkat_diblokir', 'true');
        } else {
            isBlocked = false;
            storageRemove('perangkat_diblokir');
        }
        blockedChecked = true;
    } catch (e) {
        isBlocked = storageGet('perangkat_diblokir') === 'true';
        blockedChecked = true;
    }
    return isBlocked;
}

async function periksaMaintenance() {
    try {
        var payload = {
            path: 'maintenance_status',
            method: 'GET',
            data: null,
            timestamp: Date.now()
        };
        var requestBody = payload;
        var res = await fetch(API_REVANSTORE, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-Fingerprint': fingerprint || 'check'
            },
            body: JSON.stringify(requestBody)
        });
        var result = await res.json();
        if (result && (result.maintenance === true || result.title || result.message)) {
            return result;
        }
        return null;
    } catch (e) {
        return null;
    }
}

function tampilkanHalamanMaintenance(dataMaintenance) {
    var judul = sanitize((dataMaintenance && (dataMaintenance.title || dataMaintenance.judul)) ? (dataMaintenance.title || dataMaintenance.judul) : 'SEDANG PERBAIKAN SISTEM');
    var pesan = sanitize((dataMaintenance && (dataMaintenance.message || dataMaintenance.pesan)) ? (dataMaintenance.message || dataMaintenance.pesan) : 'Website sedang dalam perbaikan oleh admin. Silakan kembali beberapa saat lagi.');
    var sampai = (dataMaintenance && (dataMaintenance.until || dataMaintenance.sampai)) ? (dataMaintenance.until || dataMaintenance.sampai) : null;
    var teksEstimasi = sanitize(sampai ? 'Estimasi selesai: ' + new Date(sampai).toLocaleString('id-ID') : 'Mohon maaf atas ketidaknyamanan ini.');

    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;font-family:\'Segoe UI\',sans-serif;">' +
        '<div style="background:#ffffff;border-radius:24px;padding:48px 36px;width:100%;max-width:440px;text-align:center;box-shadow:0 25px 60px rgba(0,0,0,0.08);border:1px solid #e2e8f0;">' +
        '<div style="width:90px;height:90px;background:#fef3c7;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;">' +
        '<i class="fas fa-tools" style="font-size:40px;color:#f59e0b;"></i>' +
        '</div>' +
        '<h1 style="color:#0c4a6e;font-size:24px;font-weight:700;margin-bottom:8px;">' + judul + '</h1>' +
        '<p style="color:#64748b;font-size:14px;margin-bottom:6px;line-height:1.6;">' + pesan + '</p>' +
        '<div style="background:#fef3c7;color:#92400e;padding:12px 16px;border-radius:12px;font-weight:600;font-size:13px;margin:16px 0 24px;">' + teksEstimasi + '</div>' +
        '</div></div>';
}
async function callRevanstore(path, method, data) {
    if (!fingerprint) fingerprint = await getFingerprint();
    if (isBlocked && path !== 'check_blocked') throw new Error('Akses ditolak');
    var captchaToken = await getRecaptchaV3Token(path);
    var payload = {
        path: path,
        method: method || 'GET',
        data: data || null,
        captchaToken: captchaToken,
        timestamp: Date.now()
    };
    var requestBody = payload;
    var headers = {
        'Content-Type': 'application/json',
        'X-Fingerprint': fingerprint
    };
    var res = await fetch(API_REVANSTORE, {
        method: 'POST',
        credentials: 'same-origin',
        headers: headers,
        body: JSON.stringify(requestBody)
    });
    if (res.status === 429) throw new Error('Terlalu banyak permintaan');
    var text = await res.text();
    if (!text || text === 'null') return null;
    var result = JSON.parse(text);
    return result;
}

async function callRvnstore(endpoint, method, body, authToken) {
    var res = await fetch(API_TOPUPBUSSID, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            endpoint: endpoint,
            method: method || 'POST',
            body: body || null,
            authToken: authToken || null
        })
    });
    return await res.json();
}

function showAlert(message, type, duration) {
    type = type || 'info';
    duration = duration || 2500;
    var alertDiv = document.getElementById('alert');
    if (alertDiv) {
        var icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle',
            loading: 'fa-spinner fa-spin'
        };
        var html = '<div class="alert-content"><div class="alert-icon"><i class="fas ' + (icons[type] || 'fa-info-circle') + '"></i></div><span>' + sanitize(message) + '</span></div>';
        safeSetHTML(alertDiv, html);
        alertDiv.className = 'alert ' + type + ' show';
        if (alertTimeout) clearTimeout(alertTimeout);
        if (type !== 'loading') {
            alertTimeout = setTimeout(function() {
                alertDiv.classList.remove('show');
            }, duration);
        }
    }
}

function showLoading(message) {
    var overlay = document.getElementById('loadingOverlay');
    var msg = document.getElementById('loadingMessage');
    if (overlay && msg) {
        msg.textContent = message || 'Memproses...';
        overlay.style.display = 'flex';
    }
}

function hideLoading() {
    var overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.style.display = 'none';
}

function formatCurrency(amount) {
    if (!amount && amount !== 0) return 'Rp 0';
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
    }).format(amount);
}

function parseAmount(input) {
    if (!input || input.trim() === '') return 0;
    var cleaned = input.toUpperCase().replace(/\s/g, '');
    if (cleaned === '2M' || cleaned === '2 M') return MAX_TOPUP_AMOUNT;
    var multiplier = 1;
    var cleanInput = cleaned;
    if (cleaned.includes('M') && !cleaned.includes('JT') && !cleaned.includes('MAX')) {
        multiplier = 1000000000;
        cleanInput = cleaned.replace('M', '');
    } else if (cleaned.includes('JT')) {
        multiplier = 1000000;
        cleanInput = cleaned.replace('JT', '');
    } else if (cleaned.includes('RB') || cleaned.includes('K')) {
        multiplier = 1000;
        cleanInput = cleaned.replace(/[KRB]/g, '');
    } else if (cleaned.includes('MAX')) {
        return MAX_TOPUP_AMOUNT;
    }
    var number = parseFloat(cleanInput.replace(/\./g, '').replace(',', '.'));
    var result = isNaN(number) ? 0 : Math.round(number * multiplier);
    return Math.min(result, MAX_TOPUP_AMOUNT);
}

function validateTopupAmount() {
    var input = document.getElementById('topupAmount');
    var preview = document.getElementById('amountPreview');
    var previewValue = document.getElementById('amountPreviewValue');
    if (!input) return;
    var amount = parseAmount(input.value);
    if (amount > 0 && input.value.trim() !== '') {
        if (preview) preview.style.display = 'block';
        if (previewValue) previewValue.textContent = formatCurrency(amount);
    } else {
        if (preview) preview.style.display = 'none';
    }
}

function hideAllSections() {
    var sections = ['accountInfo', 'topupSection', 'kurasSection', 'changeNameSection', 'historySection', 'settingsSection', 'receiptSection'];
    sections.forEach(function(section) {
        var el = document.getElementById(section);
        if (el) el.style.display = 'none';
    });
    var searchCard = document.querySelector('.search-card');
    if (searchCard) searchCard.style.display = 'none';
}

function showHome() {
    hideAllSections();
    var sc = document.querySelector('.search-card');
    if (sc) sc.style.display = 'block';
}

function backToAccount() {
    if (currentAccount) {
        hideAllSections();
        var ai = document.getElementById('accountInfo');
        if (ai) {
            ai.style.display = 'block';
            showAccountInfo(currentAccount);
        }
    } else {
        showHome();
    }
}

function parseDate(dateStr) {
    if (!dateStr) return null;
    if (String(dateStr).includes('9999')) return null;
    var parts = String(dateStr).split('/');
    if (parts.length !== 3) {
        if (String(dateStr).includes('-')) {
            parts = String(dateStr).split('-');
            if (parts.length !== 3) return null;
        } else {
            return null;
        }
    }
    var day, month, year;
    if (parts[0].length === 4) {
        year = parseInt(parts[0], 10);
        month = parseInt(parts[1], 10) - 1;
        day = parseInt(parts[2], 10);
    } else {
        month = parseInt(parts[0], 10) - 1;
        day = parseInt(parts[1], 10);
        year = parseInt(parts[2], 10);
    }
    if (isNaN(day) || isNaN(month) || isNaN(year)) return null;
    if (month < 0 || month > 11 || day < 1 || day > 31 || year < 2000) return null;
    var date = new Date(year, month, day);
    if (date.getMonth() !== month || date.getDate() !== day) return null;
    return date;
}

function calculateRemainingDays(expiryDate) {
    if (!expiryDate) return 999999;
    if (String(expiryDate).includes('9999')) return 999999;
    var expiry = parseDate(expiryDate);
    if (!expiry) return 999999;
    var now = new Date();
    now.setHours(0, 0, 0, 0);
    var diff = expiry.getTime() - now.getTime();
    if (diff < 0) {
        if (diff > -86400000) return 0;
        return Math.ceil(diff / (1000 * 60 * 60 * 24));
    }
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

function getDaysLeftClass(daysLeft) {
    if (daysLeft === 999999) return 'days-permanent';
    if (daysLeft < 0) return 'days-red';
    if (daysLeft === 0) return 'days-yellow';
    if (daysLeft <= 3) return 'days-yellow';
    return 'days-green';
}

function getDaysLeftText(daysLeft) {
    if (daysLeft === 999999) return 'Permanen';
    if (daysLeft < 0) return 'Habis ' + Math.abs(daysLeft) + ' hari';
    if (daysLeft === 0) return 'Hari ini';
    if (daysLeft === 1) return '1 hari';
    return daysLeft + ' hari';
}

function checkAccountExpiry(user) {
    if (!user || !user.expiry_date) {
        return { expired: false, daysLeft: 999999, daysLeftText: 'Permanen', daysLeftClass: 'days-permanent' };
    }
    if (String(user.expiry_date).includes('9999')) {
        return { expired: false, daysLeft: 999999, daysLeftText: 'Permanen', daysLeftClass: 'days-permanent' };
    }
    var daysLeft = calculateRemainingDays(user.expiry_date);
    if (daysLeft === 999999) {
        return { expired: false, daysLeft: 999999, daysLeftText: 'Permanen', daysLeftClass: 'days-permanent' };
    }
    var expired = daysLeft < 0;
    return {
        expired: expired,
        daysLeft: daysLeft,
        daysLeftText: getDaysLeftText(daysLeft),
        daysLeftClass: getDaysLeftClass(daysLeft)
    };
}

function showExpiredBanner() {
    var eb = document.getElementById('expiredBanner');
    if (eb) eb.style.display = 'flex';
    var ma = document.getElementById('mainApp');
    if (ma) ma.style.display = 'none';
}

function closeExpiredBanner() {
    var eb = document.getElementById('expiredBanner');
    if (eb) eb.style.display = 'none';
    logout();
}

function openWhatsApp() {
    var msg = encodeURIComponent("Assalamualaikum admin, saya ingin memperpanjang masa aktif akun. Username: " + (currentUser ? currentUser.username : ''));
    window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=' + msg, '_blank');
}

function openWhatsAppPassword() {
    var msg = encodeURIComponent("Assalamualaikum admin, saya ingin mengubah password akun. Username: " + (currentUser ? currentUser.username : ''));
    window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=' + msg, '_blank');
}

function showBlockedScreen() {
    var html = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#f0f9ff,#bae6fd,#7dd3fc);padding:20px;font-family:\'Segoe UI\',sans-serif;"><div style="background:#fff;border-radius:20px;padding:40px 30px;max-width:420px;width:100%;text-align:center;box-shadow:0 25px 60px rgba(0,0,0,0.1);"><div style="font-size:70px;color:#ef4444;margin-bottom:20px;">🔒</div><h1 style="color:#0c4a6e;font-size:24px;margin-bottom:10px;">AKSES DITOLAK</h1><p style="color:#64748b;font-size:14px;">Maaf, akses Anda telah ditolak.</p></div></div>';
    safeSetHTML(document.body, html);
}

function showBannedPopup(until) {
    var untilText = (until || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(until).toLocaleString('id-ID'));
    Swal.fire({
        icon: 'error',
        title: 'AKUN DIBANNED',
        html: '<p>Maaf, akun Anda telah dibanned oleh admin.</p><p style="color:#dc2626;background:#fee2e2;padding:8px;border-radius:8px;"><b>Durasi: ' + sanitize(untilText) + '</b></p>',
        confirmButtonText: '<i class="fab fa-whatsapp"></i> Hubungi Admin',
        confirmButtonColor: '#25D366',
        showCancelButton: true,
        cancelButtonText: 'Tutup',
        cancelButtonColor: '#64748b',
        allowOutsideClick: false
    }).then(function(r) {
        if (r.isConfirmed) window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20akun%20saya%20dibanned', '_blank');
    });
}

function showBanAccessPage(until) {
    var untilText = (until || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(until).toLocaleString('id-ID'));
    var html = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#f0f9ff 0%,#bae6fd 50%,#7dd3fc 100%);padding:20px;font-family:\'Segoe UI\',sans-serif;">' +
        '<div style="background:#ffffff;border-radius:24px;padding:48px 36px;width:100%;max-width:420px;text-align:center;box-shadow:0 20px 60px rgba(0,191,255,0.15);border:1px solid rgba(0,191,255,0.1);">' +
        '<div style="font-size:72px;color:#f59e0b;margin-bottom:12px;">🚫</div>' +
        '<h2 style="font-size:24px;font-weight:700;color:#0c4a6e;margin-bottom:8px;">AKSES DIBLOKIR</h2>' +
        '<p style="font-size:14px;color:#64748b;margin-bottom:6px;">Maaf, akses Anda diblokir oleh admin.</p>' +
        '<div style="background:#fef3c7;color:#92400e;padding:12px 16px;border-radius:12px;font-weight:600;font-size:14px;margin:16px 0 24px;">Durasi: ' + sanitize(untilText) + '</div>' +
        '<button onclick="window.open(\'https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20akses%20saya%20diblokir\',\'_blank\')" style="display:inline-flex;align-items:center;gap:10px;padding:12px 32px;background:#25D366;color:#fff;border:none;border-radius:30px;font-weight:600;font-size:15px;cursor:pointer;transition:0.2s;font-family:\'Segoe UI\',sans-serif;">' +
        '<i class="fab fa-whatsapp"></i> Hubungi Admin</button></div></div>';
    safeSetHTML(document.body, html);
}

function showSuspendedPopup() {
    Swal.fire({
        icon: 'warning',
        title: 'AKUN DITANGGUHKAN',
        html: '<p>Akun Anda ditangguhkan karena indikasi aktivitas mencurigakan.</p><p style="font-size:12px;color:#92400e;">Silakan hubungi admin.</p>',
        confirmButtonText: '<i class="fab fa-whatsapp"></i> Hubungi Admin',
        confirmButtonColor: '#25D366',
        showCancelButton: true,
        cancelButtonText: 'Tutup',
        cancelButtonColor: '#64748b',
        allowOutsideClick: false
    }).then(function(r) {
        if (r.isConfirmed) window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20akun%20saya%20ditangguhkan', '_blank');
    });
}

function checkAuth() {
    var saved = storageGet('sesi_pengguna');
    if (!saved) {
        window.location.href = '/';
        return false;
    }
    try {
        var session = JSON.parse(saved);
        var age = Date.now() - (session.timestamp || 0);
        if (age > 7 * 24 * 60 * 60 * 1000) {
            storageRemove('sesi_pengguna');
            window.location.href = '/pages/login';
            return false;
        }
        currentUser = {
            id: session.user_id,
            username: session.username,
            token: session.token || null,
            role: session.role || 'Operator',
            full_name: session.full_name || session.username,
            expiry_date: session.expiry_date || ''
        };
        return true;
    } catch (e) {
        storageRemove('sesi_pengguna');
        window.location.href = '/pages/login';
        return false;
    }
}

async function checkAccountStatus() {
    if (!currentUser) return;
    try {
        var captchaToken = await getRecaptchaV3Token('check_status');
        var payload = {
            path: 'check_account_status',
            method: 'POST',
            data: {
                username: currentUser.username,
                user_id: currentUser.id,
                fingerprint: fingerprint,
                captchaToken: captchaToken
            },
            timestamp: Date.now()
        };
        var requestBody = payload;
        var res = await fetch(API_REVANSTORE, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-Fingerprint': fingerprint
            },
            body: JSON.stringify(requestBody)
        });
        var result = await res.json();
        if (result && result.banned) {
            var untilText = (result.bannedUntil || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(result.bannedUntil).toLocaleString('id-ID'));
            Swal.fire({
                icon: 'error',
                title: 'AKUN DIBANNED',
                html: 'Maaf, akun Anda telah dibanned oleh admin.<br><br>Durasi: ' + sanitize(untilText),
                confirmButtonText: 'OK',
                confirmButtonColor: '#ef4444',
                allowOutsideClick: false
            }).then(function() {
                autoLogout();
            });
            return;
        }
        if (result && result.banAkses) {
            var untilTextA = (result.banAksesUntil || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(result.banAksesUntil).toLocaleString('id-ID'));
            Swal.fire({
                icon: 'error',
                title: 'AKSES DIBLOKIR',
                html: 'Maaf, akses Anda diblokir oleh admin.<br><br>Durasi: ' + sanitize(untilTextA),
                confirmButtonText: 'OK',
                confirmButtonColor: '#ef4444',
                allowOutsideClick: false
            }).then(function() {
                autoLogout();
            });
            return;
        }
        if (result && result.forceLogout) {
            Swal.fire({
                icon: 'warning',
                title: 'AKUN DITANGGUHKAN',
                html: 'Akun Anda ditangguhkan karena indikasi aktivitas mencurigakan.<br><br>Silakan hubungi admin.',
                confirmButtonText: 'OK',
                confirmButtonColor: '#ef4444',
                allowOutsideClick: false
            }).then(function() {
                autoLogout();
            });
            return;
        }
        if (result && result.valid && result.user) {
            currentUser.role = result.user.role || currentUser.role;
            currentUser.full_name = result.user.full_name || currentUser.full_name;
            currentUser.expiry_date = result.user.expiry_date || currentUser.expiry_date;
        }
    } catch (e) {}
}

async function autoLogout() {
    try { await fetch(API_REVANSTORE, { method: 'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({path:'logout', method:'POST'}) }); } catch (e) {}
    storageRemove('sesi_pengguna');
    if (statusCheckInterval) clearInterval(statusCheckInterval);
    window.location.href = '/pages/login';
}

function logout() {
    currentUser = null;
    currentAccount = null;
    currentAuthToken = null;
    lastDeviceId = null;
    storageRemove('sesi_pengguna');
    if (statusCheckInterval) clearInterval(statusCheckInterval);
    window.location.href = '/pages/login';
}

function updateProfileInfo() {
    if (!currentUser) return;
    var elUsername = document.getElementById('profileUsername');
    var elName = document.getElementById('profileName');
    var elRole = document.getElementById('profileRole');
    var elExpiry = document.getElementById('profileExpiry');
    if (elUsername) elUsername.textContent = currentUser.username;
    if (elName) elName.textContent = currentUser.full_name || currentUser.username;
    if (elRole) elRole.textContent = currentUser.role || 'Operator';
    if (elExpiry) {
        var expiryCheck = checkAccountExpiry(currentUser);
        var expiryFormatted = currentUser.expiry_date || 'Tidak ada';
        var html = '<span>' + sanitize(expiryFormatted) + '</span> <span class="expiry-days-left ' + expiryCheck.daysLeftClass + '">' + sanitize(expiryCheck.daysLeftText) + '</span>';
        safeSetHTML(elExpiry, html);
    }
}

function navigateBottom(page) {
    document.querySelectorAll('.bottom-nav a').forEach(function(a) {
        a.classList.remove('active');
    });
    if (event && event.target) event.target.classList.add('active');
    if (page === 'home') showHome();
    else if (page === 'riwayat') showHistory();
    else if (page === 'pengaturan') showSettings();
}

async function loginWithDeviceId(deviceId) {
    var blocked = await checkIfBlocked();
    if (blocked) {
        showBlockedScreen();
        return false;
    }
    showLoading('Menghubungkan...');
    try {
        var cleanInput = sanitize(deviceId.trim());
        if (cleanInput.includes('.')) {
            currentAuthToken = cleanInput;
        } else {
            var cid = cleanInput.toLowerCase().replace(/^android-/, '');
            var data = await callRvnstore('/Client/LoginWithAndroidDeviceID', 'POST', {
                TitleId: "4AE9",
                AndroidDeviceId: cid,
                CreateAccount: true,
                InfoRequestParameters: {
                    GetUserAccountInfo: true,
                    GetUserVirtualCurrency: true,
                    GetPlayerProfile: true
                }
            }, null);
            if (data.data && data.data.SessionTicket) {
                currentAuthToken = data.data.SessionTicket;
            } else {
                hideLoading();
                throw new Error('Device ID tidak valid!');
            }
        }
        var info = await getUserInfoFromPlayFab();
        if (info) {
            currentAccount = {
                deviceId: cleanInput,
                name: info.name,
                balance: info.balance,
                facebook: info.facebook,
                facebookAvatarUrl: info.facebookAvatarUrl,
                playFabId: info.playFabId
            };
            hideLoading();
            return true;
        }
        hideLoading();
        throw new Error('Gagal!');
    } catch (error) {
        hideLoading();
        showAlert(error.message, 'error');
        return false;
    }
}

async function getUserInfoFromPlayFab() {
    if (!currentAuthToken) return null;
    try {
        var result = await callRvnstore('/Client/GetPlayerCombinedInfo', 'POST', {
            InfoRequestParameters: {
                GetUserAccountInfo: true,
                GetUserVirtualCurrency: true,
                GetPlayerProfile: true
            }
        }, currentAuthToken);
        if (result.data) {
            var info = result.data.InfoResultPayload;
            var acc = info.AccountInfo;
            var name = (acc && acc.TitleInfo) ? (acc.TitleInfo.DisplayName || 'Unknown') : 'Unknown';
            var balance = info.UserVirtualCurrency ? info.UserVirtualCurrency.RP : 0;
            var pfid = acc ? (acc.PlayFabId || '-') : '-';
            var fb = {
                id: null,
                name: 'Tidak tertaut',
                email: null,
                isConnected: false
            };
            var fbAvatar = null;
            if (acc && acc.FacebookInfo) {
                fb = {
                    id: acc.FacebookInfo.FacebookId || null,
                    name: acc.FacebookInfo.FullName || 'Tidak tertaut',
                    email: acc.FacebookInfo.Email || null,
                    isConnected: true                };
                if (fb.id) fbAvatar = 'https://graph.facebook.com/' + fb.id + '/picture?type=large';
            }
            return {
                name: name,
                balance: balance,
                facebook: fb,
                facebookAvatarUrl: fbAvatar,
                playFabId: pfid
            };
        }
    } catch (e) {}
    return null;
}

async function searchAccount() {
    var id = document.getElementById('deviceId').value.trim();
    if (!id) {
        showAlert('Masukkan Device ID!', 'error');
        return;
    }
    var ok = await loginWithDeviceId(id);
    if (ok) {
        lastDeviceId = id;
        showAccountInfo(currentAccount);
        hideAllSections();
        var ai = document.getElementById('accountInfo');
        if (ai) ai.style.display = 'block';
        showAlert('Akun ditemukan!', 'success');
    }
}

function tampilkanFotoProfile(acc) {
    var c = document.getElementById('profilePhoto');
    if (!c) return;
    c.innerHTML = '';
    var url = acc && acc.facebookAvatarUrl ? acc.facebookAvatarUrl : null;
    if (url && url !== 'null' && url !== '') {
        var img = document.createElement('img');
        img.src = url;
        img.style.width = '100%';
        img.style.height = '100%';
        img.style.objectFit = 'cover';
        img.style.borderRadius = '50%';
        img.onload = function() {
            c.appendChild(img);
        };
        img.onerror = function() {
            c.innerHTML = '<i class="fas fa-user"></i>';
        };
    } else {
        c.innerHTML = '<i class="fas fa-user"></i>';
    }
}

function tampilkanInfoFacebook(fb) {
    var d = document.getElementById('facebookDetails');
    if (!d) return;
    if (fb && fb.isConnected && fb.id) {
        var html = '<div class="fb-info-row"><span class="fb-info-label"><i class="fab fa-facebook"></i> Status:</span><span class="fb-info-value" style="color:#1877F2;">✅ TERHUBUNG</span></div>' +
            '<div class="fb-info-row"><span class="fb-info-label">Facebook ID:</span><span class="fb-info-value" style="font-family:monospace;font-size:12px;">' + sanitize(fb.id) + '</span></div>' +
            '<div class="fb-info-row"><span class="fb-info-label">Nama:</span><span class="fb-info-value">' + sanitize(fb.name || '-') + '</span></div>' +
            '<div class="fb-info-row"><span class="fb-info-label">Email:</span><span class="fb-info-value">' + sanitize(fb.email || '-') + '</span></div>';
        safeSetHTML(d, html);
    } else {
        var html2 = '<div class="fb-info-row"><span class="fb-info-label"><i class="fab fa-facebook"></i> Status:</span><span class="fb-info-value" style="color:#ffaa00;">⚠️ TIDAK TERHUBUNG</span></div>';
        safeSetHTML(d, html2);
    }
}

function showAccountInfo(acc) {
    document.getElementById('accountName').textContent = sanitize(acc.name || '-');
    document.getElementById('accountBalance').textContent = formatCurrency(acc.balance);
    document.getElementById('playfabId').textContent = acc.playFabId || '-';
    tampilkanFotoProfile(acc);
    tampilkanInfoFacebook(acc.facebook);
}

function refreshAccountInfo() {
    if (!currentAccount) {
        showAlert('Cari akun dulu!', 'error');
        return;
    }
    showLoading('Menyegarkan...');
    setTimeout(async function() {
        var info = await getUserInfoFromPlayFab();
        if (info) {
            currentAccount.balance = info.balance;
            currentAccount.name = info.name;
            currentAccount.facebook = info.facebook;
            currentAccount.facebookAvatarUrl = info.facebookAvatarUrl;
            currentAccount.playFabId = info.playFabId;
            showAccountInfo(currentAccount);
            hideLoading();
            showAlert('Diperbarui!', 'success');
        } else {
            hideLoading();
        }
    }, 1000);
}

function setAmount(a) {
    var el = document.getElementById('topupAmount');
    if (el) {
        el.value = a;
        validateTopupAmount();
    }
}

function setupQuickAmounts() {
    var q = document.querySelector('.quick-amounts');
    if (q) {
        var html = '<button class="btn-quick" onclick="setAmount(\'2M\')">2M</button>' +
            '<button class="btn-quick" onclick="setAmount(\'1M\')">1M</button>' +
            '<button class="btn-quick" onclick="setAmount(\'500JT\')">500JT</button>' +
            '<button class="btn-quick" onclick="setAmount(\'100JT\')">100JT</button>' +
            '<button class="btn-quick" onclick="setAmount(\'50JT\')">50JT</button>';
        safeSetHTML(q, html);
    }
}

function showTopupFromAccount() {
    if (!currentAccount) return;
    document.getElementById('topupAccountName').textContent = currentAccount.name;
    document.getElementById('topupCurrentBalance').textContent = formatCurrency(currentAccount.balance);
    hideAllSections();
    document.getElementById('topupSection').style.display = 'block';
}

function showKurasFromAccount() {
    if (!currentAccount) return;
    document.getElementById('kurasAccountName').textContent = currentAccount.name;
    document.getElementById('kurasCurrentBalance').textContent = formatCurrency(currentAccount.balance);
    hideAllSections();
    document.getElementById('kurasSection').style.display = 'block';
}

function showChangeNameSection() {
    if (!currentAccount) return;
    document.getElementById('changeNameAccountLabel').textContent = currentAccount.name;
    hideAllSections();
    document.getElementById('changeNameSection').style.display = 'block';
}

async function processTopup() {
    if (!currentAccount) return;
    var el = document.getElementById('topupAmount');
    if (!el) return;
    var amt = parseAmount(el.value.trim());
    if (amt <= 0) {
        showAlert('Jumlah tidak valid!', 'error');
        return;
    }
    showConfirm('TOP UP', 'Top up ' + formatCurrency(amt) + '?', 'topup', { amount: amt });
}

async function processKuras() {
    if (!currentAccount) return;
    var el = document.getElementById('kurasAmount');
    var amt = el ? parseAmount(el.value.trim()) || currentAccount.balance : currentAccount.balance;
    if (amt <= 0 || amt > currentAccount.balance) {
        showAlert('Saldo tidak cukup!', 'error');
        return;
    }
    showConfirm('KURAS', 'Kuras ' + formatCurrency(amt) + '?', 'kuras', { amount: amt });
}

async function addCashToAccount(amt) {
    if (!currentAuthToken) return false;
    try {
        var res = await callRvnstore('/Client/ExecuteCloudScript', 'POST', {
            FunctionName: "AddRp",
            FunctionParameter: { addValue: amt },
            RevisionSelection: "Live",
            GeneratePlayStreamEvent: true
        }, currentAuthToken);
        if (res.data) {
            await new Promise(function(r) { setTimeout(r, 2000); });
            var info = await getUserInfoFromPlayFab();
            if (info) {
                currentAccount.balance = info.balance;
                currentAccount.facebook = info.facebook;
                currentAccount.facebookAvatarUrl = info.facebookAvatarUrl;
                currentAccount.playFabId = info.playFabId;
                showAccountInfo(currentAccount);
                return true;
            }
        }
        return false;
    } catch (e) {
        return false;
    }
}

async function executeTopup(amt) {
    showLoading('Memproses...');
    var old = currentAccount.balance;
    var ok = await addCashToAccount(amt);
    if (ok) {
        var trx = {
            type: 'topup',
            deviceId: currentAccount.deviceId,
            accountName: currentAccount.name,
            amount: amt,
            oldBalance: old,
            newBalance: currentAccount.balance,
            operator: currentUser.username,
            timestamp: Date.now(),
            status: 'success'
        };
        var trxResult = await callRevanstore('transactions', 'POST', trx);
        hideLoading();
        if (trxResult && trxResult.success === false) {
            Swal.fire({
                icon: 'warning',
                title: 'Perhatian',
                text: trxResult.message || 'Transaksi gagal dicatat.',
                confirmButtonColor: '#f59e0b'
            });
            return;
        }
        if (trxResult && trxResult.trxId) trx.trxId = trxResult.trxId;
        showReceipt(trx);
        showAlert('Berhasil!', 'success');
    } else {
        hideLoading();
        showAlert('Gagal!', 'error');
    }
}

async function executeKuras(amt) {
    showLoading('Memproses...');
    var old = currentAccount.balance;
    var ok = await addCashToAccount(-amt);
    if (ok) {
        var trx = {
            type: 'kuras',
            deviceId: currentAccount.deviceId,
            accountName: currentAccount.name,
            amount: amt,
            oldBalance: old,
            newBalance: currentAccount.balance,
            operator: currentUser.username,
            timestamp: Date.now(),
            status: 'success'
        };
        var trxResult = await callRevanstore('transactions', 'POST', trx);
        hideLoading();
        if (trxResult && trxResult.success === false) {
            Swal.fire({
                icon: 'warning',
                title: 'Perhatian',
                text: trxResult.message || 'Transaksi gagal dicatat.',
                confirmButtonColor: '#f59e0b'
            });
            return;
        }
        if (trxResult && trxResult.trxId) trx.trxId = trxResult.trxId;
        showReceipt(trx);
        showAlert('Berhasil!', 'success');
    } else {
        hideLoading();
        showAlert('Gagal!', 'error');
    }
}

function showReceipt(trx) {
    hideAllSections();
    var typeText = trx.type === 'topup' ? 'TOP UP' : 'KURAS';
    var sign = trx.type === 'topup' ? '+' : '-';
    var idRow = trx.trxId ? '<div class="receipt-row"><span>ID Transaksi:</span><span style="font-family:monospace;">' + sanitize(trx.trxId) + '</span></div>' : '';
    var html = '<div class="receipt-content"><div class="receipt-header"><h3>TOP UP</h3><p>Detail Transaksi</p></div><div class="receipt-details">' + idRow + '<div class="receipt-row"><span>Akun:</span><span>' + sanitize(trx.accountName) + '</span></div><div class="receipt-row"><span>Jenis:</span><span>' + sanitize(typeText) + '</span></div><div class="receipt-row"><span>Jumlah:</span><span style="color:' + (trx.type === 'topup' ? '#10b981' : '#f59e0b') + '">' + sign + formatCurrency(trx.amount) + '</span></div><div class="receipt-row"><span>Saldo Awal:</span><span>' + formatCurrency(trx.oldBalance) + '</span></div><div class="receipt-row"><span>Saldo Akhir:</span><span>' + formatCurrency(trx.newBalance) + '</span></div><div class="receipt-row"><span>Tanggal:</span><span>' + new Date(trx.timestamp).toLocaleString('id-ID') + '</span></div><div class="receipt-row"><span>Status:</span><span style="color:#10b981;">BERHASIL</span></div></div></div><div style="display:flex;gap:8px;margin-top:20px;"><button class="btn btn-primary" onclick="window._showTrxModal()" style="flex:1;">LANJUTKAN</button><button class="btn btn-secondary" onclick="window._goHome()" style="flex:1;">HOME</button></div>';
    var receiptContent = document.getElementById('receiptContent');
    safeSetHTML(receiptContent, html);
    document.getElementById('receiptSection').style.display = 'block';
}

window._showTrxModal = function() {
    var modal = document.getElementById('trxLagiModal');
    if (modal) {
        modal.style.display = 'flex';
        modal.style.opacity = '1';
        modal.style.visibility = 'visible';
    }
};
window._tutupTrxModal = function() {
    var modal = document.getElementById('trxLagiModal');
    if (modal) modal.style.display = 'none';
};
window._pilihTopup = function() {
    window._tutupTrxModal();
    showTopupFromAccount();
};
window._pilihKuras = function() {
    window._tutupTrxModal();
    showKurasFromAccount();
};
window._goHome = function() {
    showHome();
};

function backToHome() {
    showHome();
}

async function showHistory() {
    hideAllSections();
    document.getElementById('historySection').style.display = 'block';
    showLoading('Mengambil data...');
    try {
        var data = await callRevanstore('transactions', 'GET', { username: currentUser.username });
        var list = document.getElementById('transactionsList');
        if (!data || typeof data !== 'object' || Object.keys(data).length === 0) {
            currentHistoryData = [];
            if (list) {
                var emptyHtml = '<p style="text-align:center;color:#666;padding:40px 20px;">Belum ada transaksi</p>';
                safeSetHTML(list, emptyHtml);
            }
            hideLoading();
            return;
        }
        var arr = Object.keys(data).map(function(k) {
            return {
                id: k,
                trxId: data[k].trxId || '-',
                type: data[k].type,
                accountName: data[k].accountName,
                amount: data[k].amount,
                oldBalance: data[k].oldBalance,
                newBalance: data[k].newBalance,
                oldName: data[k].oldName,
                newName: data[k].newName,
                operator: data[k].operator,
                timestamp: data[k].timestamp
            };
        }).sort(function(a, b) {
            return b.timestamp - a.timestamp;
        });
        currentHistoryData = arr;
        var html = '';
        arr.forEach(function(t, idx) {
            var typeText = t.type === 'topup' ? 'TOP UP' : t.type === 'kuras' ? 'KURAS' : 'GANTI NAMA';
            var sign = t.type === 'topup' ? '+' : t.type === 'kuras' ? '-' : '';
            html += '<div class="transaction-item ' + sanitize(t.type) + '" onclick="showTransactionDetail(' + idx + ')" style="cursor:pointer;"><div class="transaction-header"><div>' + sanitize(t.accountName) + '</div><div class="transaction-amount">' + sign + formatCurrency(t.amount) + '</div></div><div class="transaction-details"><div>' + sanitize(typeText) + ' · ' + sanitize(t.trxId) + '</div><div>' + new Date(t.timestamp).toLocaleString('id-ID') + '</div></div><div class="transaction-balance"><span>Sebelum: ' + formatCurrency(t.oldBalance) + '</span><span>→</span><span>Sesudah: ' + formatCurrency(t.newBalance) + '</span></div></div>';
        });
        if (list) safeSetHTML(list, html);
        hideLoading();
    } catch (e) {
        hideLoading();
        showAlert('Gagal!', 'error');
    }
}

function showTransactionDetail(idx) {
    var t = currentHistoryData[idx];
    if (!t) return;
    var typeText = t.type === 'topup' ? 'TOP UP' : t.type === 'kuras' ? 'KURAS' : 'GANTI NAMA';
    var html;
    if (t.type === 'gantinama') {
        html = '<div style="text-align:left;font-size:14px;">' +
            '<p><b>ID Transaksi:</b> ' + sanitize(t.trxId) + '</p>' +
            '<p><b>Akun:</b> ' + sanitize(t.accountName) + '</p>' +
            '<p><b>Nama Lama:</b> ' + sanitize(t.oldName || '-') + '</p>' +
            '<p><b>Nama Baru:</b> ' + sanitize(t.newName || '-') + '</p>' +
            '<p><b>Operator:</b> ' + sanitize(t.operator) + '</p>' +
            '<p><b>Tanggal:</b> ' + new Date(t.timestamp).toLocaleString('id-ID') + '</p>' +
            '</div>';
    } else {
        var sign = t.type === 'topup' ? '+' : '-';
        html = '<div style="text-align:left;font-size:14px;">' +
            '<p><b>ID Transaksi:</b> ' + sanitize(t.trxId) + '</p>' +
            '<p><b>Akun:</b> ' + sanitize(t.accountName) + '</p>' +
            '<p><b>Jenis:</b> ' + sanitize(typeText) + '</p>' +
            '<p><b>Jumlah:</b> ' + sign + formatCurrency(t.amount) + '</p>' +
            '<p><b>Saldo Awal:</b> ' + formatCurrency(t.oldBalance) + '</p>' +
            '<p><b>Saldo Akhir:</b> ' + formatCurrency(t.newBalance) + '</p>' +
            '<p><b>Operator:</b> ' + sanitize(t.operator) + '</p>' +
            '<p><b>Tanggal:</b> ' + new Date(t.timestamp).toLocaleString('id-ID') + '</p>' +
            '</div>';
    }
    Swal.fire({
        title: 'Detail Transaksi',
        html: html,
        confirmButtonText: 'Tutup',
        confirmButtonColor: '#0ea5e9'
    });
}
window.showTransactionDetail = showTransactionDetail;

function showDeleteHistoryConfirm() {
    Swal.fire({
        title: '<i class="fas fa-trash"></i> HAPUS SEMUA RIWAYAT',
        text: "Yakin hapus semua riwayat?",
        icon: "warning",
        showCancelButton: true,
        confirmButtonColor: "#ef4444",
        cancelButtonColor: "#64748b",
        confirmButtonText: "HAPUS SEMUA",
        cancelButtonText: "BATAL"
    }).then((result) => {
        if (result.isConfirmed) deleteAllHistory();
    });
}

async function deleteAllHistory() {
    showLoading('Menghapus...');
    try {
        var result = await callRevanstore('transactions', 'DELETE', { username: currentUser.username });
        hideLoading();
        if (result && result.success) {
            Swal.fire({
                icon: "success",
                title: "Berhasil!",
                text: "Semua riwayat dihapus!",
                timer: 2000,
                showConfirmButton: false
            });
            if (document.getElementById('historySection').style.display === 'block') showHistory();
        } else {
            Swal.fire({
                icon: "info",
                title: "Info",
                text: "Tidak ada riwayat!",
                confirmButtonColor: "#0ea5e9"
            });
        }
    } catch (error) {
        hideLoading();
        Swal.fire({
            icon: "error",
            title: "Oops...",
            text: "Gagal menghapus!",
            confirmButtonColor: "#ef4444"
        });
    }
}

function showSettings() {
    hideAllSections();
    document.getElementById('settingsSection').style.display = 'block';
    updateProfileInfo();
}

function showConfirm(title, message, action, data) {
    var titleEl = document.getElementById('modalConfirmTitle');
    var messageEl = document.getElementById('modalConfirmMessage');
    safeSetHTML(titleEl, sanitize(title));
    safeSetHTML(messageEl, sanitize(message));
    pendingAction = action;
    pendingData = data;
    document.getElementById('confirmModal').classList.add('active');
}

function cancelConfirm() {
    pendingAction = null;
    pendingData = null;
    document.getElementById('confirmModal').classList.remove('active');
}

async function confirmAction() {
    if (!pendingAction || !pendingData) return;
    document.getElementById('confirmModal').classList.remove('active');
    if (pendingAction === 'topup') await executeTopup(pendingData.amount);
    else if (pendingAction === 'kuras') await executeKuras(pendingData.amount);
    else if (pendingAction === 'changename') await executeChangeName(pendingData);
    pendingAction = null;
    pendingData = null;
}

async function checkNameAvailability() {
    var d = document.getElementById('nameAvailability');
    d.innerHTML = 'Mengecek...';
    d.style.display = 'block';
    setTimeout(function() {
        d.innerHTML = '✅ Tersedia!';
    }, 1000);
}

async function changeAccountNameSimple() {
    var nameEl = document.getElementById('newAccountName');
    if (!nameEl) return;
    var name = sanitize(nameEl.value.trim());
    if (!name) {
        showAlert('Masukkan nama!', 'error');
        return;
    }
    if (!currentAccount || !currentAuthToken) {
        showAlert('Cari akun dulu!', 'error');
        return;
    }
    showConfirm('GANTI NAMA', 'Ganti ke "' + name + '"?', 'changename', name);
}

async function executeChangeName(newName) {
    showLoading('Mengubah...');
    try {
        var res = await callRvnstore('/Client/UpdateUserTitleDisplayName', 'POST', {
            DisplayName: newName
        }, currentAuthToken);
        if (res.data && res.data.DisplayName) {
            var old = currentAccount.name;
            currentAccount.name = newName;
            document.getElementById('accountName').textContent = newName;
            var trxResult = await callRevanstore('transactions', 'POST', {
                type: 'gantinama',
                accountName: currentAccount.name,
                oldName: old,
                newName: newName,
                operator: currentUser.username,
                timestamp: Date.now(),
                status: 'success'
            });
            hideLoading();
            if (trxResult && trxResult.success === false) {
                Swal.fire({
                    icon: 'warning',
                    title: 'Perhatian',
                    text: trxResult.message || 'Transaksi gagal dicatat.',
                    confirmButtonColor: '#f59e0b'
                });
                return;
            }
            var idRow = (trxResult && trxResult.trxId) ? '<div class="receipt-row"><span>ID Transaksi:</span><span style="font-family:monospace;">' + sanitize(trxResult.trxId) + '</span></div>' : '';
            hideAllSections();
            var html = '<div class="receipt-content"><div class="receipt-header"><h3>GANTI NAMA</h3></div><div class="receipt-details">' + idRow + '<div class="receipt-row"><span>Lama:</span><span>' + sanitize(old) + '</span></div><div class="receipt-row"><span>Baru:</span><span style="color:#0ea5e9;">' + sanitize(newName) + '</span></div></div></div><button class="btn btn-primary btn-block" onclick="window._goBackAccount()">KEMBALI</button>';
            var receiptContent = document.getElementById('receiptContent');
            safeSetHTML(receiptContent, html);
            document.getElementById('receiptSection').style.display = 'block';
            showAlert('Berhasil!', 'success');
        } else {
            hideLoading();
            showAlert('Gagal!', 'error');
        }
    } catch (e) {
        hideLoading();
        showAlert('Gagal!', 'error');
    }
}

window._goBackAccount = function() {
    backToAccount();
};

function showNameChangeModal(msg, type) {
    var m = document.getElementById('nameChangeModal');
    var msgEl = document.getElementById('nameChangeMessage');
    safeSetHTML(msgEl, sanitize(msg));
    m.classList.add('active');
}

function closeNameChangeModal() {
    document.getElementById('nameChangeModal').classList.remove('active');
}

function setupEventListeners() {
    var t = document.getElementById('topupAmount');
    if (t) t.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') processTopup();
    });
    var d = document.getElementById('deviceId');
    if (d) d.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') searchAccount();
    });
}

document.addEventListener('DOMContentLoaded', async function() {
    if (!checkAuth()) return;

    var maintenance = await periksaMaintenance();
    if (maintenance) { tampilkanHalamanMaintenance(maintenance); return; }

    setupEventListeners();
    setupQuickAmounts();
    document.addEventListener('contextmenu', function(e) { e.preventDefault(); });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I') || (e.ctrlKey && e.key === 'U')) {
            e.preventDefault();
            return false;
        }
    });
    if (!fingerprint) fingerprint = await getFingerprint();
    var blocked = await checkIfBlocked();
    if (blocked) {
        showBlockedScreen();
        return;
    }
    var mainApp = document.getElementById('mainApp');
    var bottomNav = document.getElementById('bottomNav');
    if (mainApp) mainApp.style.display = 'block';
    if (bottomNav) bottomNav.style.display = 'flex';
    var expiryCheck = checkAccountExpiry(currentUser);
    if (expiryCheck.expired) {
        showExpiredBanner();
        return;
    }
    showHome();
    if (typeof grecaptcha !== 'undefined') {
        grecaptcha.ready(async function() {
            await checkAccountStatus();
            statusCheckInterval = setInterval(checkAccountStatus, 30000);
        });
    } else {
        await checkAccountStatus();
        statusCheckInterval = setInterval(checkAccountStatus, 30000);
    }
    console.log('Dashboard siap. User:', currentUser.username);
});
