var API_WEBSITE = '/api/webtopupbussid';
var API_USER = '/api/user';
var API_AUTH = '/api/auth';
var API_RVNSTORE = '/api/rvnstore';
var WHATSAPP_NUMBER = "6285199120995";
var MAX_TOPUP_AMOUNT = 2147483647;
var RECAPTCHA_V3_SITE_KEY = '6LcVBn4tAAAAAINTTIleUbUZr1ZykvyB6WA-oOfT';

var currentUser = null;
var currentAccount = null;
var currentAuthToken = null;
var pendingAction = null;
var pendingData = null;
var fingerprint = '';
var alertTimeout = null;
var statusCheckInterval = null;
var currentHistoryData = [];

var STORAGE_KEY = 'app_data';

function storageSet(key, value) {
    try {
        var allData = storageGetAll();
        allData[key] = value;
        localStorage.setItem(STORAGE_KEY, JSON.stringify(allData));
    } catch (e) {}
}
function storageGet(key) {
    var allData = storageGetAll();
    return allData[key] !== undefined ? allData[key] : null;
}
function storageRemove(key) {
    var allData = storageGetAll();
    delete allData[key];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(allData));
}
function storageGetAll() {
    try {
        var raw = localStorage.getItem(STORAGE_KEY);
        return raw ? (JSON.parse(raw) || {}) : {};
    } catch (e) { return {}; }
}

async function getFingerprint() {
    var fp = '';
    fp += navigator.userAgent || '';
    fp += navigator.language || '';
    fp += navigator.platform || '';
    fp += (screen.availWidth || 0) + 'x' + (screen.availHeight || 0);
    fp += screen.colorDepth || '';
    try { fp += Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}
    fp += navigator.hardwareConcurrency || '';
    fp += navigator.maxTouchPoints || '0';
    fp += (window.devicePixelRatio || 1);
    try {
        var canvas = document.createElement('canvas');
        var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            var di = gl.getExtension('WEBGL_debug_renderer_info');
            if (di) {
                fp += gl.getParameter(di.UNMASKED_VENDOR_WEBGL) || '';
                fp += gl.getParameter(di.UNMASKED_RENDERER_WEBGL) || '';
            }
        }
    } catch (e) {}
    const data = new TextEncoder().encode(fp);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
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

function getCookie(name) {
    var v = document.cookie.split('; ').find(r => r.startsWith(name + '='));
    return v ? decodeURIComponent(v.split('=')[1]) : '';
}

async function apiGet(url) {
    if (!fingerprint) fingerprint = await getFingerprint();
    var res = await fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        headers: { 'X-Fingerprint': fingerprint },
        cache: 'no-store'
    });
    var text = await res.text();
    if (!text || text === 'null') return { status: res.status, data: null };
    try { return { status: res.status, data: JSON.parse(text) }; }
    catch { return { status: res.status, data: null }; }
}

async function apiPost(url, body) {
    if (!fingerprint) fingerprint = await getFingerprint();
    var headers = {
        'Content-Type': 'application/json',
        'X-Fingerprint': fingerprint
    };
    var csrf = getCookie('csrf_token');
    if (csrf) headers['X-CSRF-Token'] = csrf;

    var res = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: headers,
        body: JSON.stringify(body || {})
    });
    var text = await res.text();
    if (!text || text === 'null') return { status: res.status, data: null };
    try { return { status: res.status, data: JSON.parse(text) }; }
    catch { return { status: res.status, data: null }; }
}

async function getRecaptchaV3Token(action) {
    try {
        return await grecaptcha.execute(RECAPTCHA_V3_SITE_KEY, { action: action });
    } catch (e) {
        return null;
    }
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
            alertTimeout = setTimeout(function () {
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
    sections.forEach(function (section) {
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
    if (!user || !user.expiry_date) return { expired: false, daysLeft: 999999, daysLeftText: 'Permanen', daysLeftClass: 'days-permanent' };
    if (String(user.expiry_date).includes('9999')) return { expired: false, daysLeft: 999999, daysLeftText: 'Permanen', daysLeftClass: 'days-permanent' };
    var daysLeft = calculateRemainingDays(user.expiry_date);
    if (daysLeft === 999999) return { expired: false, daysLeft: 999999, daysLeftText: 'Permanen', daysLeftClass: 'days-permanent' };
    var expired = daysLeft < 0;
    return {
        expired: expired,
        daysLeft: daysLeft,
        daysLeftText: getDaysLeftText(daysLeft),
        daysLeftClass: getDaysLeftClass(daysLeft)
    };
}

function openWhatsApp() {
    var msg = encodeURIComponent("Assalamualaikum admin, saya ingin memperpanjang masa aktif akun. Username: " + (currentUser ? currentUser.username : ''));
    window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=' + msg, '_blank');
}

function showBlockedScreen() {
    var html = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#f0f9ff,#bae6fd,#7dd3fc);padding:20px;font-family:\'Segoe UI\',sans-serif;"><div style="background:#fff;border-radius:20px;padding:40px 30px;max-width:420px;width:100%;text-align:center;box-shadow:0 25px 60px rgba(0,0,0,0.1);"><div style="font-size:70px;color:#ef4444;margin-bottom:20px;">🔒</div><h1 style="color:#0c4a6e;font-size:24px;margin-bottom:10px;">AKSES DITOLAK</h1><p style="color:#64748b;font-size:14px;">Maaf, akses Anda telah ditolak.</p></div></div>';
    safeSetHTML(document.body, html);
}

async function forceLogout() {
    try {
        await apiPost(API_AUTH + '?action=logout', {});
    } catch (e) {}
    storageRemove('sesi_pengguna');
    if (statusCheckInterval) clearInterval(statusCheckInterval);
    window.location.href = '/';
}

function logout() {
    Swal.fire({
        icon: 'question',
        title: 'Logout?',
        text: 'Yakin ingin keluar?',
        showCancelButton: true,
        confirmButtonText: 'Ya, Logout',
        cancelButtonText: 'Batal',
        confirmButtonColor: '#ef4444',
        cancelButtonColor: '#64748b'
    }).then(function (r) {
        if (r.isConfirmed) forceLogout();
    });
}

async function checkAuthWithServer() {
    try {
        var res = await apiGet(API_USER + '?action=check-status');
        var data = res.data;

        if (res.status === 401) {
            redirectToLogin();
            return null;
        }

        if (data && data.banned) {
            showBannedAndLogout(data.bannedUntil || 0);
            return null;
        }

        if (data && data.banAkses) {
            showBanAksesAndLogout(data.banAksesUntil || 0, data.reason);
            return null;
        }

        if (data && data.forceLogout) {
            showSuspendedAndLogout();
            return null;
        }

        if (data && data.maintenance) {
            showMaintenancePage(data);
            return null;
        }

        if (data && data.expired) {
            showExpiredAndLogout();
            return null;
        }

        if (data && data.valid && data.user) {
            currentUser = {
                id: data.user.id,
                username: data.user.username,
                role: data.user.role || 'User',
                email: data.user.email || '',
                expiry_date: data.user.expiry_date || ''
            };
            return currentUser;
        }

        redirectToLogin();
        return null;
    } catch (e) {
        redirectToLogin();
        return null;
    }
}

function redirectToLogin() {
    try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
    if (statusCheckInterval) clearInterval(statusCheckInterval);
    window.location.href = '/';
}

function showBannedAndLogout(until) {
    var untilText = (until || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(until).toLocaleString('id-ID'));
    Swal.fire({
        icon: 'error',
        title: 'AKUN DIBANNED',
        html: '<p>Akun Anda telah dibanned oleh admin.</p><p style="color:#dc2626;background:#fee2e2;padding:8px;border-radius:8px;"><b>Durasi: ' + sanitize(untilText) + '</b></p>',
        confirmButtonText: '<i class="fab fa-whatsapp"></i> Hubungi Admin',
        confirmButtonColor: '#25D366',
        showCancelButton: true,
        cancelButtonText: 'Tutup',
        cancelButtonColor: '#64748b',
        allowOutsideClick: false
    }).then(function (r) {
        if (r.isConfirmed) window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20akun%20saya%20dibanned', '_blank');
        forceLogout();
    });
}

function showBanAksesAndLogout(until, reason) {
    var untilText = (until || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(until).toLocaleString('id-ID'));
    var reasonText = reason ? '<p style="color:#92400e;background:#fef3c7;padding:8px;border-radius:8px;"><b>Alasan:</b> ' + sanitize(reason) + '</p>' : '';
    Swal.fire({
        icon: 'error',
        title: 'AKSES DIBLOKIR',
        html: '<p>Akses Anda diblokir oleh admin.</p>' + reasonText + '<p style="color:#f59e0b;background:#fef3c7;padding:8px;border-radius:8px;"><b>Durasi: ' + sanitize(untilText) + '</b></p>',
        confirmButtonText: 'OK',
        confirmButtonColor: '#ef4444',
        allowOutsideClick: false
    }).then(function () { forceLogout(); });
}

function showSuspendedAndLogout() {
    Swal.fire({
        icon: 'warning',
        title: 'AKUN DITANGGUHKAN',
        text: 'Akun Anda ditangguhkan. Hubungi admin.',
        confirmButtonText: 'OK',
        confirmButtonColor: '#f59e0b',
        allowOutsideClick: false
    }).then(function () { forceLogout(); });
}

function showExpiredAndLogout() {
    Swal.fire({
        icon: 'warning',
        title: 'AKUN EXPIRED',
        text: 'Masa aktif akun Anda habis. Hubungi admin.',
        confirmButtonText: 'OK',
        confirmButtonColor: '#f59e0b',
        allowOutsideClick: false
    }).then(function () { forceLogout(); });
}

function showMaintenancePage(data) {
    var judul = sanitize(data.title || 'SEDANG PERBAIKAN SISTEM');
    var pesan = sanitize(data.message || 'Website sedang dalam perbaikan.');
    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#e0f2fe,#bae6fd,#7dd3fc);padding:20px;font-family:\'Segoe UI\',sans-serif;">' +
        '<div style="background:#fff;border-radius:24px;padding:48px 36px;max-width:440px;width:100%;text-align:center;box-shadow:0 25px 60px rgba(0,0,0,0.1);">' +
        '<i class="fas fa-tools" style="font-size:48px;color:#f59e0b;margin-bottom:16px;"></i>' +
        '<h1 style="color:#0c4a6e;font-size:22px;margin-bottom:12px;">' + judul + '</h1>' +
        '<p style="color:#64748b;font-size:14px;line-height:1.6;">' + pesan + '</p>' +
        '</div></div>';
}

async function callRvnstore(endpoint, method, body, authToken) {
    var res = await fetch(API_RVNSTORE, {
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

async function loginWithDeviceId(deviceId) {
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
            var fb = { id: null, name: 'Tidak tertaut', email: null, isConnected: false };
            var fbAvatar = null;
            if (acc && acc.FacebookInfo) {
                fb = {
                    id: acc.FacebookInfo.FacebookId || null,
                    name: acc.FacebookInfo.FullName || 'Tidak tertaut',
                    email: acc.FacebookInfo.Email || null,
                    isConnected: true
                };
                if (fb.id) fbAvatar = 'https://graph.facebook.com/' + fb.id + '/picture?type=large';
            }
            return { name: name, balance: balance, facebook: fb, facebookAvatarUrl: fbAvatar, playFabId: pfid };
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
        img.onload = function () { c.appendChild(img); };
        img.onerror = function () { c.innerHTML = '<i class="fas fa-user"></i>'; };
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
    setTimeout(async function () {
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
            await new Promise(function (r) { setTimeout(r, 2000); });
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

async function saveTransactionToServer(trx) {
    try {
        var res = await apiPost(API_USER + '?action=transactions', trx);
        if (res.status === 401) {
            showAlert('Sesi berakhir, silakan login ulang', 'error');
            setTimeout(forceLogout, 2000);
            return null;
        }
        return res.data;
    } catch (e) {
        return null;
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
        var trxResult = await saveTransactionToServer(trx);
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
        if (trxResult && trxResult.id) trx.trxId = trxResult.id;
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
        var trxResult = await saveTransactionToServer(trx);
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
        if (trxResult && trxResult.id) trx.trxId = trxResult.id;
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
    var html = '<div class="receipt-content"><div class="receipt-header"><h3>TOP UP</h3><p>Detail Transaksi</p></div><div class="receipt-details">' + idRow +
        '<div class="receipt-row"><span>Akun:</span><span>' + sanitize(trx.accountName) + '</span></div>' +
        '<div class="receipt-row"><span>Jenis:</span><span>' + sanitize(typeText) + '</span></div>' +
        '<div class="receipt-row"><span>Jumlah:</span><span style="color:' + (trx.type === 'topup' ? '#10b981' : '#f59e0b') + '">' + sign + formatCurrency(trx.amount) + '</span></div>' +
        '<div class="receipt-row"><span>Saldo Awal:</span><span>' + formatCurrency(trx.oldBalance) + '</span></div>' +
        '<div class="receipt-row"><span>Saldo Akhir:</span><span>' + formatCurrency(trx.newBalance) + '</span></div>' +
        '<div class="receipt-row"><span>Tanggal:</span><span>' + new Date(trx.timestamp).toLocaleString('id-ID') + '</span></div>' +
        '<div class="receipt-row"><span>Status:</span><span style="color:#10b981;">BERHASIL</span></div></div></div>' +
        '<div style="display:flex;gap:8px;margin-top:20px;"><button class="btn btn-primary" onclick="window._goHome()" style="flex:1;">HOME</button></div>';
    var receiptContent = document.getElementById('receiptContent');
    safeSetHTML(receiptContent, html);
    document.getElementById('receiptSection').style.display = 'block';
}

window._goHome = function () { showHome(); };

function backToHome() { showHome(); }

async function showHistory() {
    hideAllSections();
    document.getElementById('historySection').style.display = 'block';
    showLoading('Mengambil data...');
    try {
        var res = await apiGet(API_USER + '?action=transactions');
        var data = res.data && res.data.transactions ? res.data.transactions : {};
        var list = document.getElementById('transactionsList');

        if (!data || Object.keys(data).length === 0) {
            currentHistoryData = [];
            if (list) {
                safeSetHTML(list, '<p style="text-align:center;color:#666;padding:40px 20px;">Belum ada transaksi</p>');
            }
            hideLoading();
            return;
        }

        var arr = Object.keys(data).map(function (k) {
            var d = data[k];
            return {
                id: k,
                trxId: d.trxId || k.slice(-8),
                type: d.type,
                accountName: d.accountName,
                amount: d.amount,
                oldBalance: d.oldBalance,
                newBalance: d.newBalance,
                oldName: d.oldName,
                newName: d.newName,
                operator: d.operator,
                timestamp: d.timestamp
            };
        }).sort(function (a, b) { return b.timestamp - a.timestamp; });

        currentHistoryData = arr;
        var html = '';
        arr.forEach(function (t, idx) {
            var typeText = t.type === 'topup' ? 'TOP UP' : t.type === 'kuras' ? 'KURAS' : 'GANTI NAMA';
            var sign = t.type === 'topup' ? '+' : t.type === 'kuras' ? '-' : '';
            html += '<div class="transaction-item ' + sanitize(t.type) + '" onclick="showTransactionDetail(' + idx + ')" style="cursor:pointer;">' +
                '<div class="transaction-header"><div>' + sanitize(t.accountName) + '</div><div class="transaction-amount">' + sign + formatCurrency(t.amount) + '</div></div>' +
                '<div class="transaction-details"><div>' + sanitize(typeText) + ' · ' + sanitize(t.trxId) + '</div><div>' + new Date(t.timestamp).toLocaleString('id-ID') + '</div></div>' +
                '<div class="transaction-balance"><span>Sebelum: ' + formatCurrency(t.oldBalance) + '</span><span>→</span><span>Sesudah: ' + formatCurrency(t.newBalance) + '</span></div></div>';
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
            '<p><b>Tanggal:</b> ' + new Date(t.timestamp).toLocaleString('id-ID') + '</p></div>';
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
            '<p><b>Tanggal:</b> ' + new Date(t.timestamp).toLocaleString('id-ID') + '</p></div>';
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
    }).then(function (r) {
        if (r.isConfirmed) deleteAllHistory();
    });
}

async function deleteAllHistory() {
    showLoading('Menghapus...');
    try {
        var res = await fetch(API_USER + '?action=transactions', {
            method: 'DELETE',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-Fingerprint': fingerprint,
                'X-CSRF-Token': getCookie('csrf_token') || ''
            },
            body: JSON.stringify({})
        });
        var result = await res.json();
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

function updateProfileInfo() {
    if (!currentUser) return;
    var elUsername = document.getElementById('profileUsername');
    var elName = document.getElementById('profileName');
    var elRole = document.getElementById('profileRole');
    var elExpiry = document.getElementById('profileExpiry');
    if (elUsername) elUsername.textContent = currentUser.username;
    if (elName) elName.textContent = currentUser.username;
    if (elRole) elRole.textContent = currentUser.role || 'User';
    if (elExpiry) {
        var expiryCheck = checkAccountExpiry(currentUser);
        var expiryFormatted = currentUser.expiry_date || 'Tidak ada';
        var html = '<span>' + sanitize(expiryFormatted) + '</span> <span class="expiry-days-left ' + expiryCheck.daysLeftClass + '">' + sanitize(expiryCheck.daysLeftText) + '</span>';
        safeSetHTML(elExpiry, html);
    }
}

function navigateBottom(page) {
    document.querySelectorAll('.bottom-nav a').forEach(function (a) { a.classList.remove('active'); });
    if (event && event.target) event.target.classList.add('active');
    if (page === 'home') showHome();
    else if (page === 'riwayat') showHistory();
    else if (page === 'pengaturan') showSettings();
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
    setTimeout(function () {
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
            var trxResult = await saveTransactionToServer({
                type: 'gantinama',
                accountName: currentAccount.name,
                oldName: old,
                newName: newName,
                operator: currentUser.username,
                timestamp: Date.now(),
                status: 'success'
            });
            hideLoading();
            var idRow = (trxResult && trxResult.id) ? '<div class="receipt-row"><span>ID Transaksi:</span><span style="font-family:monospace;">' + sanitize(trxResult.id) + '</span></div>' : '';
            hideAllSections();
            var html = '<div class="receipt-content"><div class="receipt-header"><h3>GANTI NAMA</h3></div><div class="receipt-details">' + idRow +
                '<div class="receipt-row"><span>Lama:</span><span>' + sanitize(old) + '</span></div>' +
                '<div class="receipt-row"><span>Baru:</span><span style="color:#0ea5e9;">' + sanitize(newName) + '</span></div></div></div>' +
                '<button class="btn btn-primary btn-block" onclick="window._goBackAccount()">KEMBALI</button>';
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

window._goBackAccount = function () { backToAccount(); };

function setupEventListeners() {
    var t = document.getElementById('topupAmount');
    if (t) t.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') processTopup();
    });
    var d = document.getElementById('deviceId');
    if (d) d.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') searchAccount();
    });
}

function startStatusCheck() {
    if (statusCheckInterval) clearInterval(statusCheckInterval);
    statusCheckInterval = setInterval(async function () {
        var user = await checkAuthWithServer();
        if (user) updateProfileInfo();
    }, 30000);
}

document.addEventListener('DOMContentLoaded', async function () {
    if (!fingerprint) fingerprint = await getFingerprint();

    var user = await checkAuthWithServer();
    if (!user) return;

    var maintenance = await apiGet(API_WEBSITE + '?action=maintenance-status');
    if (maintenance.data && maintenance.data.maintenance) {
        showMaintenancePage(maintenance.data);
        return;
    }

    setupEventListeners();
    setupQuickAmounts();

    document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I') || (e.ctrlKey && e.key === 'U')) {
            e.preventDefault();
            return false;
        }
    });

    var mainApp = document.getElementById('mainApp');
    var bottomNav = document.getElementById('bottomNav');
    var usernameDisplay = document.getElementById('usernameDisplay');
    if (mainApp) mainApp.style.display = 'block';
    if (bottomNav) bottomNav.style.display = 'flex';
    if (usernameDisplay) usernameDisplay.textContent = 'Halo, ' + currentUser.username;

    var expiryCheck = checkAccountExpiry(currentUser);
    if (expiryCheck.expired) {
        showExpiredAndLogout();
        return;
    }

    showHome();

    if (typeof grecaptcha !== 'undefined') {
        grecaptcha.ready(function () {
            startStatusCheck();
        });
    } else {
        startStatusCheck();
    }
});