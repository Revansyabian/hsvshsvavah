var API_BASE = '/api';
var API_WEBSITE = '/api/webtopupbussid';
var API_AUTH = '/api/auth';
var WHATSAPP_NUMBER = "6285199120995";
var MAX_PASSWORD_LENGTH = 20;

var currentUser = null;
var fingerprint = '';
var alertTimeout = null;
var isBlocked = false;
var blockedChecked = false;
var loginInProgress = false;
var globalFailedAttempts = 0;
var globalBlockedUntil = null;

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
function getGlobalBlockData() {
    var data = storageGet('global_block');
    if (data) {
        try {
            if (data.blockedUntil && Date.now() > data.blockedUntil) {
                storageRemove('global_block');
                return { attempts: 0, blockedUntil: null };
            }
            return data;
        } catch (e) {
            return { attempts: 0, blockedUntil: null };
        }
    }
    return { attempts: 0, blockedUntil: null };
}
function saveGlobalBlockData(data) {
    storageSet('global_block', data);
}

function sanitize(str) {
    if (!str) return '';
    return String(str).replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
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

async function apiGet(url) {
    if (!fingerprint) fingerprint = await getFingerprint();
    var res = await fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        headers: { 'X-Fingerprint': fingerprint },
        cache: 'no-store'
    });
    var text = await res.text();
    if (!text || text === 'null') return null;
    try { return JSON.parse(text); } catch { return null; }
}

async function apiPost(url, body) {
    if (!fingerprint) fingerprint = await getFingerprint();
    var res = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            'X-Fingerprint': fingerprint
        },
        body: JSON.stringify(body || {})
    });
    var text = await res.text();
    if (!text || text === 'null') return null;
    try { return JSON.parse(text); } catch { return null; }
}

async function periksaMaintenance() {
    try {
        var result = await apiGet(API_WEBSITE + '?action=maintenance-status');
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

    document.body.innerHTML = `
        <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#f4f7fb;font-family:'Inter','Segoe UI',Tahoma,sans-serif;-webkit-font-smoothing:antialiased;">
            <div style="background:#FFFFFF;border:2px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;padding:40px 32px 36px;width:100%;max-width:440px;text-align:center;">
                <div style="width:88px;height:88px;background:#fef3c7;border:2px solid #0F172A;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 22px;box-shadow:3px 3px 0 #0F172A;">
                    <i class="fas fa-tools" style="font-size:36px;color:#f59e0b;"></i>
                </div>
                <div style="display:inline-block;background:#fef3c7;color:#92400e;border:2px solid #0F172A;border-radius:999px;padding:5px 14px;font-size:11px;font-weight:900;letter-spacing:0.08em;text-transform:uppercase;box-shadow:2px 2px 0 #0F172A;margin-bottom:18px;">Maintenance</div>
                <h1 style="color:#0F172A;font-size:24px;font-weight:900;letter-spacing:-0.03em;line-height:1.2;margin:0 0 10px;">${judul}</h1>
                <p style="color:#64748b;font-size:14px;font-weight:500;line-height:1.6;margin:0 0 22px;">${pesan}</p>
                <div style="background:#E0F5FF;color:#0F172A;border:2px solid #0F172A;border-radius:10px;padding:12px 16px;font-weight:700;font-size:13px;box-shadow:2px 2px 0 #0F172A;">${teksEstimasi}</div>
            </div>
        </div>
    `;
}

async function checkIfBlocked() {
    if (blockedChecked) return isBlocked;
    if (!fingerprint) fingerprint = await getFingerprint();

    var globalBlock = getGlobalBlockData();
    if (globalBlock.blockedUntil && Date.now() < globalBlock.blockedUntil) {
        isBlocked = true;
        blockedChecked = true;
        return true;
    }

    try {
        var result = await apiGet(API_WEBSITE + '?action=check-blocked');
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

function tampilkanHalamanBlokir(alasan) {
    var alasanText = sanitize(alasan || 'Akses Anda diblokir karena terdeteksi aktivitas yang melanggar aturan. Jika Anda merasa ini kesalahan, silakan hubungi admin untuk membuka akses.');

    document.body.innerHTML = `
        <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#f4f7fb;font-family:'Inter','Segoe UI',Tahoma,sans-serif;-webkit-font-smoothing:antialiased;">
            <div style="background:#FFFFFF;border:2px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;padding:40px 32px 36px;width:100%;max-width:440px;text-align:center;">
                <div style="width:88px;height:88px;background:#fee2e2;border:2px solid #0F172A;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 22px;box-shadow:3px 3px 0 #0F172A;">
                    <i class="fas fa-lock" style="font-size:36px;color:#ef4444;"></i>
                </div>
                <div style="display:inline-block;background:#fee2e2;color:#991b1b;border:2px solid #0F172A;border-radius:999px;padding:5px 14px;font-size:11px;font-weight:900;letter-spacing:0.08em;text-transform:uppercase;box-shadow:2px 2px 0 #0F172A;margin-bottom:18px;">
                    <i class="fas fa-exclamation-circle" style="margin-right:4px;"></i> Diblokir
                </div>
                <h1 style="color:#0F172A;font-size:24px;font-weight:900;letter-spacing:-0.03em;line-height:1.2;margin:0 0 12px;">AKSES DITOLAK</h1>
                <p style="color:#64748b;font-size:14px;font-weight:500;line-height:1.6;margin:0 0 20px;">Maaf, akses Anda diblokir.</p>
                <div style="background:#fef3c7;color:#92400e;border:2px solid #0F172A;border-radius:10px;padding:14px 16px;font-weight:700;font-size:13px;line-height:1.5;box-shadow:2px 2px 0 #0F172A;text-align:left;">
                    <div style="font-size:10px;font-weight:900;letter-spacing:0.08em;text-transform:uppercase;color:#0F172A;margin-bottom:6px;">
                        <i class="fas fa-circle-info" style="margin-right:4px;"></i> Alasan
                    </div>
                    ${alasanText}
                </div>
            </div>
        </div>
    `;
}

function tampilkanHalamanBanAkses(until, alasan) {
    var untilText = sanitize((until || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(until).toLocaleString('id-ID')));
    var alasanText = sanitize(alasan || 'Akses Anda diblokir oleh admin karena terdeteksi pelanggaran aturan.');

    document.body.innerHTML = `
        <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#f4f7fb;font-family:'Inter','Segoe UI',Tahoma,sans-serif;-webkit-font-smoothing:antialiased;">
            <div style="background:#FFFFFF;border:2px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;padding:40px 32px 36px;width:100%;max-width:440px;text-align:center;">
                <div style="width:88px;height:88px;background:#fee2e2;border:2px solid #0F172A;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 22px;box-shadow:3px 3px 0 #0F172A;">
                    <i class="fas fa-ban" style="font-size:36px;color:#ef4444;"></i>
                </div>
                <div style="display:inline-block;background:#fee2e2;color:#991b1b;border:2px solid #0F172A;border-radius:999px;padding:5px 14px;font-size:11px;font-weight:900;letter-spacing:0.08em;text-transform:uppercase;box-shadow:2px 2px 0 #0F172A;margin-bottom:18px;">
                    <i class="fas fa-exclamation-triangle" style="margin-right:4px;"></i> Akses Diblokir
                </div>
                <h1 style="color:#0F172A;font-size:24px;font-weight:900;letter-spacing:-0.03em;line-height:1.2;margin:0 0 12px;">AKSES DIBLOKIR</h1>
                <p style="color:#64748b;font-size:14px;font-weight:500;line-height:1.6;margin:0 0 20px;">Maaf, akses Anda diblokir oleh admin.</p>
                <div style="background:#fef3c7;color:#92400e;border:2px solid #0F172A;border-radius:10px;padding:14px 16px;font-weight:700;font-size:13px;line-height:1.5;box-shadow:2px 2px 0 #0F172A;margin-bottom:14px;text-align:left;">
                    <div style="font-size:10px;font-weight:900;letter-spacing:0.08em;text-transform:uppercase;color:#0F172A;margin-bottom:6px;">
                        <i class="fas fa-circle-info" style="margin-right:4px;"></i> Alasan
                    </div>
                    ${alasanText}
                </div>
                <div style="background:#fee2e2;color:#991b1b;border:2px solid #0F172A;border-radius:10px;padding:12px 16px;font-weight:800;font-size:13px;box-shadow:2px 2px 0 #0F172A;">
                    <i class="fas fa-clock" style="margin-right:6px;"></i> Durasi: ${untilText}
                </div>
            </div>
        </div>
    `;
}

function tampilkanPopupBanned(until) {
    var untilText = sanitize((until || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(until).toLocaleString('id-ID')));
    Swal.fire({
        icon: 'error',
        title: 'AKUN DIBANNED',
        html: '<p>Maaf, akun Anda telah dibanned oleh admin.</p><p style="color:#dc2626;background:#fee2e2;padding:8px;border-radius:8px;"><b>Durasi: ' + untilText + '</b></p>',
        confirmButtonText: '<i class="fab fa-whatsapp"></i> Hubungi Admin',
        confirmButtonColor: '#25D366',
        showCancelButton: true,
        cancelButtonText: 'Tutup',
        cancelButtonColor: '#64748b',
        allowOutsideClick: false
    }).then(function (r) {
        if (r.isConfirmed) window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20akun%20saya%20dibanned', '_blank');
    });
}

function tampilkanPopupDitangguhkan() {
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
    }).then(function (r) {
        if (r.isConfirmed) window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20akun%20saya%20ditangguhkan', '_blank');
    });
}

function tampilkanPopupBelumAktif() {
    Swal.fire({
        icon: 'warning',
        title: 'AKUN BELUM AKTIF',
        html: '<p>Akun Anda belum diaktivasi oleh admin.</p><p style="color:#0ea5e9;background:#E6F9FF;padding:8px;border-radius:8px;"><b>Silakan aktivasi dengan menghubungi nomor di bawah ini:</b></p><p style="font-size:18px;font-weight:700;color:#25D366;margin-top:8px;"><i class="fab fa-whatsapp"></i> ' + WHATSAPP_NUMBER + '</p>',
        confirmButtonText: '<i class="fab fa-whatsapp"></i> Hubungi Admin',
        confirmButtonColor: '#25D366',
        showCancelButton: true,
        cancelButtonText: 'Tutup',
        cancelButtonColor: '#64748b',
        allowOutsideClick: false
    }).then(function (r) {
        if (r.isConfirmed) window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20saya%20ingin%20aktivasi%20akun', '_blank');
    });
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
        alertDiv.innerHTML = '<div class="alert-content"><div class="alert-icon"><i class="fas ' + (icons[type] || 'fa-info-circle') + '"></i></div><span>' + sanitize(message) + '</span></div>';
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

function updatePasswordCounter() {
    var input = document.getElementById('password');
    var counter = document.getElementById('passwordCharCount');
    if (input && counter) counter.textContent = input.value.length + '/' + MAX_PASSWORD_LENGTH;
}

function parseDate(dateStr) {
    if (!dateStr) return null;
    var parts = dateStr.split('/');
    if (parts.length !== 3) return null;
    var month = parseInt(parts[0], 10) - 1;
    var day = parseInt(parts[1], 10);
    var year = parseInt(parts[2], 10);
    if (isNaN(day) || isNaN(month) || isNaN(year)) return null;
    if (month < 0 || month > 11 || day < 1 || day > 31 || year < 2000) return null;
    var date = new Date(year, month, day);
    if (date.getMonth() !== month || date.getDate() !== day) return null;
    return date;
}

function calculateRemainingDays(expiryDate) {
    if (!expiryDate) return -999;
    if (expiryDate.includes('9999')) return 999999;
    var expiry = parseDate(expiryDate);
    if (!expiry) return -999;
    var now = new Date();
    now.setHours(0, 0, 0, 0);
    return Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
}

function checkAccountExpiry(user) {
    if (!user || !user.expiry_date) return { expired: false, daysLeft: 999999 };
    var daysLeft = calculateRemainingDays(user.expiry_date);
    var expired = daysLeft <= 0 && daysLeft !== 999999;
    return { expired: expired, daysLeft: daysLeft };
}

async function login() {
    if (loginInProgress) return;
    loginInProgress = true;
    try {
        var maintenance = await periksaMaintenance();
        if (maintenance) {
            tampilkanHalamanMaintenance(maintenance);
            loginInProgress = false;
            return;
        }

        var blocked = await checkIfBlocked();
        if (blocked) {
            tampilkanHalamanBlokir();
            loginInProgress = false;
            return;
        }

        var username = sanitize(document.getElementById('username').value.trim());
        var password = document.getElementById('password').value.trim();

        if (!username || !password) {
            Swal.fire({ icon: "warning", title: "Oops...", text: "Harap isi username dan password!", confirmButtonColor: "#0ea5e9" });
            loginInProgress = false;
            return;
        }

        var blockData = getBlockData(username);
        if (blockData.blockedUntil && Date.now() < blockData.blockedUntil) {
            Swal.fire({ icon: "error", title: "Akses Ditolak", text: "🔒 Terlalu banyak percobaan!", confirmButtonColor: "#ef4444" });
            loginInProgress = false;
            return;
        }

        var captchaResponse = grecaptcha.getResponse();
        if (!captchaResponse || captchaResponse.length === 0) {
            Swal.fire({ icon: "warning", title: "Oops...", text: "Centang \"I'm not a robot\" dulu ya!", confirmButtonColor: "#0ea5e9" });
            loginInProgress = false;
            return;
        }

        showLoading('Login...');
        if (!fingerprint) fingerprint = await getFingerprint();

        var result = await apiPost(API_AUTH + '?action=login', {
            username: username,
            password: password,
            captchaToken: captchaResponse
        });

        if (result && result.error === 'blocked') {
            isBlocked = true;
            storageSet('perangkat_diblokir', 'true');
            hideLoading();
            tampilkanHalamanBlokir(result.reason || result.alasan || null);
            loginInProgress = false;
            return;
        }

        if (result && result.banned) {
            hideLoading();
            tampilkanPopupBanned(result.bannedUntil || 0);
            loginInProgress = false;
            return;
        }

        if (result && result.banAkses) {
            hideLoading();
            tampilkanHalamanBanAkses(result.banAksesUntil || 0, result.reason || result.alasan || null);
            loginInProgress = false;
            return;
        }

        if (result && result.forceLogout) {
            hideLoading();
            tampilkanPopupDitangguhkan();
            loginInProgress = false;
            return;
        }

        if (result && result.error === 'pending_activation') {
            hideLoading();
            tampilkanPopupBelumAktif();
            try { grecaptcha.reset(); } catch (e) {}
            loginInProgress = false;
            return;
        }

        if (result && result.error === 'rejected') {
            hideLoading();
            Swal.fire({ icon: "error", title: "AKUN DITOLAK", text: "Akun Anda ditolak oleh admin.", confirmButtonColor: "#ef4444" });
            try { grecaptcha.reset(); } catch (e) {}
            loginInProgress = false;
            return;
        }

        if (result && result.error === 'captcha_failed') {
            hideLoading();
            Swal.fire({ icon: "error", title: "reCAPTCHA Gagal", text: "Coba lagi.", confirmButtonColor: "#ef4444" });
            try { grecaptcha.reset(); } catch (e) {}
            loginInProgress = false;
            return;
        }

        if (result && result.success) {
            storageRemove(getBlockKey(username));
            var globalBlock = getGlobalBlockData();
            if (globalBlock.attempts > 0) {
                saveGlobalBlockData({ attempts: 0, blockedUntil: null });
            }

            var user = result.user || {};

            storageSet('sesi_pengguna', JSON.stringify({
                username: user.username || username,
                user_id: user.id || '',
                role: user.role || 'User',
                email: user.email || '',
                expiry_date: user.expiry_date || '',
                timestamp: Date.now()
            }));

            hideLoading();
            Swal.fire({
                icon: "success",
                title: "Login Berhasil!",
                text: "Selamat datang, " + (user.username || username) + "!",
                timer: 1500,
                showConfirmButton: false
            }).then(function () {
                window.location.href = '/pages/dashboard';
            });
            return;
        }

        var globalBlock = getGlobalBlockData();
        globalBlock.attempts += 1;

        if (globalBlock.attempts >= 5) {
            globalBlock.blockedUntil = Date.now() + 15 * 60 * 1000;
            saveGlobalBlockData(globalBlock);
            isBlocked = true;
            storageSet('perangkat_diblokir', 'true');
            hideLoading();
            try { grecaptcha.reset(); } catch (e) {}
            Swal.fire({
                icon: "error",
                title: "PERANGKAT DIBLOKIR",
                text: "Terlalu banyak percobaan gagal. Perangkat Anda diblokir selama 15 menit.",
                confirmButtonColor: "#ef4444"
            }).then(function () {
                tampilkanHalamanBlokir();
            });
            loginInProgress = false;
            return;
        }

        saveGlobalBlockData(globalBlock);

        blockData.attempts += 1;
        var d = getBlockDuration(blockData.attempts);
        hideLoading();
        try { grecaptcha.reset(); } catch (e) {}

        if (d > 0) {
            blockData.blockedUntil = Date.now() + d * 60 * 1000;
            saveBlockData(username, blockData);
            Swal.fire({ icon: "error", title: "Akses Ditolak", text: "🔒 Terlalu banyak percobaan!", confirmButtonColor: "#ef4444" });
        } else {
            saveBlockData(username, blockData);
            var remaining = 5 - globalBlock.attempts;
            Swal.fire({
                icon: "error",
                title: "Oops...",
                text: "User tidak ditemukan atau password salah! (" + remaining + " percobaan lagi sebelum perangkat diblokir)",
                confirmButtonColor: "#ef4444"
            });
        }
    } catch (error) {
        hideLoading();
        try { grecaptcha.reset(); } catch (e) {}
        Swal.fire({ icon: "error", title: "Oops...", text: "Gagal menghubungkan ke server!", confirmButtonColor: "#ef4444" });
    }
    loginInProgress = false;
}

function autoCheckSession() {
    var saved = storageGet('sesi_pengguna');
    if (!saved) return;
    try {
        var session = JSON.parse(saved);
        var age = Date.now() - (session.timestamp || 0);
        if (age > 7 * 24 * 60 * 60 * 1000) {
            storageRemove('sesi_pengguna');
            return;
        }
        window.location.href = '/pages/dashboard';
    } catch (e) {
        storageRemove('sesi_pengguna');
    }
}

document.addEventListener('DOMContentLoaded', async function () {
    autoCheckSession();

    if (!fingerprint) fingerprint = await getFingerprint();

    var maintenance = await periksaMaintenance();
    if (maintenance) {
        tampilkanHalamanMaintenance(maintenance);
        return;
    }

    var blocked = await checkIfBlocked();
    if (blocked) {
        tampilkanHalamanBlokir();
        return;
    }

    updatePasswordCounter();
    document.getElementById('password').addEventListener('input', updatePasswordCounter);

    document.getElementById('username').addEventListener('keypress', function (e) {
        if (e.key === 'Enter') document.getElementById('password').focus();
    });
    document.getElementById('password').addEventListener('keypress', function (e) {
        if (e.key === 'Enter') login();
    });

    const togglePassword = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');

    if (togglePassword && passwordInput) {
        let hideTimeout = null;

        togglePassword.addEventListener('click', function () {
            const isVisible = passwordInput.getAttribute('type') === 'text';
            passwordInput.setAttribute('type', isVisible ? 'password' : 'text');
            this.classList.toggle('fa-eye');
            this.classList.toggle('fa-eye-slash');
            if (!isVisible) {
                if (hideTimeout) clearTimeout(hideTimeout);
                hideTimeout = setTimeout(() => {
                    passwordInput.setAttribute('type', 'password');
                    togglePassword.classList.remove('fa-eye');
                    togglePassword.classList.add('fa-eye-slash');
                    hideTimeout = null;
                }, 5000);
            } else {
                if (hideTimeout) {
                    clearTimeout(hideTimeout);
                    hideTimeout = null;
                }
            }
        });

        passwordInput.addEventListener('blur', function () {
            if (this.getAttribute('type') === 'text') {
                this.setAttribute('type', 'password');
                togglePassword.classList.remove('fa-eye');
                togglePassword.classList.add('fa-eye-slash');
                if (hideTimeout) {
                    clearTimeout(hideTimeout);
                    hideTimeout = null;
                }
            }
        });
    }
});