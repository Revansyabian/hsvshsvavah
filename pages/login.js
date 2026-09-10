var API_REVANSTORE = '/api/revanstoreV2';
var WHATSAPP_NUMBER = "6285199120995";
var MAX_PASSWORD_LENGTH = 20;

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
var globalFailedAttempts = 0;
var globalBlockedUntil = null;

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
        var payload = {
            path: 'check_blocked',
            method: 'POST',
            data: { fingerprint: fingerprint },
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
function tampilkanHalamanBlokir() {
    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;font-family:\'Segoe UI\',sans-serif;">' +
        '<div style="background:#ffffff;border-radius:24px;padding:48px 36px;max-width:420px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.08);border:1px solid #e2e8f0;">' +
        '<i class="fas fa-lock" style="font-size:64px;color:#ef4444;margin-bottom:16px;display:block;"></i>' +
        '<span style="display:inline-block;background:#fef2f2;color:#dc2626;padding:4px 16px;border-radius:20px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;border:1px solid #fecaca;margin-bottom:12px;"><i class="fas fa-exclamation-circle"></i> DIBLOKIR</span>' +
        '<h1 style="font-size:24px;font-weight:700;color:#1e293b;margin-bottom:8px;">AKSES DITOLAK</h1>' +
        '<p style="font-size:14px;color:#64748b;line-height:1.6;">Akses ditolak, jika ingin dibuka silakan hubungi admin.</p>' +
        '</div></div>';
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
    }).then(function(r) {
        if (r.isConfirmed) window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20akun%20saya%20dibanned', '_blank');
    });
}

function tampilkanHalamanBanAkses(until) {
    var untilText = sanitize((until || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(until).toLocaleString('id-ID')));
    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#f0f9ff 0%,#bae6fd 50%,#7dd3fc 100%);padding:20px;font-family:\'Segoe UI\',sans-serif;">' +
        '<div style="background:#ffffff;border-radius:24px;padding:48px 36px;width:100%;max-width:420px;text-align:center;box-shadow:0 20px 60px rgba(0,191,255,0.15);border:1px solid rgba(0,191,255,0.1);">' +
        '<div style="font-size:72px;color:#f59e0b;margin-bottom:12px;">🚫</div>' +
        '<h2 style="font-size:24px;font-weight:700;color:#0c4a6e;margin-bottom:8px;">AKSES DIBLOKIR</h2>' +
        '<p style="font-size:14px;color:#64748b;margin-bottom:6px;">Maaf, akses Anda diblokir oleh admin.</p>' +
        '<div style="background:#fef3c7;color:#92400e;padding:12px 16px;border-radius:12px;font-weight:600;font-size:14px;margin:16px 0 24px;">Durasi: ' + untilText + '</div>' +
        '<button onclick="window.open(\'https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20akses%20saya%20diblokir\',\'_blank\')" style="display:inline-flex;align-items:center;gap:10px;padding:12px 32px;background:#25D366;color:#fff;border:none;border-radius:30px;font-weight:600;font-size:15px;cursor:pointer;transition:0.2s;font-family:\'Segoe UI\',sans-serif;">' +
        '<i class="fab fa-whatsapp"></i> Hubungi Admin</button></div></div>';
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
    }).then(function(r) {
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
    }).then(function(r) {
        if (r.isConfirmed) window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=Assalamualaikum%20admin%2C%20saya%20ingin%20aktivasi%20akun', '_blank');
    });
}

async function callRevanstore(path, method, data) {
    if (!fingerprint) fingerprint = await getFingerprint();
    if (isBlocked && path !== 'check_blocked') throw new Error('Akses ditolak');
    var payload = {
        path: path,
        method: method || 'GET',
        data: data || null,
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

function getDaysLeftClass(daysLeft) {
    if (daysLeft === 999999) return 'days-permanent';
    if (daysLeft <= 0) return 'days-red';
    if (daysLeft <= 3) return 'days-yellow';
    return 'days-green';
}

function getDaysLeftText(daysLeft) {
    if (daysLeft === 999999) return 'Permanen';
    if (daysLeft === -999) return 'Tidak ada';
    if (daysLeft < 0) return 'Habis ' + Math.abs(daysLeft) + ' hari';
    if (daysLeft === 0) return 'Hari ini';
    if (daysLeft === 1) return '1 hari';
    return daysLeft + ' hari';
}

function checkAccountExpiry(user) {
    if (!user || !user.expiry_date) return { expired: true, daysLeft: -999, daysLeftText: 'Tidak ada', daysLeftClass: 'days-red' };
    var daysLeft = calculateRemainingDays(user.expiry_date);
    var expired = daysLeft <= 0 && daysLeft !== 999999;
    return { expired: expired, daysLeft: daysLeft, daysLeftText: getDaysLeftText(daysLeft), daysLeftClass: getDaysLeftClass(daysLeft) };
}

async function login() {
    if (loginInProgress) return;
    loginInProgress = true;
    try {
        var maintenance = await periksaMaintenance();
        if (maintenance) { tampilkanHalamanMaintenance(maintenance); loginInProgress = false; return; }

        var blocked = await checkIfBlocked();
        if (blocked) { tampilkanHalamanBlokir(); loginInProgress = false; return; }
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
        var userIP = 'unknown';
        try {
            var ipRes = await fetch('https://api.ipify.org?format=json');
            var ipData = await ipRes.json();
            userIP = ipData.ip || 'unknown';
        } catch (e) {}
        if (!fingerprint) fingerprint = await getFingerprint();
        var result = await callRevanstore('login', 'POST', {
            username: username,
            password: password,
            ip: userIP,
            fingerprint: fingerprint,
            captchaToken: captchaResponse
        });
        if (result && result.blocked) {
            isBlocked = true;
            storageSet('perangkat_diblokir', 'true');
            hideLoading();
            tampilkanHalamanBlokir();
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
            tampilkanHalamanBanAkses(result.banAksesUntil || 0);
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
            grecaptcha.reset();
            loginInProgress = false;
            return;
        }
        if (result && result.error === 'rejected') {
            hideLoading();
            Swal.fire({ icon: "error", title: "AKUN DITOLAK", text: "Akun Anda ditolak oleh admin.", confirmButtonColor: "#ef4444" });
            grecaptcha.reset();
            loginInProgress = false;
            return;
        }
        if (result && result.success) {
            storageRemove(getBlockKey(username));
            var globalBlock = getGlobalBlockData();
            if (globalBlock.attempts > 0) {
                saveGlobalBlockData({ attempts: 0, blockedUntil: null });
            }
            var user = result.data;
            var expiryCheck = checkAccountExpiry(user);
            if (expiryCheck.expired) {
                hideLoading();
                storageSet('sesi_pengguna', JSON.stringify({
                    username: username,
                    user_id: user.id,
                    role: user.role || 'Operator',
                    full_name: user.full_name || username,
                    expiry_date: user.expiry_date || '',
                    timestamp: Date.now()
                }));
                window.location.href = '/pages/dashboard';
                loginInProgress = false;
                return;
            }
            await callRevanstore('login_success', 'POST', {});
            storageSet('sesi_pengguna', JSON.stringify({
                username: username,
                user_id: user.id,
                role: user.role || 'Operator',
                full_name: user.full_name || username,
                expiry_date: user.expiry_date || '',
                timestamp: Date.now()
            }));
            hideLoading();
            Swal.fire({
                icon: "success",
                title: "Login Berhasil!",
                text: "Selamat datang, " + (user.full_name || username) + "!",
                timer: 1500,
                showConfirmButton: false
            }).then(function() {
                window.location.href = '/pages/dashboard';
            });
        } else {
            await callRevanstore('login_failed', 'POST', {});
            
            var globalBlock = getGlobalBlockData();
            globalBlock.attempts += 1;
            
            if (globalBlock.attempts >= 5) {
                var duration = 15;
                globalBlock.blockedUntil = Date.now() + duration * 60 * 1000;
                saveGlobalBlockData(globalBlock);
                isBlocked = true;
                storageSet('perangkat_diblokir', 'true');
                hideLoading();
                grecaptcha.reset();
                Swal.fire({ 
                    icon: "error", 
                    title: "PERANGKAT DIBLOKIR", 
                    text: "Terlalu banyak percobaan gagal. Perangkat Anda diblokir selama 15 menit.", 
                    confirmButtonColor: "#ef4444" 
                }).then(function() {
                    tampilkanHalamanBlokir();
                });
                loginInProgress = false;
                return;
            }
            
            saveGlobalBlockData(globalBlock);
            
            blockData.attempts += 1;
            var d = getBlockDuration(blockData.attempts);
            hideLoading();
            grecaptcha.reset();
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

document.addEventListener('DOMContentLoaded', async function() {
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
    document.getElementById('username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') document.getElementById('password').focus();
    });
    document.getElementById('password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') login();
    });

    const togglePassword = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');

    if (togglePassword && passwordInput) {
        let hideTimeout = null;

        togglePassword.addEventListener('click', function() {
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

        passwordInput.addEventListener('blur', function() {
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