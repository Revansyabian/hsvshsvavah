var API_RESET = '/api/reset-pw';
var API_REVANSTORE = '/api/revanstoreV2';
var WHATSAPP_NUMBER = "6285199120995";
var fingerprint = '';
var resetInProgress = false;
var isBlocked = false;
var blockedChecked = false;

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

function sanitize(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/`/g, '&#96;')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .replace(/<script/gi, '')
        .replace(/<\/script/gi, '');
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

function validateUsernameInput() {
    var input = document.getElementById('username');
    var value = input.value;
    var cleaned = value.replace(/[^a-zA-Z0-9_.]/g, '');
    if (value !== cleaned) {
        input.value = cleaned;
        Swal.fire({ icon: "warning", title: "Simbol Tidak Diizinkan!", text: "Username hanya boleh huruf, angka, underscore (_), dan titik (.)", timer: 2000, showConfirmButton: false });
    }
}

function showError(msg) {
    var el = document.getElementById('errorText');
    var container = document.getElementById('errorMessage');
    if (el) el.textContent = msg;
    if (container) {
        container.classList.add('show');
        document.getElementById('successMessage').classList.remove('show');
    }
}

function showSuccess(msg) {
    var el = document.getElementById('successText');
    var container = document.getElementById('successMessage');
    if (el) el.textContent = msg;
    if (container) {
        container.classList.add('show');
        document.getElementById('errorMessage').classList.remove('show');
    }
}

function setButtonLoading(loading) {
    var btn = document.getElementById('btnReset');
    btn.disabled = loading;
    btn.innerHTML = loading ? '<i class="fas fa-spinner fa-spin"></i> MENGIRIM...' : '<i class="fas fa-paper-plane"></i> KIRIM LINK RESET';
}

function tampilkanHalamanMaintenance(dataMaintenance) {
    var judul = sanitize((dataMaintenance && (dataMaintenance.title || dataMaintenance.judul)) ? (dataMaintenance.title || dataMaintenance.judul) : 'SEDANG PERBAIKAN SISTEM');
    var pesan = sanitize((dataMaintenance && (dataMaintenance.message || dataMaintenance.pesan)) ? (dataMaintenance.message || dataMaintenance.pesan) : 'Website sedang dalam perbaikan oleh admin. Silakan kembali beberapa saat lagi.');
    var sampai = (dataMaintenance && (dataMaintenance.until || dataMaintenance.sampai)) ? (dataMaintenance.until || dataMaintenance.sampai) : null;
    var teksEstimasi = sanitize(sampai ? 'Estimasi selesai: ' + new Date(sampai).toLocaleString('id-ID') : 'Mohon maaf atas ketidaknyamanan ini.');

    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;padding:20px;font-family:\'Segoe UI\',sans-serif;">' +
        '<div style="background:#ffffff;border-radius:24px;padding:48px 36px;width:100%;max-width:440px;text-align:center;box-shadow:0 25px 60px rgba(0,0,0,0.08);border:1px solid #e2e8f0;">' +
        '<div style="width:90px;height:90px;background:#fef3c7;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;">' +
        '<i class="fas fa-tools" style="font-size:40px;color:#f59e0b;"></i>' +
        '</div>' +
        '<h1 style="color:#0c4a6e;font-size:24px;font-weight:700;margin-bottom:8px;">' + judul + '</h1>' +
        '<p style="color:#64748b;font-size:14px;margin-bottom:6px;line-height:1.6;">' + pesan + '</p>' +
        '<div style="background:#fef3c7;color:#92400e;padding:12px 16px;border-radius:12px;font-weight:600;font-size:13px;margin:16px 0 24px;">' + teksEstimasi + '</div>' +
        '</div></div>';
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
            if (result && result.data && typeof result.data === 'object') result = result.data;
        if (result && (result.maintenance === true || result.title || result.message)) {
            return result;
        }
        return null;
    } catch (e) {
        return null;
    }
}

async function checkIfBlocked() {
    if (blockedChecked) return isBlocked;
    if (!fingerprint) fingerprint = await getFingerprint();
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
            if (result && result.data && typeof result.data === 'object') result = result.data;
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

function tampilkanHalamanBlokir() {
    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;font-family:\'Segoe UI\',sans-serif;">' +
        '<div style="background:#ffffff;border-radius:24px;padding:48px 36px;max-width:420px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.08);border:1px solid #e2e8f0;">' +
        '<i class="fas fa-lock" style="font-size:64px;color:#ef4444;margin-bottom:16px;display:block;"></i>' +
        '<span style="display:inline-block;background:#fef2f2;color:#dc2626;padding:4px 16px;border-radius:20px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;border:1px solid #fecaca;margin-bottom:12px;"><i class="fas fa-exclamation-circle"></i> DIBLOKIR</span>' +
        '<h1 style="font-size:24px;font-weight:700;color:#1e293b;margin-bottom:8px;">AKSES DITOLAK</h1>' +
        '<p style="font-size:14px;color:#64748b;line-height:1.6;">Akses ditolak, jika ingin dibuka silakan hubungi admin.</p>' +
        '</div></div>';
}

async function resetPassword() {
    if (resetInProgress) return;
    resetInProgress = true;
    
    try {
        if (!fingerprint) fingerprint = await getFingerprint();
        
        var maintenance = await periksaMaintenance();
        if (maintenance) {
            tampilkanHalamanMaintenance(maintenance);
            resetInProgress = false;
            return;
        }
        
        var blocked = await checkIfBlocked();
        if (blocked) {
            tampilkanHalamanBlokir();
            resetInProgress = false;
            return;
        }
        
        var username = sanitize(document.getElementById('username').value.trim());
        
        if (!username || username.length < 3) {
            Swal.fire({ icon: "warning", title: "Username Tidak Valid!", text: "Masukkan username minimal 3 karakter.", confirmButtonColor: "#00BFFF" });
            resetInProgress = false;
            return;
        }
        
        var usernameRegex = /^[a-zA-Z0-9_.]+$/;
        if (!usernameRegex.test(username)) {
            Swal.fire({ icon: "error", title: "Simbol Tidak Diizinkan!", confirmButtonColor: "#ef4444" });
            resetInProgress = false;
            return;
        }
        
        var captchaResponse = '';
        if (typeof grecaptcha !== 'undefined') {
            captchaResponse = grecaptcha.getResponse();
        }
        
        if (!captchaResponse || captchaResponse.length === 0) {
            Swal.fire({ icon: "warning", title: "reCAPTCHA Diperlukan!", text: "Centang \"I'm not a robot\" dulu ya!", confirmButtonColor: "#00BFFF" });
            resetInProgress = false;
            return;
        }
        
        setButtonLoading(true);
        
        var payload = {
            action: 'request_reset',
            data: {
                username: username
            },
            username: username,
            captchaToken: captchaResponse,
            timestamp: Date.now()
        };
        
        if (!payload.data) {
            payload.data = { username: username };
        }
        
        var requestBody = payload;
        
        var res = await fetch(API_RESET, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-Fingerprint': fingerprint
            },
            body: JSON.stringify(requestBody)
        });
        
        var result = await res.json();
            if (result && result.data && typeof result.data === 'object') result = result.data;
        
        setButtonLoading(false);
        
        if (result && result.success) {
            if (typeof grecaptcha !== 'undefined') {
                grecaptcha.reset();
            }
            
            var maskedEmail = result.maskedEmail || '';
            var msg = maskedEmail ? 'Link reset telah dikirim ke ' + maskedEmail + '. Link expired dalam 15 menit.' : 'Jika username terdaftar, link reset akan dikirim ke email Anda.';
            
            showSuccess(msg);
            
            Swal.fire({
                icon: "success",
                title: "Link Terkirim!",
                text: msg,
                timer: 4000,
                showConfirmButton: false
            });
            
            document.getElementById('username').value = '';
            
        } else {
            var errorMsg = 'Terjadi kesalahan. Coba lagi nanti.';
            
            if (result && result.error) {
                switch(result.error) {
                    case 'rate_limit':
                        errorMsg = 'Terlalu banyak percobaan. Coba lagi nanti.';
                        break;
                    case 'no_data':
                        errorMsg = 'Data tidak ditemukan!';
                        break;
                    case 'access_denied':
                        errorMsg = 'Akses ditolak!';
                        break;
                    case 'invalid_username':
                        errorMsg = 'Username minimal 3 karakter!';
                        break;
                    case 'invalid_captcha':
                        errorMsg = 'reCAPTCHA tidak valid! Silakan coba lagi.';
                        break;
                    case 'user_not_found':
                        errorMsg = 'Username tidak terdaftar! Periksa kembali username Anda.';
                        break;
                    case 'email_not_found':
                        errorMsg = 'Akun ini tidak memiliki email terdaftar! Hubungi admin.';
                        break;
                    case 'account_banned':
                        errorMsg = 'Akun Anda dibanned! Hubungi admin.';
                        break;
                    case 'account_suspended':
                        errorMsg = 'Akun Anda ditangguhkan! Hubungi admin.';
                        break;
                    case 'email_error':
                        errorMsg = 'Gagal mengirim email! Coba lagi nanti.';
                        break;
                    default:
                        errorMsg = result.message || 'Terjadi kesalahan. Coba lagi nanti.';
                }
            }
            
            Swal.fire({ 
                icon: "error", 
                title: "Gagal!", 
                text: errorMsg, 
                confirmButtonColor: "#ef4444" 
            });
            
            if (typeof grecaptcha !== 'undefined') {
                grecaptcha.reset();
            }
        }
        
    } catch (error) {
        setButtonLoading(false);
        console.error('Reset password error:', error);
        Swal.fire({ 
            icon: "error", 
            title: "Error!", 
            text: "Gagal menghubungkan ke server: " + error.message, 
            confirmButtonColor: "#ef4444" 
        });
        if (typeof grecaptcha !== 'undefined') {
            grecaptcha.reset();
        }
    }
    
    resetInProgress = false;
}

document.addEventListener('DOMContentLoaded', async function() {
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
    
    document.getElementById('username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') resetPassword();
    });
});