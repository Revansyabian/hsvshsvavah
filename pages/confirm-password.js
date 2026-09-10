// confirm-password.js
var API_RESET = '/api/reset-pw';
var API_REVANSTORE = '/api/revanstoreV2';
var fingerprint = '';
var resetToken = '';

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

function getUrlParam(name) {
    var params = new URLSearchParams(window.location.search);
    return params.get(name);
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

function showPage(pageId) {
    var pages = ['loadingPage', 'expiredPage', 'invalidPage', 'formSection', 'successPage'];
    pages.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.classList.remove('show');
    });
    var target = document.getElementById(pageId);
    if (target) target.classList.add('show');
}

function updatePasswordStrength() {
    var password = document.getElementById('newPassword').value;
    var bar = document.getElementById('passwordStrengthBar');
    bar.className = 'password-strength-bar';
    if (password.length === 0) {
        bar.style.width = '0%';
    } else if (password.length < 6) {
        bar.classList.add('strength-weak');
    } else if (password.length < 10) {
        bar.classList.add('strength-medium');
    } else {
        bar.classList.add('strength-strong');
    }
}

function setButtonLoading(loading) {
    var btn = document.getElementById('btnConfirm');
    btn.disabled = loading;
    btn.innerHTML = loading ? '<i class="fas fa-spinner fa-spin"></i> MEMPROSES...' : '<i class="fas fa-check"></i> RESET PASSWORD';
}

function tampilkanHalamanMaintenance(dataMaintenance) {
    var judul = sanitize((dataMaintenance && (dataMaintenance.title || dataMaintenance.judul)) ? (dataMaintenance.title || dataMaintenance.judul) : 'SEDANG PERBAIKAN SISTEM');
    var pesan = sanitize((dataMaintenance && (dataMaintenance.message || dataMaintenance.pesan)) ? (dataMaintenance.message || dataMaintenance.pesan) : 'Website sedang dalam perbaikan oleh admin. Silakan kembali beberapa saat lagi.');
    var sampai = (dataMaintenance && (dataMaintenance.until || dataMaintenance.sampai)) ? (dataMaintenance.until || dataMaintenance.sampai) : null;
    var teksEstimasi = sanitize(sampai ? 'Estimasi selesai: ' + new Date(sampai).toLocaleString('id-ID') : 'Mohon maaf atas ketidaknyamanan ini.');

    var html = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#e0f2fe 0%,#bae6fd 50%,#7dd3fc 100%);padding:20px;font-family:\'Segoe UI\',sans-serif;">' +
        '<div style="background:#ffffff;border-radius:24px;padding:48px 36px;width:100%;max-width:440px;text-align:center;box-shadow:0 25px 60px rgba(0,0,0,0.1);">' +
        '<div style="width:90px;height:90px;background:#fef3c7;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;">' +
        '<i class="fas fa-tools" style="font-size:40px;color:#f59e0b;"></i>' +
        '</div>' +
        '<h1 style="color:#0c4a6e;font-size:24px;font-weight:700;margin-bottom:8px;">' + judul + '</h1>' +
        '<p style="color:#64748b;font-size:14px;margin-bottom:6px;line-height:1.6;">' + pesan + '</p>' +
        '<div style="background:#fef3c7;color:#92400e;padding:12px 16px;border-radius:12px;font-weight:600;font-size:13px;margin:16px 0 24px;">' + teksEstimasi + '</div></div></div>';

    safeSetHTML(document.body, html);
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
            return true;
        }
        return false;
    } catch (e) {
        return false;
    }
}

async function verifyToken() {
    var payload = {
        action: 'verify_token',
        token: resetToken,
        timestamp: Date.now()
    };

    var requestBody = payload;

    try {
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

        return result;
    } catch (e) {
        return null;
    }
}



async function checkTokenOnLoad() {
    resetToken = getUrlParam('token');

    // CEK TOKEN ADA APA GA
    if (!resetToken || resetToken.length < 10) {
        document.getElementById('headerSubtitle').textContent = 'Link Tidak Valid';
        showPage('invalidPage');
        return;
    }

    // ==================== 1. TAMPILKAN LOADING ====================
    showPage('loadingPage');

    if (!fingerprint) fingerprint = await getFingerprint();

    // ==================== 2. CEK MAINTENANCE ====================
    var maintenance = await periksaMaintenance();
    if (maintenance) {
        tampilkanHalamanMaintenance(maintenance);
        return;
    }

    // ==================== 3. CEK BLOCKED ====================
    var blocked = await checkIfBlocked();
    if (blocked) {
        tampilkanHalamanBlokir();
        return;
    }

    // ==================== 4. CEK TOKEN ====================
    var result = await verifyToken();

    if (result && result.valid) {
        document.getElementById('headerSubtitle').textContent = 'Masukkan password baru Anda';
        showPage('formSection');
    } else if (result && result.error === 'token_expired') {
        document.getElementById('headerSubtitle').textContent = 'Link Expired';
        showPage('expiredPage');
    } else {
        document.getElementById('headerSubtitle').textContent = 'Link Tidak Valid';
        showPage('invalidPage');
    }
}

async function confirmReset() {
    var newPassword = document.getElementById('newPassword').value.trim();
    var confirmPassword = document.getElementById('confirmPassword').value.trim();

    if (!resetToken) {
        Swal.fire({ icon: "error", title: "Link Tidak Valid!", confirmButtonColor: "#ef4444" });
        return;
    }

    if (!newPassword || newPassword.length < 6) {
        Swal.fire({ icon: "warning", title: "Password Terlalu Pendek!", text: "Password minimal 6 karakter.", confirmButtonColor: "#00BFFF" });
        return;
    }

    if (newPassword !== confirmPassword) {
        Swal.fire({ icon: "error", title: "Password Tidak Cocok!", text: "Password dan konfirmasi harus sama.", confirmButtonColor: "#ef4444" });
        return;
    }

    var captchaResponse = '';
    if (typeof grecaptcha !== 'undefined') {
        captchaResponse = grecaptcha.getResponse();
    }

    if (!captchaResponse || captchaResponse.length === 0) {
        Swal.fire({ icon: "warning", title: "reCAPTCHA Diperlukan!", text: "Centang \"I'm not a robot\" dulu ya!", confirmButtonColor: "#00BFFF" });
        return;
    }

    setButtonLoading(true);

    var payload = {
        action: 'confirm_reset',
        token: resetToken,
        newPassword: newPassword,
        captchaToken: captchaResponse,
        timestamp: Date.now()
    };

    var requestBody = payload;

    try {
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
            document.getElementById('headerSubtitle').textContent = 'Berhasil';
            showPage('successPage');
        } else if (result && result.error === 'token_expired') {
            if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
            document.getElementById('headerSubtitle').textContent = 'Link Expired';
            showPage('expiredPage');
        } else if (result && result.error === 'token_not_found') {
            if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
            document.getElementById('headerSubtitle').textContent = 'Link Tidak Valid';
            showPage('invalidPage');
        } else {
            Swal.fire({ icon: "error", title: "Gagal!", text: "Terjadi kesalahan. Coba lagi nanti.", confirmButtonColor: "#ef4444" });
            if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
        }

    } catch (e) {
        setButtonLoading(false);
        Swal.fire({ icon: "error", title: "Error!", text: "Gagal menghubungkan ke server!", confirmButtonColor: "#ef4444" });
    }
}

document.addEventListener('DOMContentLoaded', async function() {
    if (!fingerprint) fingerprint = await getFingerprint();
    
    document.getElementById('newPassword').addEventListener('input', updatePasswordStrength);
    document.getElementById('confirmPassword').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') confirmReset();
    });
    
    checkTokenOnLoad();
});