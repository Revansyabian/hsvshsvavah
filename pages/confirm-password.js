var API_WEBSITE = '/api/webtopupbussid';
var API_AUTH = '/api/auth';
var WHATSAPP_NUMBER = "6285199120995";

var fingerprint = '';
var resetToken = '';
var alertTimeout = null;
var busy = false;

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

function showPage(pageId) {
    var pages = ['loadingPage', 'expiredPage', 'invalidPage', 'formSection', 'successPage'];
    pages.forEach(function (id) {
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

    var html = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f7fb;padding:20px;font-family:\'Inter\',\'Segoe UI\',sans-serif;">' +
        '<div style="background:#FFFFFF;border:2px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;padding:40px 32px 36px;width:100%;max-width:440px;text-align:center;">' +
        '<div style="width:88px;height:88px;background:#fef3c7;border:2px solid #0F172A;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 22px;box-shadow:3px 3px 0 #0F172A;">' +
        '<i class="fas fa-tools" style="font-size:36px;color:#f59e0b;"></i>' +
        '</div>' +
        '<h1 style="color:#0F172A;font-size:24px;font-weight:900;margin-bottom:8px;letter-spacing:-0.03em;">' + judul + '</h1>' +
        '<p style="color:#64748b;font-size:14px;font-weight:500;margin-bottom:6px;line-height:1.6;">' + pesan + '</p>' +
        '<div style="background:#E0F5FF;color:#0F172A;border:2px solid #0F172A;border-radius:10px;padding:12px 16px;font-weight:700;font-size:13px;box-shadow:2px 2px 0 #0F172A;margin-top:16px;">' + teksEstimasi + '</div></div></div>';

    safeSetHTML(document.body, html);
}

function tampilkanHalamanBlokir() {
    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f7fb;padding:20px;font-family:\'Inter\',sans-serif;">' +
        '<div style="background:#FFFFFF;border:2px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;padding:40px 32px 36px;max-width:440px;width:100%;text-align:center;">' +
        '<div style="width:88px;height:88px;background:#fee2e2;border:2px solid #0F172A;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 22px;box-shadow:3px 3px 0 #0F172A;">' +
        '<i class="fas fa-lock" style="font-size:36px;color:#ef4444;"></i>' +
        '</div>' +
        '<h1 style="color:#0F172A;font-size:24px;font-weight:900;margin-bottom:12px;letter-spacing:-0.03em;">AKSES DITOLAK</h1>' +
        '<p style="color:#64748b;font-size:14px;line-height:1.6;">Akses ditolak, jika ingin dibuka silakan hubungi admin.</p>' +
        '</div></div>';
}

function tampilkanHalamanBanAkses(until) {
    var untilText = sanitize((until || 0) === 0 ? 'PERMANEN' : ('sampai ' + new Date(until).toLocaleString('id-ID')));
    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f7fb;padding:20px;font-family:\'Inter\',sans-serif;">' +
        '<div style="background:#FFFFFF;border:2px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;padding:40px 32px 36px;width:100%;max-width:440px;text-align:center;">' +
        '<div style="width:88px;height:88px;background:#fee2e2;border:2px solid #0F172A;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 22px;box-shadow:3px 3px 0 #0F172A;">' +
        '<i class="fas fa-ban" style="font-size:36px;color:#ef4444;"></i>' +
        '</div>' +
        '<h1 style="color:#0F172A;font-size:24px;font-weight:900;margin-bottom:12px;letter-spacing:-0.03em;">AKSES DIBLOKIR</h1>' +
        '<p style="color:#64748b;font-size:14px;margin-bottom:6px;">Maaf, akses Anda diblokir oleh admin.</p>' +
        '<div style="background:#fef3c7;color:#92400e;border:2px solid #0F172A;border-radius:10px;padding:12px 16px;font-weight:800;font-size:13px;box-shadow:2px 2px 0 #0F172A;margin-top:16px;">Durasi: ' + untilText + '</div>' +
        '</div></div>';
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

async function checkIfBlocked() {
    try {
        var result = await apiGet(API_WEBSITE + '?action=check-blocked');
        if (result && result.blocked) {
            return result;
        }
        return null;
    } catch (e) {
        return null;
    }
}

async function verifyToken() {
    try {
        var result = await apiPost(API_AUTH + '?action=verify-token', {
            token: resetToken
        });
        return result;
    } catch (e) {
        return null;
    }
}

function ensureRecaptchaRendered(attempt) {
    attempt = attempt || 0;
    var box = document.querySelector('#formSection .g-recaptcha');
    if (!box) return;
    if (box.querySelector('iframe')) return;
    if (typeof grecaptcha === 'undefined' || typeof grecaptcha.render !== 'function') {
        if (attempt < 40) setTimeout(function () { ensureRecaptchaRendered(attempt + 1); }, 250);
        return;
    }
    try {
        if (!box.hasAttribute('data-recaptcha-rendered')) {
            grecaptcha.render(box, { sitekey: box.getAttribute('data-sitekey') });
            box.setAttribute('data-recaptcha-rendered', '1');
        }
    } catch (e) {
        if (attempt < 40) setTimeout(function () { ensureRecaptchaRendered(attempt + 1); }, 250);
    }
}

/* ═══ FIX: checkTokenOnLoad — langsung verify token, tidak cek maintenance/blocked dulu ═══ */
async function checkTokenOnLoad() {
    resetToken = getUrlParam('token');

    if (!resetToken || resetToken.length < 10) {
        document.getElementById('headerSubtitle').textContent = 'Link Tidak Valid';
        showPage('invalidPage');
        return;
    }

    showPage('loadingPage');
    if (!fingerprint) fingerprint = await getFingerprint();

    // Langsung verify token, jangan cek maintenance/blocked dulu
    var result = await verifyToken();

    if (result && result.valid) {
        document.getElementById('headerSubtitle').textContent = 'Masukkan password baru Anda';
        showPage('formSection');
        ensureRecaptchaRendered();
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

    try {
        var maintenance = await periksaMaintenance();
        if (maintenance) {
            setButtonLoading(false);
            tampilkanHalamanMaintenance(maintenance);
            return;
        }

        var blockData = await checkIfBlocked();
        if (blockData && blockData.blockType === 'ban_akses') {
            setButtonLoading(false);
            tampilkanHalamanBanAkses(blockData.banAksesUntil || 0);
            return;
        }
        if (blockData && blockData.blocked) {
            setButtonLoading(false);
            tampilkanHalamanBlokir();
            return;
        }

        var result = await apiPost(API_AUTH + '?action=confirm-reset', {
            token: resetToken,
            newPassword: newPassword,
            captchaToken: captchaResponse
        });

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
            Swal.fire({ icon: "error", title: "Gagal!", text: (result && result.message) || "Terjadi kesalahan. Coba lagi nanti.", confirmButtonColor: "#ef4444" });
            if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
        }

    } catch (e) {
        setButtonLoading(false);
        Swal.fire({ icon: "error", title: "Error!", text: "Gagal menghubungkan ke server!", confirmButtonColor: "#ef4444" });
    }
}

document.addEventListener('DOMContentLoaded', async function () {
    if (!fingerprint) fingerprint = await getFingerprint();

    document.getElementById('newPassword').addEventListener('input', updatePasswordStrength);
    document.getElementById('confirmPassword').addEventListener('keypress', function (e) {
        if (e.key === 'Enter') confirmReset();
    });

    document.querySelectorAll('.toggle-eye').forEach(function (el) {
        el.addEventListener('click', function () {
            var target = document.getElementById(this.getAttribute('data-target'));
            if (!target) return;
            var isText = target.type === 'text';
            target.type = isText ? 'password' : 'text';
            this.classList.toggle('fa-eye', !isText);
            this.classList.toggle('fa-eye-slash', isText);
        });
    });

    checkTokenOnLoad();
});