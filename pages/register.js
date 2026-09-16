var API_REGISTER = '/api/register';
var API_SECRET = '1417-1426-1527-1517';
var WHATSAPP_NUMBER = '6285199120995';
var fingerprint = '';
var registerInProgress = false;
var selectedPaket = '';
var selectedHarga = 0;
var sessionFingerprint = CryptoJS.MD5(Date.now() + Math.random() + navigator.userAgent).toString();
var lastSubmitTime = 0;
var SUBMIT_COOLDOWN = 3000;
var FORBIDDEN_USERNAMES = ['admin', 'administrator', 'root', 'system', 'owner', 'moderator', 'staff', 'support', 'ceo', 'boss'];
var THROWAWAY_DOMAINS = ['mailinator.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com', 'yopmail.com', 'tempmail.net', 'dispostable.com'];
var COMMON_PASSWORDS = ['password', 'password123', '12345678', 'qwerty123', 'admin123', 'bismillah', 'sayang', 'cinta'];
var KEYBOARD_PATTERNS = ['asdf', 'qwer', 'zxcv', 'tyui', 'ghjk', 'bnm', 'poiuy', 'lkjh', 'mnbv'];
var SEQUENTIAL_PATTERNS = ['123456', '654321', 'abcdef', 'qwerty', '111111', '222222', '333333'];
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
    return CryptoJS.MD5(fp).toString();
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
        .replace(/=/g, '&#61;')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .replace(/<script/gi, '')
        .replace(/<\/script/gi, '')
        .replace(/<img/gi, '')
        .replace(/<svg/gi, '')
        .replace(/<iframe/gi, '');
}
function isSequentialPassword(password) {
    for (var i = 0; i < SEQUENTIAL_PATTERNS.length; i++) {
        if (password.toLowerCase().includes(SEQUENTIAL_PATTERNS[i])) return true;
    }
    return false;
}
function isCommonPassword(password) {
    for (var i = 0; i < COMMON_PASSWORDS.length; i++) {
        if (password.toLowerCase() === COMMON_PASSWORDS[i]) return true;
    }
    return false;
}
function isKeyboardSmash(password) {
    for (var i = 0; i < KEYBOARD_PATTERNS.length; i++) {
        if (password.toLowerCase().includes(KEYBOARD_PATTERNS[i])) return true;
    }
    return false;
}
function hasRepeatingChars(password) {
    for (var i = 0; i < password.length - 2; i++) {
        if (password[i] === password[i + 1] && password[i] === password[i + 2]) return true;
    }
    return false;
}
function validatePasswordComplexity(password) {
    var hasUpperCase = /[A-Z]/.test(password);
    var hasLowerCase = /[a-z]/.test(password);
    var hasNumber = /\d/.test(password);
    return hasUpperCase && hasLowerCase && hasNumber;
}
function isThrowawayEmail(email) {
    var parts = email.split('@');
    if (parts.length !== 2) return false;
    return THROWAWAY_DOMAINS.includes(parts[1].toLowerCase());
}
function isValidIndonesianPhone(phone) {
    var cleaned = phone.replace(/[^0-9]/g, '');
    if (cleaned.startsWith('0')) return cleaned.length >= 10 && cleaned.length <= 13;
    if (cleaned.startsWith('62')) return cleaned.length >= 11 && cleaned.length <= 14;
    return false;
}
function isValidUserAgent() {
    var ua = navigator.userAgent;
    if (ua.includes('Headless') || ua.includes('PhantomJS') || ua.includes('puppeteer') || ua.includes('Playwright')) return false;
    return true;
}
function isValidScreenSize() {
    if (screen.width === 0 || screen.height === 0) return false;
    if (screen.width < 320 || screen.height < 480) return false;
    return true;
}
function checkBrowserRateLimit() {
    var blockedUntil = localStorage.getItem('register_blocked_until');
    if (blockedUntil) {
        var timeLeft = parseInt(blockedUntil) - Date.now();
        if (timeLeft > 0) {
            var minutes = Math.ceil(timeLeft / 60000);
            Swal.fire({ icon: "error", title: "Terlalu Banyak Percobaan!", text: "Coba lagi dalam " + minutes + " menit.", confirmButtonColor: "#ef4444" });
            return false;
        } else {
            localStorage.removeItem('register_blocked_until');
            localStorage.removeItem('register_attempts');
        }
    }
    return true;
}
function recordRegisterAttempt() {
    var attempts = parseInt(localStorage.getItem('register_attempts') || '0') + 1;
    localStorage.setItem('register_attempts', attempts);
    if (attempts >= 3) {
        localStorage.setItem('register_blocked_until', Date.now() + 3600000);
        localStorage.removeItem('register_attempts');
        Swal.fire({ icon: "error", title: "Diblokir 1 Jam!", text: "Terlalu banyak percobaan gagal.", confirmButtonColor: "#ef4444" });
    }
}
function resetRegisterAttempts() {
    localStorage.removeItem('register_attempts');
    localStorage.removeItem('register_blocked_until');
}
function updateStrengthBar(inputId, barId) {
    var value = document.getElementById(inputId).value;
    var bar = document.getElementById(barId);
    bar.className = 'password-strength-bar';
    if (value.length === 0) {
        bar.style.width = '0%';
    } else if (value.length < 6) {
        bar.className = 'password-strength-bar strength-weak';
        bar.style.width = '33%';
    } else if (value.length < 10) {
        bar.className = 'password-strength-bar strength-medium';
        bar.style.width = '66%';
    } else {
        bar.className = 'password-strength-bar strength-strong';
        bar.style.width = '100%';
    }
}
function updatePasswordStrength() {
    updateStrengthBar('password', 'passwordStrengthBar');
}
function updateConfirmPasswordStrength() {
    updateStrengthBar('confirmPassword', 'confirmPasswordStrengthBar');
}
function validateConfirmPasswordComplexity() {
    var confirmPassword = document.getElementById('confirmPassword').value;
    if (confirmPassword.length === 0) return;
    if (!validatePasswordComplexity(confirmPassword)) {
        Swal.fire({ icon: "warning", title: "Password Lemah!", text: "Password harus ada huruf BESAR, kecil, dan angka!", confirmButtonColor: "#0ea5e9" });
    }
}
function showError(msg) {
    document.getElementById('errorText').textContent = msg;
    document.getElementById('errorMessage').classList.add('show');
}
function hideError() {
    document.getElementById('errorMessage').classList.remove('show');
}
function toggleSubmitButton() {
    var check = document.getElementById('verificationCheck');
    var btn = document.getElementById('btnRegister');
    var hasPaket = selectedPaket !== '';
    btn.disabled = !(check.checked && hasPaket);
}
function togglePaketList() {
    var list = document.getElementById('paketList');
    var select = document.getElementById('paketSelect');
    if (list) {
        list.classList.toggle('show');
        if (select) select.classList.toggle('active');
    }
}
function selectPaketOption(option) {
    selectedPaket = option.getAttribute('data-paket');
    selectedHarga = parseInt(option.getAttribute('data-harga'));
    document.querySelectorAll('.paket-option').forEach(function (o) { o.classList.remove('selected'); });
    option.classList.add('selected');
    var placeholder = document.getElementById('paketPlaceholder');
    if (placeholder) {
        placeholder.textContent = selectedPaket + ' - Rp ' + selectedHarga.toLocaleString();
        placeholder.className = 'selected-text';
    }
    var select = document.getElementById('paketSelect');
    var list = document.getElementById('paketList');
    if (select) select.classList.remove('active');
    if (list) list.classList.remove('show');
    toggleSubmitButton();
}
document.addEventListener('click', function (e) {
    var dropdown = document.getElementById('paketDropdown');
    if (dropdown && !dropdown.contains(e.target)) {
        var select = document.getElementById('paketSelect');
        var list = document.getElementById('paketList');
        if (select) select.classList.remove('active');
        if (list) list.classList.remove('show');
    }
});
function validateUsernameInput() {
    var input = document.getElementById('username');
    var value = input.value;
    var cleaned = value.replace(/\s/g, '').replace(/[^a-zA-Z0-9_.]/g, '');
    if (value !== cleaned) {
        input.value = cleaned;
        Swal.fire({ icon: "warning", title: "Simbol Tidak Diizinkan!", timer: 2000, showConfirmButton: false });
    }
}
function validatePhoneInput() {
    var input = document.getElementById('phone');
    var value = input.value;
    var cleaned = value.replace(/[^0-9+]/g, '');
    if (value !== cleaned) {
        input.value = cleaned;
        Swal.fire({ icon: "warning", title: "Karakter Tidak Valid!", timer: 2000, showConfirmButton: false });
    }
}
function validateEmailInput() {
    var input = document.getElementById('email');
    var value = input.value;
    var cleaned = value.replace(/\s/g, '');
    if (value !== cleaned) input.value = cleaned;
}
function setButtonLoading(loading) {
    var btn = document.getElementById('btnRegister');
    btn.disabled = loading;
    btn.innerHTML = loading ? '<i class="fas fa-spinner fa-spin"></i> MEMPROSES...' : '<i class="fas fa-user-plus"></i> DAFTAR';
}
function encryptData(data) {
    try {
        var jsonStr = JSON.stringify(data);
        return CryptoJS.AES.encrypt(jsonStr, API_SECRET).toString();
    } catch (error) {
        console.error('Encryption error:', error);
        return null;
    }
}
function decryptData(encrypted) {
    try {
        var bytes = CryptoJS.AES.decrypt(encrypted, API_SECRET);
        var decrypted = bytes.toString(CryptoJS.enc.Utf8);
        return JSON.parse(decrypted);
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}
async function callRegisterApi(action, data) {
    var payload = { action: action };
    if (data) {
        for (var key in data) {
            if (Object.prototype.hasOwnProperty.call(data, key)) {
                payload[key] = data[key];
            }
        }
    }
    payload.timestamp = Date.now();
    var encryptedPayload = encryptData(payload);
    if (!encryptedPayload) throw new Error('Gagal mengenkripsi');
    var res = await fetch(API_REGISTER, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Fingerprint': fingerprint
        },
        body: JSON.stringify({ data: encryptedPayload })
    });
    if (res.status === 429) throw new Error('Terlalu banyak percobaan');
    var text = await res.text();
    if (!text || text === 'null') return null;
    var result = JSON.parse(text);
    if (result && result.data) {
        try {
            var dec = decryptData(result.data);
            if (dec) return dec;
        } catch (e) {
            return null;
        }
    }
    return result;
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
async function checkMaintenanceAndBlock() {
    try {
        var result = await callRegisterApi('check_status', {});
        if (result && result.blocked === true) {
            tampilkanHalamanBlokir();
            return true;
        }
        if (result && result.maintenance === true) {
            tampilkanHalamanMaintenance(result);
            return true;
        }
        return false;
    } catch (e) {
        console.error('Error checking maintenance/block:', e);
        return false;
    }
}
async function register() {
    if (registerInProgress) return;
    registerInProgress = true;
    hideError();
    try {
        if (!isValidUserAgent() || !isValidScreenSize()) {
            Swal.fire({ icon: "error", title: "Browser Tidak Valid!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        var now = Date.now();
        if (now - lastSubmitTime < SUBMIT_COOLDOWN) {
            Swal.fire({ icon: "warning", title: "Terlalu Cepat!", text: "Tunggu 3 detik.", confirmButtonColor: "#0ea5e9" });
            registerInProgress = false;
            return;
        }
        lastSubmitTime = now;
        var honeypot = document.getElementById('website').value;
        if (honeypot) {
            Swal.fire({ icon: "error", title: "Bot Detected!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (!checkBrowserRateLimit()) {
            registerInProgress = false;
            return;
        }
        var blockedOrMaintenance = await checkMaintenanceAndBlock();
        if (blockedOrMaintenance) {
            registerInProgress = false;
            return;
        }
        var username = document.getElementById('username').value.trim();
        var password = document.getElementById('password').value;
        var confirmPassword = document.getElementById('confirmPassword').value.trim();
        var phone = document.getElementById('phone').value.trim();
        var email = document.getElementById('email').value.trim();
        if (!username || username.length < 3) {
            Swal.fire({ icon: "warning", title: "Username Tidak Valid!", text: "Username minimal 3 karakter!", confirmButtonColor: "#0ea5e9" });
            registerInProgress = false;
            return;
        }
        if (username.length > 20) {
            Swal.fire({ icon: "warning", title: "Username Tidak Valid!", text: "Username maksimal 20 karakter!", confirmButtonColor: "#0ea5e9" });
            registerInProgress = false;
            return;
        }
        if (!/^[a-zA-Z0-9_.]+$/.test(username)) {
            Swal.fire({ icon: "error", title: "Simbol Tidak Diizinkan!", text: "Username hanya boleh huruf, angka, underscore (_), dan titik (.)", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        var lowerUsername = username.toLowerCase();
        for (var i = 0; i < FORBIDDEN_USERNAMES.length; i++) {
            if (lowerUsername.includes(FORBIDDEN_USERNAMES[i])) {
                Swal.fire({ icon: "error", title: "Username Tidak Diizinkan!", text: "Username mengandung kata terlarang!", confirmButtonColor: "#ef4444" });
                registerInProgress = false;
                return;
            }
        }
        if (!password || password.length < 6) {
            Swal.fire({ icon: "warning", title: "Password Terlalu Pendek!", text: "Password minimal 6 karakter!", confirmButtonColor: "#0ea5e9" });
            registerInProgress = false;
            return;
        }
        if (password.toLowerCase() === username.toLowerCase()) {
            Swal.fire({ icon: "error", title: "Password Lemah!", text: "Password tidak boleh sama dengan username!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (!validatePasswordComplexity(password)) {
            Swal.fire({ icon: "error", title: "Password Lemah!", text: "Password harus ada huruf BESAR, kecil, dan angka!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (isSequentialPassword(password)) {
            Swal.fire({ icon: "error", title: "Password Terlalu Mudah!", text: "Password sequential tidak diizinkan!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (isCommonPassword(password)) {
            Swal.fire({ icon: "error", title: "Password Terlalu Umum!", text: "Password terlalu umum!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (isKeyboardSmash(password)) {
            Swal.fire({ icon: "error", title: "Password Terlalu Mudah!", text: "Password keyboard pattern tidak diizinkan!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (hasRepeatingChars(password)) {
            Swal.fire({ icon: "error", title: "Password Terlalu Mudah!", text: "Password berulang tidak diizinkan!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (password !== confirmPassword) {
            Swal.fire({ icon: "error", title: "Password Tidak Cocok!", text: "Password dan konfirmasi harus sama!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (!phone || phone.length < 10) {
            Swal.fire({ icon: "warning", title: "Nomor Tidak Valid!", text: "Nomor telepon minimal 10 digit!", confirmButtonColor: "#0ea5e9" });
            registerInProgress = false;
            return;
        }
        if (!isValidIndonesianPhone(phone)) {
            Swal.fire({ icon: "error", title: "Nomor Tidak Valid!", text: "Gunakan nomor Indonesia (08xx / +62xx)!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (!email || !email.includes('@')) {
            Swal.fire({ icon: "error", title: "Email Tidak Valid!", text: "Email wajib mengandung @!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            Swal.fire({ icon: "error", title: "Email Tidak Valid!", text: "Format email tidak valid!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (isThrowawayEmail(email)) {
            Swal.fire({ icon: "error", title: "Email Tidak Diizinkan!", text: "Gunakan email asli!", confirmButtonColor: "#ef4444" });
            registerInProgress = false;
            return;
        }
        if (!selectedPaket) {
            Swal.fire({ icon: "warning", title: "Paket Belum Dipilih!", text: "Pilih paket terlebih dahulu!", confirmButtonColor: "#0ea5e9" });
            registerInProgress = false;
            return;
        }
        if (!document.getElementById('verificationCheck').checked) {
            Swal.fire({ icon: "warning", title: "Verifikasi Diperlukan!", text: "Centang verifikasi aktivasi!", confirmButtonColor: "#0ea5e9" });
            registerInProgress = false;
            return;
        }
        var captchaResponse = '';
        if (typeof grecaptcha !== 'undefined') {
            captchaResponse = grecaptcha.getResponse();
        }
        if (!captchaResponse || captchaResponse.length === 0) {
            Swal.fire({ icon: "warning", title: "reCAPTCHA Diperlukan!", text: "Centang \"I'm not a robot\" dulu ya!", confirmButtonColor: "#0ea5e9" });
            registerInProgress = false;
            return;
        }
        setButtonLoading(true);
        if (!fingerprint) fingerprint = await getFingerprint();
        var userIP = 'unknown';
        try {
            var ipRes = await fetch('https://api.ipify.org?format=json');
            var ipData = await ipRes.json();
            userIP = ipData.ip || 'unknown';
        } catch (e) {}
        var result = await callRegisterApi('register', {
            username: username,
            password: password,
            confirmPassword: confirmPassword,
            phone: phone,
            email: email,
            paket: selectedPaket,
            harga: selectedHarga,
            ip: userIP,
            fingerprint: fingerprint,
            sessionFingerprint: sessionFingerprint,
            captchaToken: captchaResponse
        });
        setButtonLoading(false);
        if (result && result.success) {
            resetRegisterAttempts();
            var waMessage = 'Assalamualaikum min, tolong aktivasi akun saya%0A%0AUsername: ' + encodeURIComponent(username) + '%0APaket: ' + encodeURIComponent(selectedPaket) + '%0AHarga: Rp ' + selectedHarga.toLocaleString() + '%0AEmail: ' + encodeURIComponent(email) + '%0ANo. HP: ' + encodeURIComponent(phone);
            window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=' + waMessage, '_blank');
            Swal.fire({ icon: "success", title: "Pendaftaran Berhasil!", timer: 3000, showConfirmButton: false }).then(function () {
                window.location.href = '/';
            });
        } else {
            recordRegisterAttempt();
            var errorMsg = 'Terjadi kesalahan. Coba lagi.';
            if (result && result.error === 'ip_limit') {
                errorMsg = 'Maaf, kamu sudah mendaftar sebelumnya.';
            } else if (result && result.error === 'fp_limit') {
                errorMsg = 'Maaf, kamu sudah mendaftar sebelumnya.';
            } else if (result && result.error === 'username_exists') {
                errorMsg = 'Username sudah terdaftar!';
            } else if (result && result.error === 'email_exists') {
                errorMsg = 'Email sudah terdaftar!';
            } else if (result && result.error === 'maintenance') {
                errorMsg = 'Website sedang dalam perbaikan.';
            } else if (result && result.error === 'access_denied') {
                errorMsg = 'Akses Anda diblokir.';
            } else if (result && result.message) {
                errorMsg = result.message;
            }
            Swal.fire({ icon: "error", title: "Gagal!", text: errorMsg, confirmButtonColor: "#ef4444" });
            if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
        }
    } catch (error) {
        setButtonLoading(false);
        Swal.fire({ icon: "error", title: "Error!", text: "Gagal menghubungkan ke server!", confirmButtonColor: "#ef4444" });
        if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
    }
    registerInProgress = false;
}
document.addEventListener('DOMContentLoaded', async function () {
    if (!fingerprint) fingerprint = await getFingerprint();
    var blockedOrMaintenance = await checkMaintenanceAndBlock();
    if (blockedOrMaintenance) {
        return;
    }
    document.getElementById('password').addEventListener('input', updatePasswordStrength);
    document.getElementById('confirmPassword').addEventListener('input', updateConfirmPasswordStrength);
    document.getElementById('confirmPassword').addEventListener('blur', validateConfirmPasswordComplexity);
    document.getElementById('confirmPassword').addEventListener('paste', function (e) { e.preventDefault(); Swal.fire({ icon: "warning", title: "Paste Tidak Diizinkan!", timer: 2000, showConfirmButton: false }); });
    document.getElementById('password').addEventListener('copy', function (e) { e.preventDefault(); Swal.fire({ icon: "warning", title: "Copy Tidak Diizinkan!", timer: 2000, showConfirmButton: false }); });
    document.getElementById('username').addEventListener('input', function () {
        var input = document.getElementById('username');
        var value = input.value;
        var cleaned = value.replace(/\s/g, '').replace(/[^a-zA-Z0-9_.]/g, '');
        if (value !== cleaned) {
            input.value = cleaned;
        }
    });
    document.getElementById('password').addEventListener('keypress', function (e) { if (e.key === 'Enter') document.getElementById('confirmPassword').focus(); });
    document.getElementById('confirmPassword').addEventListener('keypress', function (e) { if (e.key === 'Enter') document.getElementById('phone').focus(); });
    document.getElementById('phone').addEventListener('keypress', function (e) { if (e.key === 'Enter') document.getElementById('email').focus(); });
    document.getElementById('email').addEventListener('keypress', function (e) { if (e.key === 'Enter') register(); });
});
