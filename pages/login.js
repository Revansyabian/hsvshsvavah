// pages/login.js
var API_BASE = '/api';
var API_WEBSITE = '/api/webtopupbussid';
var API_AUTH = '/api/auth';
var WHATSAPP_NUMBER = "6285199120995";
var MAX_PASSWORD_LENGTH = 20;

var currentUser = null;
var fingerprint = '';
var fpSignature = '';
var alertTimeout = null;
var isBlocked = false;
var blockedChecked = false;
var loginInProgress = false;

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

function sanitize(str) {
  if (!str) return '';
  return String(str).replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
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

async function getSignedFingerprint() {
  if (!fingerprint) fingerprint = await getFingerprint();
  if (fpSignature) return { fp: fingerprint, sig: fpSignature };

  try {
    const res = await fetch(API_AUTH + '?action=sign-fp', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fp: fingerprint })
    });
    const data = await res.json();
    if (data && data.success && data.sig) {
      fpSignature = data.sig;
      return { fp: fingerprint, sig: fpSignature };
    }
  } catch (e) {}
  return { fp: fingerprint, sig: '' };
}

async function apiGet(url) {
  const { fp, sig } = await getSignedFingerprint();
  const headers = { 'X-Fingerprint': fp };
  if (sig) headers['X-FP-Sig'] = sig;

  var res = await fetch(url, {
    method: 'GET',
    credentials: 'same-origin',
    headers,
    cache: 'no-store'
  });
  var text = await res.text();
  if (!text || text === 'null') return null;
  try { return JSON.parse(text); } catch { return null; }
}

async function apiPost(url, body) {
  const { fp, sig } = await getSignedFingerprint();
  const headers = { 'Content-Type': 'application/json', 'X-Fingerprint': fp };
  if (sig) headers['X-FP-Sig'] = sig;

  var res = await fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers,
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

async function checkIfBlocked() {
  if (blockedChecked) return isBlocked;
  try {
    var result = await apiGet(API_WEBSITE + '?action=check-blocked');
    isBlocked = !!(result && result.blocked);
    blockedChecked = true;
  } catch (e) {
    isBlocked = false;
    blockedChecked = true;
  }
  return isBlocked;
}

function tampilkanHalamanMaintenance(dataMaintenance) {
  var judul = sanitize(dataMaintenance?.title || 'SEDANG PERBAIKAN SISTEM');
  var pesan = sanitize(dataMaintenance?.message || 'Website sedang dalam perbaikan.');
  var sampai = dataMaintenance?.until || null;
  var teksEstimasi = sanitize(sampai ? 'Estimasi selesai: ' + new Date(sampai).toLocaleString('id-ID') : 'Mohon maaf atas ketidaknyamanan ini.');
  document.body.innerHTML = `<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#f4f7fb;font-family:'Inter',sans-serif;">
    <div style="background:#fff;border:2px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;padding:40px 32px;width:100%;max-width:440px;text-align:center;">
      <div style="width:88px;height:88px;background:#fef3c7;border:2px solid #0F172A;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 22px;box-shadow:3px 3px 0 #0F172A;">
        <i class="fas fa-tools" style="font-size:36px;color:#f59e0b;"></i>
      </div>
      <h1 style="color:#0F172A;font-size:24px;font-weight:900;margin:0 0 10px;">${judul}</h1>
      <p style="color:#64748b;font-size:14px;margin:0 0 22px;">${pesan}</p>
      <div style="background:#E0F5FF;color:#0F172A;border:2px solid #0F172A;border-radius:10px;padding:12px 16px;font-weight:700;font-size:13px;box-shadow:2px 2px 0 #0F172A;">${teksEstimasi}</div>
    </div></div>`;
}

function tampilkanHalamanBlokir() {
  document.body.innerHTML = `<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#f4f7fb;font-family:'Inter',sans-serif;">
    <div style="background:#fff;border:2px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;padding:40px 32px;width:100%;max-width:440px;text-align:center;">
      <div style="width:88px;height:88px;background:#fee2e2;border:2px solid #0F172A;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 22px;box-shadow:3px 3px 0 #0F172A;">
        <i class="fas fa-lock" style="font-size:36px;color:#ef4444;"></i>
      </div>
      <h1 style="color:#0F172A;font-size:24px;font-weight:900;margin:0 0 12px;">AKSES DITOLAK</h1>
      <p style="color:#64748b;font-size:14px;">Maaf, akses Anda diblokir. Hubungi admin.</p>
    </div></div>`;
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

async function autoCheckSession() {
  try {
    storageRemove('sesi_pengguna');

    const { fp, sig } = await getSignedFingerprint();
    const headers = { 'X-Fingerprint': fp };
    if (sig) headers['X-FP-Sig'] = sig;

    const res = await fetch(API_BASE + '/user?action=check-status', {
      method: 'GET',
      credentials: 'same-origin',
      headers,
      cache: 'no-store'
    });

    if (res.status !== 200) return;

    const data = await res.json();
    if (data && data.valid && data.user) {
      window.location.href = '/pages/dashboard';
    }
  } catch (e) {}
}

async function waitForSessionCommit(maxAttempts) {
  maxAttempts = maxAttempts || 10;
  for (var i = 0; i < maxAttempts; i++) {
    try {
      const { fp, sig } = await getSignedFingerprint();
      const headers = { 'X-Fingerprint': fp };
      if (sig) headers['X-FP-Sig'] = sig;

      const res = await fetch(API_BASE + '/user?action=check-status', {
        method: 'GET',
        credentials: 'same-origin',
        headers,
        cache: 'no-store'
      });

      if (res.status === 200) {
        const data = await res.json();
        if (data && data.valid && data.user) return data.user;
      }
    } catch (e) {}

    await new Promise(function (r) { setTimeout(r, 300); });
  }
  return null;
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

    var username = document.getElementById('username').value.trim();
    var password = document.getElementById('password').value.trim();

    if (!username || !password) {
      Swal.fire({ icon: "warning", title: "Oops...", text: "Harap isi username dan password!", confirmButtonColor: "#0ea5e9" });
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

    storageRemove('sesi_pengguna');
    storageRemove('admin_current');
    storageRemove('session_start');

    var result = await apiPost(API_AUTH + '?action=login', {
      username: username,
      password: password,
      captchaToken: captchaResponse
    });

    if (result && result.error === 'blocked') {
      hideLoading();
      tampilkanHalamanBlokir();
      loginInProgress = false;
      return;
    }

    if (result && result.error === 'use_admin_page') {
      hideLoading();
      try { grecaptcha.reset(); } catch (e) {}
      await Swal.fire({
        icon: 'info',
        title: 'Login Admin',
        html: '<p>Akun ini terdaftar sebagai <b>Admin</b>.</p><p>Silakan login di halaman admin.</p>',
        confirmButtonText: 'Ke Halaman Admin',
        confirmButtonColor: '#0ea5e9',
        allowOutsideClick: false
      });
      window.location.href = '/admin';
      loginInProgress = false;
      return;
    }

    if (result && result.error === 'no_expiry') {
      hideLoading();
      try { grecaptcha.reset(); } catch (e) {}
      await Swal.fire({
        icon: 'error',
        title: 'Masa Aktif Tidak Valid',
        text: result.message || 'Masa aktif akun tidak di-set. Hubungi admin.',
        confirmButtonColor: '#ef4444'
      });
      loginInProgress = false;
      return;
    }

    if (result && result.error === 'bad_expiry') {
      hideLoading();
      try { grecaptcha.reset(); } catch (e) {}
      await Swal.fire({
        icon: 'error',
        title: 'Masa Aktif Tidak Valid',
        text: result.message || 'Format masa aktif rusak. Hubungi admin.',
        confirmButtonColor: '#ef4444'
      });
      loginInProgress = false;
      return;
    }

    if (result && result.error === 'expired') {
      hideLoading();
      try { grecaptcha.reset(); } catch (e) {}
      await Swal.fire({
        icon: 'warning',
        title: 'Masa Aktif Habis',
        text: result.message || 'Hubungi admin untuk perpanjang.',
        confirmButtonColor: '#f59e0b'
      });
      loginInProgress = false;
      return;
    }

    if (result && result.banned) {
      hideLoading();
      Swal.fire({
        icon: 'error',
        title: 'AKUN DIBANNED',
        text: 'Durasi: ' + ((result.bannedUntil || 0) === 0 ? 'PERMANEN' : 'sampai ' + new Date(result.bannedUntil).toLocaleString('id-ID')),
        confirmButtonColor: '#ef4444'
      });
      loginInProgress = false;
      return;
    }

    if (result && result.banAkses) {
      hideLoading();
      Swal.fire({
        icon: 'error',
        title: 'AKSES DIBLOKIR',
        text: 'Hubungi admin.',
        confirmButtonColor: '#ef4444'
      });
      loginInProgress = false;
      return;
    }

    if (result && result.forceLogout) {
      hideLoading();
      Swal.fire({
        icon: 'warning',
        title: 'AKUN DITANGGUHKAN',
        text: 'Hubungi admin.',
        confirmButtonColor: '#f59e0b'
      });
      loginInProgress = false;
      return;
    }

    if (result && result.error === 'pending_activation') {
      hideLoading();
      Swal.fire({ icon: 'warning', title: 'AKUN BELUM AKTIF', text: 'Hubungi admin untuk aktivasi.', confirmButtonColor: '#0ea5e9' });
      try { grecaptcha.reset(); } catch (e) {}
      loginInProgress = false;
      return;
    }

    if (result && result.error === 'rejected') {
      hideLoading();
      Swal.fire({ icon: 'error', title: 'AKUN DITOLAK', text: 'Akun Anda ditolak admin.', confirmButtonColor: '#ef4444' });
      try { grecaptcha.reset(); } catch (e) {}
      loginInProgress = false;
      return;
    }

    if (result && result.error === 'captcha_failed') {
      hideLoading();
      Swal.fire({ icon: 'error', title: 'reCAPTCHA Gagal', text: 'Coba lagi.', confirmButtonColor: '#ef4444' });
      try { grecaptcha.reset(); } catch (e) {}
      loginInProgress = false;
      return;
    }

    if (result && result.success) {
      var sessionUser = await waitForSessionCommit(12);

      if (!sessionUser) {
        hideLoading();
        Swal.fire({
          icon: "error",
          title: "Sesi Gagal",
          text: "Login berhasil tapi sesi gagal tersimpan. Coba lagi.",
          confirmButtonColor: "#ef4444"
        });
        try { grecaptcha.reset(); } catch (e) {}
        loginInProgress = false;
        return;
      }

      hideLoading();
      Swal.fire({
        icon: "success",
        title: "Login Berhasil!",
        text: "Selamat datang, " + (sessionUser.username || username) + "!",
        timer: 1200,
        showConfirmButton: false
      }).then(function () {
        window.location.href = '/pages/dashboard';
      });
      return;
    }

    hideLoading();
    try { grecaptcha.reset(); } catch (e) {}
    Swal.fire({
      icon: "error",
      title: "Login Gagal",
      text: (result && result.message) || 'Username atau password salah!',
      confirmButtonColor: "#ef4444"
    });
  } catch (error) {
    hideLoading();
    try { grecaptcha.reset(); } catch (e) {}
    Swal.fire({ icon: "error", title: "Error", text: "Gagal menghubungkan ke server!", confirmButtonColor: "#ef4444" });
  }
  loginInProgress = false;
}

document.addEventListener('DOMContentLoaded', async function () {
  if (!fingerprint) fingerprint = await getFingerprint();

  await autoCheckSession();

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
        if (hideTimeout) { clearTimeout(hideTimeout); hideTimeout = null; }
      }
    });
    passwordInput.addEventListener('blur', function () {
      if (this.getAttribute('type') === 'text') {
        this.setAttribute('type', 'password');
        togglePassword.classList.remove('fa-eye');
        togglePassword.classList.add('fa-eye-slash');
        if (hideTimeout) { clearTimeout(hideTimeout); hideTimeout = null; }
      }
    });
  }
});