const API = '/api/admin';
let usersCache = [];
let currentAdmin = null;
let shareCheckInterval = null;
let sessionTimerInterval = null;
let sessionExpiresAt = 0;

const StorageVault = (function () {
  'use strict';
  const PREFIX = '__sv_';
  const KEY_ENDPOINT = '/api/admin?action=storage-key';
  let _key = null;
  let _keyPromise = null;

  function _fp() {
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

  function _getCSRF() {
    const v = document.cookie.split('; ').find(r => r.startsWith('csrf_token='));
    return v ? decodeURIComponent(v.split('=')[1]) : '';
  }

  async function _fetchKey() {
    if (_key) return _key;
    if (_keyPromise) return _keyPromise;
    _keyPromise = (async () => {
      try {
        const fp = _fp();
        const res = await fetch(KEY_ENDPOINT, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json', 'X-Fingerprint': fp, 'X-CSRF-Token': _getCSRF() },
          body: JSON.stringify({})
        });
        if (!res.ok) return null;
        const data = await res.json();
        if (!data.success || !data.storageKey) return null;
        _key = CryptoJS.SHA256(data.storageKey + '|' + fp).toString();
        return _key;
      } catch (e) { return null; }
      finally { _keyPromise = null; }
    })();
    return _keyPromise;
  }

  function _enc(plaintext, key) {
    const iv = CryptoJS.lib.WordArray.random(16);
    const e = CryptoJS.AES.encrypt(plaintext, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return 'sv1.' + iv.toString(CryptoJS.enc.Base64) + '.' + e.ciphertext.toString(CryptoJS.enc.Base64);
  }

  function _dec(ciphertext, key) {
    if (!ciphertext || typeof ciphertext !== 'string' || !ciphertext.startsWith('sv1.')) return null;
    try {
      const parts = ciphertext.split('.');
      const iv = CryptoJS.enc.Base64.parse(parts[1]);
      const ct = CryptoJS.enc.Base64.parse(parts[2]);
      const cp = CryptoJS.lib.CipherParams.create({ ciphertext: ct });
      const d = CryptoJS.AES.decrypt(cp, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      const out = d.toString(CryptoJS.enc.Utf8);
      return out || null;
    } catch (e) { return null; }
  }

  return {
    async set(key, value) {
      try {
        const k = await _fetchKey();
        if (!k) return false;
        const plain = typeof value === 'string' ? value : JSON.stringify(value);
        window.localStorage.setItem(PREFIX + key, _enc(plain, k));
        return true;
      } catch (e) { return false; }
    },
    async get(key) {
      try {
        const raw = window.localStorage.getItem(PREFIX + key);
        if (!raw) return null;
        const k = await _fetchKey();
        if (!k) return null;
        const d = _dec(raw, k);
        if (!d) return null;
        try { return JSON.parse(d); }
        catch { return d; }
      } catch (e) { return null; }
    },
    remove(key) { window.localStorage.removeItem(PREFIX + key); },
    has(key) { return window.localStorage.getItem(PREFIX + key) !== null; },
    clear() {
      const keys = [];
      for (let i = 0; i < window.localStorage.length; i++) {
        const k = window.localStorage.key(i);
        if (k && k.startsWith(PREFIX)) keys.push(k);
      }
      keys.forEach(k => window.localStorage.removeItem(k));
    },
    async refreshKey() { _key = null; _keyPromise = null; return _fetchKey(); }
  };
})();

const $ = id => document.getElementById(id);
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

/* ─── Neo-Brut Swal Helper ─── */
const NEO_INPUT_STYLE = 'width:100%;padding:12px 14px;border:2px solid #0F172A;border-radius:10px;font-size:14px;font-weight:600;background:#fff;box-shadow:2px 2px 0 #0F172A;outline:none;font-family:inherit';
const NEO_SELECT_STYLE = 'width:100%;padding:12px 14px;border:2px solid #0F172A;border-radius:10px;font-size:14px;font-weight:600;background:#fff;box-shadow:2px 2px 0 #0F172A;outline:none;font-family:inherit;cursor:pointer';

const SwalTheme = {
  confirmButtonColor: '#00BFFF',
  cancelButtonColor: '#64748b',
  buttonsStyling: true,
  customClass: {
    popup: 'neo-swal-popup',
    title: 'neo-swal-title',
    htmlContainer: 'neo-swal-html',
    confirmButton: 'neo-swal-btn',
    cancelButton: 'neo-swal-btn-cancel'
  }
};

function toast(title, text = '', icon = 'success') {
  if (!window.Swal) return alert(title);
  return Swal.fire({
    ...SwalTheme,
    icon, title, text,
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 2600,
    timerProgressBar: true,
    didOpen: (t) => {
      t.addEventListener('mouseenter', Swal.stopTimer);
      t.addEventListener('mouseleave', Swal.resumeTimer);
    }
  });
}

async function confirmBox(text) {
  if (window.Swal) {
    const r = await Swal.fire({
      ...SwalTheme,
      icon: 'warning',
      title: 'Konfirmasi',
      text,
      showCancelButton: true,
      confirmButtonText: 'Ya, Lanjutkan',
      cancelButtonText: 'Batal'
    });
    return r.isConfirmed;
  }
  return confirm(text);
}

/* ─── DURASI MAP — untuk semua konversi durasi ke ms/jam/hari ─── */
const DURATION_MAP = {
  '1j': { ms: 3600000, label: '1 Jam' },
  '2j': { ms: 7200000, label: '2 Jam' },
  '3h': { ms: 3 * 86400000, label: '3 Hari' },
  '1mgg': { ms: 7 * 86400000, label: '1 Minggu' },
  '2mgg': { ms: 14 * 86400000, label: '2 Minggu' },
  '1bln': { ms: 30 * 86400000, label: '1 Bulan' },
  '2bln': { ms: 60 * 86400000, label: '2 Bulan' },
  '1thn': { ms: 365 * 86400000, label: '1 Tahun' },
  'permanen': { ms: 0, label: 'Permanen' }
};

let _fpCache = '';
async function getFingerprint() {
  if (_fpCache) return _fpCache;
  var fp = '';
  fp += navigator.userAgent || '';
  fp += navigator.language || '';
  fp += (screen.width || 0) + 'x' + (screen.height || 0);
  fp += screen.colorDepth || '';
  fp += new Date().getTimezoneOffset();
  fp += navigator.hardwareConcurrency || '';
  fp += navigator.deviceMemory || '';
  fp += navigator.platform || '';
  _fpCache = CryptoJS.MD5(fp).toString();
  return _fpCache;
}

function getCookie(name) {
  const v = document.cookie.split('; ').find(r => r.startsWith(name + '='));
  return v ? decodeURIComponent(v.split('=')[1]) : '';
}
function setMsg(id, text, ok = false) {
  const el = $(id);
  if (!el) return;
  el.textContent = text || '';
  el.style.color = ok ? '#10b981' : '#ef4444';
}

async function request(action, payload = {}) {
  const fp = await getFingerprint();
  const headers = { 'Content-Type': 'application/json', 'X-Fingerprint': fp };
  const csrf = getCookie('csrf_token');
  if (csrf) headers['X-CSRF-Token'] = csrf;

  let res;
  try {
    res = await fetch(API + '?action=' + encodeURIComponent(action), {
      method: 'POST',
      credentials: 'include',
      headers,
      cache: 'no-store',
      body: JSON.stringify(payload)
    });
  } catch (e) {
    throw new Error('Gagal menghubungi server');
  }

  let data;
  try { data = await res.json(); }
  catch { throw new Error('Response server tidak valid'); }

  if (!res.ok) {
    if (res.status === 401 && action !== 'login') {
      showLogin();
      Swal.fire({
        ...SwalTheme,
        icon: 'warning',
        title: 'Sesi Berakhir',
        text: 'Sesi admin kamu sudah habis. Silakan login lagi.',
        confirmButtonText: 'OK'
      });
    }
    throw new Error(data.message || data.error || 'Request gagal');
  }
  return data;
}

function showLogin() {
  $('loginWrapper').classList.remove('hidden');
  $('appContainer').classList.remove('on');
  $('sessionBar').classList.add('hidden');
  if (shareCheckInterval) clearInterval(shareCheckInterval);
  if (sessionTimerInterval) clearInterval(sessionTimerInterval);
}
function showApp() {
  $('loginWrapper').classList.add('hidden');
  $('appContainer').classList.add('on');
}

async function loadRecaptcha() {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const check = () => {
      if (window.grecaptcha && typeof window.grecaptcha.getResponse === 'function') return resolve();
      if (Date.now() - started > 15000) return reject(new Error('reCAPTCHA gagal dimuat'));
      setTimeout(check, 100);
    };
    check();
  });
}

async function loginAdmin() {
  const username = $('loginEmail').value.trim();
  const password = $('loginPassword').value;
  const accessKey = $('loginAccessKey').value.trim();

  if (!username) return toast('Isi email atau username', '', 'warning');
  if (!password) return toast('Isi password', '', 'warning');
  if (!accessKey) return toast('Isi kode akses', '', 'warning');

  let captchaToken = '';
  try { await loadRecaptcha(); captchaToken = window.grecaptcha.getResponse(); }
  catch (e) { return toast(e.message, '', 'error'); }
  if (!captchaToken) return toast('Centang reCAPTCHA dulu', '', 'warning');

  $('btnLogin').disabled = true;
  setMsg('loginMsg', '');

  Swal.fire({
    ...SwalTheme,
    title: 'Memverifikasi...',
    html: '<span style="font-size:13px;color:#64748b">Mohon tunggu sebentar</span>',
    allowOutsideClick: false,
    allowEscapeKey: false,
    showConfirmButton: false,
    didOpen: () => { Swal.showLoading(); }
  });

  try {
    const r = await request('login', { accessKey, username, password, captchaToken });
    if (!r.success) throw new Error(r.message || 'Login gagal');

    currentAdmin = { username: r.username, role: r.role };
    await StorageVault.set('admin_current', currentAdmin);
    await StorageVault.set('session_start', Date.now());

    $('loginPassword').value = '';
    $('loginAccessKey').value = '';
    setMsg('loginMsg', '');

    await Swal.fire({
      ...SwalTheme,
      icon: 'success',
      title: 'Login Berhasil',
      text: 'Selamat datang, ' + r.username,
      timer: 1400,
      showConfirmButton: false,
      timerProgressBar: true
    });

    showApp();
    $('navbarUserName').textContent = r.username;
    $('adminAvatar').textContent = (r.username || 'A')[0].toUpperCase();
    await loadDashboard();
    switchPage('dashboard');
    startShareCheck();
    startSessionTimer(3 * 24 * 60 * 60);
  } catch (e) {
    Swal.close();
    setMsg('loginMsg', e.message);
    await toast('Login gagal', e.message, 'error');
    try { if (window.grecaptcha) window.grecaptcha.reset(); } catch {}
  } finally {
    $('btnLogin').disabled = false;
  }
}

async function logoutAdmin() {
  if (!await confirmBox('Yakin ingin logout?')) return;
  try { await request('logout'); } catch {}
  StorageVault.remove('admin_current');
  StorageVault.remove('session_start');
  location.reload();
}

function startSessionTimer(seconds) {
  sessionExpiresAt = Date.now() + seconds * 1000;
  $('sessionBar').classList.remove('hidden');
  if (sessionTimerInterval) clearInterval(sessionTimerInterval);
  const tick = () => {
    const left = Math.max(0, Math.floor((sessionExpiresAt - Date.now()) / 1000));
    const days = Math.floor(left / 86400);
    const hours = Math.floor((left % 86400) / 3600);
    const mins = Math.floor((left % 3600) / 60);
    const secs = left % 60;
    const el = $('sessionCountdown');
    if (el) {
      if (days > 0) el.textContent = days + 'd ' + hours + 'j';
      else if (hours > 0) el.textContent = hours + 'j ' + mins + 'm';
      else el.textContent = mins + 'm ' + secs + 's';
    }
    if (left <= 0) {
      clearInterval(sessionTimerInterval);
      if (shareCheckInterval) clearInterval(shareCheckInterval);
      Swal.fire({
        ...SwalTheme,
        icon: 'warning',
        title: 'Sesi Berakhir',
        text: 'Waktu sesi kamu sudah habis. Silakan login lagi.',
        confirmButtonText: 'Login Lagi',
        allowOutsideClick: false
      }).then(async () => {
        try { await request('logout'); } catch {}
        StorageVault.remove('admin_current');
        StorageVault.remove('session_start');
        location.reload();
      });
    }
  };
  tick();
  sessionTimerInterval = setInterval(tick, 1000);
}

function startShareCheck() {
  if (shareCheckInterval) clearInterval(shareCheckInterval);
  shareCheckInterval = setInterval(async () => {
    try {
      const r = await request('check-share');
      if (r.kick) {
        if (shareCheckInterval) clearInterval(shareCheckInterval);
        if (sessionTimerInterval) clearInterval(sessionTimerInterval);
        await Swal.fire({
          ...SwalTheme,
          icon: 'error',
          title: 'Sesi Ditutup',
          text: r.message || 'Akun login di perangkat lain.',
          confirmButtonText: 'OK',
          confirmButtonColor: '#ef4444',
          allowOutsideClick: false
        });
        try { await request('logout'); } catch {}
        StorageVault.remove('admin_current');
        StorageVault.remove('session_start');
        location.reload();
      }
    } catch (e) {}
  }, 30000);
}

function toggleSidebar() {
  $('sidebar').classList.toggle('open');
  $('mainContent').classList.toggle('shifted');
}
function closeSidebar() {
  $('sidebar').classList.remove('open');
  $('mainContent').classList.remove('shifted');
}

function switchPage(page) {
  document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.sidebar-nav a[data-page]').forEach(x => x.classList.remove('active'));
  const target = $('page-' + page);
  if (target) {
    target.classList.add('active');
    target.style.animation = 'none';
    void target.offsetWidth;
    target.style.animation = '';
  }
  const link = document.querySelector(`[data-page="${page}"]`);
  if (link) link.classList.add('active');
  $('topTitle').textContent = link ? link.textContent.trim() : 'Dashboard';
  closeSidebar();
  const f = {
    dashboard: loadDashboard,
    users: loadUsers,
    'add-user': () => { updateExpiryPreview(); },
    'user-activity': loadUserActivity,
    'user-registrations': loadUserRegistrations,
    blocked: loadBlocked,
    logs: loadLogs,
    suspicious: loadSuspicious,
    maintenance: loadMaintenance
  };
  if (f[page]) f[page]();
}

function skeletonRows(n = 4) {
  let h = '';
  for (let i = 0; i < n; i++) {
    h += `<div style="display:flex;gap:14px;align-items:center;padding:14px;border:2px solid var(--line);border-radius:12px;background:var(--surface);margin-bottom:8px;opacity:.6">
      <div style="width:56px;height:56px;border-radius:14px;background:linear-gradient(90deg,#e0f5ff,#b8e8ff,#e0f5ff);background-size:200% 100%;animation:neoShimmer 1.4s ease-in-out infinite"></div>
      <div style="flex:1;display:flex;flex-direction:column;gap:6px">
        <div style="width:40%;height:12px;border-radius:4px;background:linear-gradient(90deg,#e0f5ff,#b8e8ff,#e0f5ff);background-size:200% 100%;animation:neoShimmer 1.4s ease-in-out infinite"></div>
        <div style="width:65%;height:10px;border-radius:4px;background:linear-gradient(90deg,#e0f5ff,#b8e8ff,#e0f5ff);background-size:200% 100%;animation:neoShimmer 1.4s ease-in-out infinite"></div>
      </div>
    </div>`;
  }
  return h;
}

function ensureShimmerStyle() {
  if (document.getElementById('neo-shimmer-style')) return;
  const s = document.createElement('style');
  s.id = 'neo-shimmer-style';
  s.textContent = `@keyframes neoShimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
    .neo-swal-popup{border:2px solid #0F172A !important;border-radius:14px !important;box-shadow:6px 6px 0 #0F172A !important;font-family:'Inter',sans-serif !important}
    .neo-swal-title{font-weight:900 !important;letter-spacing:-0.02em !important;color:#0F172A !important}
    .neo-swal-html{font-weight:500 !important;color:#475569 !important}
    .neo-swal-btn{background:#00BFFF !important;border:2px solid #0F172A !important;border-radius:10px !important;font-weight:800 !important;box-shadow:3px 3px 0 #0F172A !important;text-transform:uppercase !important;letter-spacing:0.04em !important}
    .neo-swal-btn-cancel{background:#fff !important;color:#0F172A !important;border:2px solid #0F172A !important;border-radius:10px !important;font-weight:800 !important;box-shadow:3px 3px 0 #0F172A !important;text-transform:uppercase !important}
    .swal2-input,.swal2-select,.swal2-textarea{border:2px solid #0F172A !important;border-radius:10px !important;box-shadow:2px 2px 0 #0F172A !important;font-weight:600 !important;font-family:'Inter',sans-serif !important}
  `;
  document.head.appendChild(s);
}

async function loadDashboard() {
  ensureShimmerStyle();
  try {
    const r = await request('stats');
    if (r.stats) {
      animateCount($('statTotal'), r.stats.total || 0);
      animateCount($('statActive'), r.stats.active || 0);
      animateCount($('statPending'), r.stats.pending || 0);
      animateCount($('statBanned'), r.stats.banned || 0);
    }
    const logs = await request('logs', { limit: 8 });
    const list = logs.logs || [];
    $('dashboardLogs').innerHTML = list.length
      ? list.map(logHtml).join('')
      : '<div class="empty">Belum ada aktivitas.</div>';
  } catch (e) { await toast('Gagal memuat dashboard', e.message, 'error'); }
}

function animateCount(el, target) {
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  if (start === target) { el.textContent = target; return; }
  const duration = 500;
  const t0 = performance.now();
  const step = (t) => {
    const p = Math.min(1, (t - t0) / duration);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(start + (target - start) * eased);
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

async function loadUsers() {
  ensureShimmerStyle();
  $('userList').innerHTML = skeletonRows(4);
  try {
    const r = await request('users');
    usersCache = r.users || [];
    renderUserList();
  } catch (e) { await toast('Gagal memuat user', e.message, 'error'); }
}

function userStatusBadge(u) {
  if (u.banned) return '<span class="badge red"><i class="fa-solid fa-ban"></i> BANNED</span>';
  if (u.accessBanned) return '<span class="badge yellow"><i class="fa-solid fa-lock"></i> BAN AKSES</span>';
  if (u.forceLogout) return '<span class="badge yellow"><i class="fa-solid fa-pause"></i> TANGGUH</span>';
  if (u.status === 'pending') return '<span class="badge gray"><i class="fa-solid fa-hourglass"></i> PENDING</span>';
  return '<span class="badge green"><i class="fa-solid fa-check"></i> AKTIF</span>';
}

function expiryText(u) {
  if (!u.expiry_date) return '<span class="expiry-info" style="color:var(--muted)">Tidak ada</span>';
  if (typeof u.daysLeft === 'number') {
    if (u.daysLeft === 999999 || String(u.expiry_date).includes('9999')) {
      return '<span class="expiry-info expiry-permanent"><i class="fa-solid fa-infinity"></i> Permanen</span>';
    }
    if (u.daysLeft < 0) return '<span class="expiry-info expiry-bad">EXPIRED</span>';
    if (u.daysLeft === 0) return '<span class="expiry-info expiry-warn">Hari ini</span>';
    if (u.daysLeft <= 3) return '<span class="expiry-info expiry-warn">' + u.daysLeft + ' hari</span>';
    return '<span class="expiry-info expiry-ok">' + u.daysLeft + ' hari</span>';
  }
  return '<span class="expiry-info">' + esc(u.expiry_date) + '</span>';
}

function highlightCaseSensitive(text, query) {
  if (!query) return esc(text);
  const idx = text.indexOf(query);
  if (idx < 0) return esc(text);
  const before = text.substring(0, idx);
  const match = text.substring(idx, idx + query.length);
  const after = text.substring(idx + query.length);
  return esc(before) + '<mark>' + esc(match) + '</mark>' + esc(after);
}

function renderUserList() {
  const rawQuery = ($('userSearch') && $('userSearch').value) || '';
  const query = rawQuery.trim();

  const list = usersCache.filter(u => {
    if (!query) return true;
    const username = String(u.username || '');
    const email = String(u.email || '');
    return username.indexOf(query) >= 0 || email.indexOf(query) >= 0;
  });

  $('userCount').textContent = usersCache.length;
  if (!list.length) { $('userList').innerHTML = '<div class="empty">Tidak ada user.</div>'; return; }

  $('userList').innerHTML = list.map(u => {
    const usernameHl = highlightCaseSensitive(u.username || '-', query);
    const emailHl = highlightCaseSensitive(u.email || 'tanpa email', query);
    const lastIP = (u.ipHistory || []).slice(-1)[0] || '-';
    const lastFP = ((u.fpHistory || []).slice(-1)[0] || '-');
    return `
      <div class="user-card" onclick="openProfileModal('${esc(u.id)}')">
        <div class="user-avatar" style="background:${esc(u.initialColor || '#64748b')}">${esc(u.initialLetter || '?')}</div>
        <div class="user-main">
          <b>${usernameHl}</b>
          <div class="user-sub">
            <span>${emailHl}</span><span>·</span><span>${esc(u.role || 'User')}</span>
          </div>
          <div class="user-meta">
            <span><i class="fa-solid fa-network-wired"></i> ${esc(lastIP)}</span>
            <span><i class="fa-solid fa-fingerprint"></i> ${esc(lastFP.slice(0, 12))}...</span>
          </div>
        </div>
        <div class="user-status">
          ${userStatusBadge(u)}
          ${expiryText(u)}
        </div>
      </div>
    `;
  }).join('');
}

async function openProfileModal(id) {
  $('profileModal').classList.add('show');
  $('profileBody').innerHTML = `<div style="padding:20px">${skeletonRows(3)}</div>`;
  try {
    const r = await request('get-user-detail', { id });
    if (!r.success || !r.user) throw new Error(r.message || 'Gagal memuat');
    renderProfile(r.user);
  } catch (e) {
    $('profileBody').innerHTML = '<div class="empty">Gagal: ' + esc(e.message) + '</div>';
  }
}
function closeProfileModal() { $('profileModal').classList.remove('show'); }

function renderProfile(u) {
  const avatar = `<div class="profile-avatar" style="background:${esc(u.initialColor || '#64748b')}">${esc(u.initialLetter || '?')}</div>`;

  const ipHtml = (u.ipHistory || []).length
    ? u.ipHistory.slice().reverse().map(ip => `<div class="info-row"><span class="info-key">IP</span><span class="info-val">${esc(ip)}</span></div>`).join('')
    : '<div class="info-row"><span class="info-key">IP</span><span class="info-val" style="color:var(--muted)">Belum ada</span></div>';

  const fpHtml = (u.fpHistory || []).length
    ? u.fpHistory.slice().reverse().map(fp => `<div class="info-row"><span class="info-key">FP</span><span class="info-val" style="font-family:monospace;font-size:11px">${esc(fp).slice(0, 32)}...</span></div>`).join('')
    : '<div class="info-row"><span class="info-key">FP</span><span class="info-val" style="color:var(--muted)">Belum ada</span></div>';

  const topupsHtml = (u.recentTopups || []).length
    ? u.recentTopups.map(t => `
        <div class="trx-item">
          <div class="trx-head">
            <span>${esc(t.accountName || t.account || '-')}</span>
            <span>+Rp ${Number(t.amount || 0).toLocaleString('id-ID')}</span>
          </div>
          <div class="trx-meta">${new Date(t.timestamp || 0).toLocaleString('id-ID')} · ${esc(t.operator || '')}</div>
        </div>`).join('')
    : '<div class="empty">Belum ada riwayat top up</div>';

  const logsHtml = (u.recentLogs || []).length
    ? u.recentLogs.slice(0, 10).map(l => `
        <div class="log-item">
          <div class="log-head">${esc(l.action || '-')}</div>
          <div class="log-detail">${esc(l.details || '-')}</div>
          <div class="log-meta">${new Date(l.timestamp || 0).toLocaleString('id-ID')} · ${esc(l.ip || '-')}</div>
        </div>`).join('')
    : '<div class="empty">Belum ada log</div>';

  $('profileBody').innerHTML = `
    <div class="profile-header">
      ${avatar}
      <div class="profile-info">
        <h2>${esc(u.username || '-')}</h2>
        <p>${esc(u.email || 'Tanpa email')}</p>
        <div style="margin-top:8px">${userStatusBadge(u)}</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title"><i class="fa-solid fa-circle-info"></i> Informasi Akun</div>
      <div class="info-row"><span class="info-key">Role</span><span class="info-val">${esc(u.role || 'User')}</span></div>
      <div class="info-row"><span class="info-key">No. HP</span><span class="info-val">${esc(u.phone || '-')}</span></div>
      <div class="info-row"><span class="info-key">Masa Aktif</span><span class="info-val">${esc(u.expiry_date || '-')} ${typeof u.daysLeft === 'number' && u.daysLeft >= 0 && u.daysLeft !== 999999 ? '· ' + u.daysLeft + ' hari' : ''}</span></div>
      <div class="info-row"><span class="info-key">Dibuat</span><span class="info-val">${u.createdAt ? new Date(u.createdAt).toLocaleString('id-ID') : '-'}</span></div>
      <div class="info-row"><span class="info-key">Reset Password</span><span class="info-val">${u.resetCount || 0}x</span></div>
    </div>

    <div class="section">
      <div class="section-title"><i class="fa-solid fa-network-wired"></i> IP History</div>
      ${ipHtml}
    </div>

    <div class="section">
      <div class="section-title"><i class="fa-solid fa-fingerprint"></i> Fingerprint History</div>
      ${fpHtml}
    </div>

    <div class="section">
      <div class="section-title"><i class="fa-solid fa-coins"></i> Riwayat Top Up</div>
      ${topupsHtml}
    </div>

    <div class="section">
      <div class="section-title"><i class="fa-solid fa-list-check"></i> Log Terakhir</div>
      ${logsHtml}
    </div>

    <div class="section">
      <div class="section-title"><i class="fa-solid fa-bolt"></i> Aksi</div>
      <div class="action-grid">
        ${u.banned
          ? `<button class="btn success" onclick="askDuration('unban-user','${esc(u.username)}')"><i class="fa-solid fa-unlock"></i> Unban User</button>`
          : `<button class="btn danger" onclick="askDuration('ban-user','${esc(u.username)}')"><i class="fa-solid fa-ban"></i> Ban User</button>`}

        ${u.accessBanned
          ? `<button class="btn success" onclick="askDuration('unban-akses','${esc(u.username)}')"><i class="fa-solid fa-unlock"></i> Unban Akses</button>`
          : `<button class="btn warning" onclick="askDuration('ban-akses','${esc(u.username)}')"><i class="fa-solid fa-lock"></i> Ban Akses</button>`}

        ${u.forceLogout
          ? `<button class="btn success" onclick="askDuration('unforce-logout','${esc(u.username)}')"><i class="fa-solid fa-play"></i> Pulihkan</button>`
          : `<button class="btn warning" onclick="askDuration('force-logout','${esc(u.username)}')"><i class="fa-solid fa-pause"></i> Tangguhkan</button>`}

        <button class="btn light" onclick="editUserPrompt('${esc(u.username)}')"><i class="fa-solid fa-pen"></i> Edit User</button>
        <button class="btn danger" onclick="doUserAction('delete-user','${esc(u.username)}')"><i class="fa-solid fa-trash"></i> Hapus</button>
      </div>
    </div>
  `;
}

async function askDuration(action, username) {
  const isUnban = action.startsWith('un') || action === 'unforce-logout';
  if (isUnban) return doUserAction(action, username);

  const titleMap = {
    'ban-user': 'Ban User',
    'ban-akses': 'Ban Akses',
    'force-logout': 'Tangguhkan'
  };

  const durationOptions = Object.entries(DURATION_MAP).map(([k, v]) =>
    `<option value="${k}" ${k === 'permanen' ? 'selected' : ''}>${v.label}</option>`
  ).join('');

  const r = await Swal.fire({
    ...SwalTheme,
    title: titleMap[action] || 'Pilih Durasi',
    html: `
      <p style="font-size:13px;color:#64748b;margin:0 0 16px;font-weight:600;text-align:left">Pilih durasi untuk <b style="color:#0F172A">${esc(username)}</b>:</p>
      <select id="swalDuration" style="${NEO_SELECT_STYLE};margin-bottom:12px">${durationOptions}</select>
      <input id="swalReason" placeholder="Alasan (opsional)" style="${NEO_INPUT_STYLE}">
    `,
    showCancelButton: true,
    confirmButtonText: 'Lanjutkan',
    cancelButtonText: 'Batal',
    confirmButtonColor: '#ef4444',
    preConfirm: () => ({
      duration: document.getElementById('swalDuration').value,
      reason: document.getElementById('swalReason').value
    })
  });
  if (!r.isConfirmed) return;

  const messages = {
    'ban-user': 'Ban user ini? IP & FP akan diblokir + user langsung force logout.',
    'ban-akses': 'Ban akses user ini? IP & FP akan diblokir + user force logout.',
    'force-logout': 'Tangguhkan user ini? User akan langsung force logout.'
  };
  const c = await confirmBox(messages[action] || 'Yakin?');
  if (!c) return;

  try {
    const res = await request(action, { username, ...r.value });
    await toast(res.success ? 'Berhasil' : 'Gagal', res.message || '', res.success ? 'success' : 'error');
    if (res.success) { closeProfileModal(); await loadUsers(); }
  } catch (e) { await toast('Gagal', e.message, 'error'); }
}

async function doUserAction(action, username) {
  const messages = {
    'unban-user': 'Unban user ini? IP & FP akan diunblock.',
    'unban-akses': 'Unban akses user ini? IP & FP akan diunblock.',
    'unforce-logout': 'Pulihkan user ini dari penangguhan?',
    'delete-user': 'Hapus user ' + username + '? Tidak bisa dibatalkan.'
  };
  const c = await confirmBox(messages[action] || 'Yakin?');
  if (!c) return;
  try {
    const r = await request(action, { username });
    await toast(r.success ? 'Berhasil' : 'Gagal', r.message || '', r.success ? 'success' : 'error');
    if (r.success) { closeProfileModal(); await loadUsers(); }
  } catch (e) { await toast('Gagal', e.message, 'error'); }
}

async function editUserPrompt(username) {
  const u = usersCache.find(x => x.username === username);
  if (!u) return;
  const r = await Swal.fire({
    ...SwalTheme,
    title: 'Edit User',
    html: `
      <input id="swalEmail" placeholder="Email" value="${esc(u.email || '')}" style="${NEO_INPUT_STYLE};margin:6px 0">
      <input id="swalPhone" placeholder="No HP" value="${esc(u.phone || '')}" style="${NEO_INPUT_STYLE};margin:6px 0">
      <input id="swalExpiry" type="date" value="${esc(u.expiry_date || '')}" style="${NEO_INPUT_STYLE};margin:6px 0">
      <select id="swalRole" style="${NEO_SELECT_STYLE};margin:6px 0">
        <option value="User" ${u.role === 'User' ? 'selected' : ''}>User</option>
        <option value="Admin" ${u.role === 'Admin' ? 'selected' : ''}>Admin</option>
      </select>
      <input id="swalPassword" type="password" placeholder="Password baru (opsional)" style="${NEO_INPUT_STYLE};margin:6px 0">
    `,
    focusConfirm: false,
    showCancelButton: true,
    confirmButtonText: 'Simpan',
    cancelButtonText: 'Batal',
    confirmButtonColor: '#00BFFF',
    preConfirm: () => ({
      email: document.getElementById('swalEmail').value.trim(),
      phone: document.getElementById('swalPhone').value.trim(),
      expiry_date: document.getElementById('swalExpiry').value,
      role: document.getElementById('swalRole').value,
      password: document.getElementById('swalPassword').value
    })
  });
  if (!r.isConfirmed) return;
  try {
    const x = await request('edit-user', { username, ...r.value });
    await toast(x.success ? 'Berhasil' : 'Gagal', x.message || '', x.success ? 'success' : 'error');
    if (x.success) { closeProfileModal(); await loadUsers(); }
  } catch (e) { await toast('Gagal', e.message, 'error'); }
}

function updateExpiryPreview() {
  const sel = $('newExpiryDuration');
  const preview = $('expiryPreview');
  if (!sel || !preview) return;
  const d = DURATION_MAP[sel.value];
  if (!d) { preview.textContent = ''; return; }
  if (d.ms === 0) {
    preview.textContent = '→ Tanpa batas waktu (permanen)';
    return;
  }
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const t = new Date(now.getTime() + d.ms);
  const y = t.getFullYear();
  const m = String(t.getMonth() + 1).padStart(2, '0');
  const dd = String(t.getDate()).padStart(2, '0');
  preview.textContent = '→ Sampai ' + y + '-' + m + '-' + dd + ' (' + d.label + ')';
}

async function submitAddUser() {
  const username = $('newUsername').value.trim();
  const password = $('newPassword').value;
  const email = $('newEmail').value.trim();
  const phone = $('newPhone').value.trim();
  const expiry_duration = $('newExpiryDuration').value;
  const role = $('newRole').value;

  if (!username || username.length < 3) return toast('Username minimal 3 karakter', '', 'warning');
  if (!password || password.length < 6) return toast('Password minimal 6 karakter', '', 'warning');
  if (!email || !email.includes('@')) return toast('Email tidak valid', '', 'warning');
  if (!phone || phone.length < 10) return toast('No HP minimal 10 digit', '', 'warning');

  const d = DURATION_MAP[expiry_duration];
  if (!d) return toast('Durasi tidak valid', '', 'warning');

  let expiry_date;
  if (d.ms === 0) {
    expiry_date = '9999-12-31';
  } else {
    const now = new Date();
    now.setHours(0, 0, 0, 0);
    const t = new Date(now.getTime() + d.ms);
    expiry_date = t.getFullYear() + '-' + String(t.getMonth() + 1).padStart(2, '0') + '-' + String(t.getDate()).padStart(2, '0');
  }

  try {
    const r = await request('add-user', { username, password, email, phone, expiry_date, role });
    await toast(r.success ? 'User ditambahkan' : 'Gagal', r.message || '', r.success ? 'success' : 'error');
    if (r.success) { resetAddUserForm(); await loadUsers(); switchPage('users'); }
  } catch (e) { await toast('Gagal', e.message, 'error'); }
}

function resetAddUserForm() {
  ['newUsername', 'newPassword', 'newEmail', 'newPhone'].forEach(id => { $(id).value = ''; });
  $('newExpiryDuration').value = '1bln';
  $('newRole').value = 'User';
  updateExpiryPreview();
}

async function loadUserActivity() {
  ensureShimmerStyle();
  try {
    const r = await request('user-activity', { limit: 200 });
    const list = r.logs || [];
    $('userActivityLog').innerHTML = list.length
      ? list.map(logHtml).join('')
      : '<div class="empty">Belum ada aktivitas user.</div>';
  } catch (e) { await toast('Gagal memuat', e.message, 'error'); }
}

async function loadUserRegistrations() {
  ensureShimmerStyle();
  try {
    const r = await request('user-registrations');
    const list = r.registrations || [];
    $('userRegistrations').innerHTML = list.length
      ? list.map(u => {
          const initial = (u.username || '?')[0];
          const isUpper = initial >= 'A' && initial <= 'Z';
          const color = isUpper ? '#00BFFF' : (initial >= 'a' && initial <= 'z' ? '#10b981' : '#64748b');
          return `
            <div class="user-card" onclick="openProfileModal('${esc(u.id)}')">
              <div class="user-avatar" style="background:${color}">${esc(initial.toUpperCase())}</div>
              <div class="user-main">
                <b>${esc(u.username)}</b>
                <div class="user-sub"><span>${esc(u.email || '-')}</span><span>·</span><span>${esc(u.paket || '-')}</span></div>
                <div class="user-meta"><span><i class="fa-solid fa-calendar"></i> ${new Date(u.createdAt).toLocaleString('id-ID')}</span></div>
              </div>
              <div class="user-status">${userStatusBadge(u)}</div>
            </div>
          `;
        }).join('')
      : '<div class="empty">Belum ada user terdaftar.</div>';
  } catch (e) { await toast('Gagal memuat', e.message, 'error'); }
}

async function loadBlocked() {
  try {
    const [ips, fps] = await Promise.all([request('list-blocked-ips'), request('list-blocked-fps')]);
    const ipList = ips.items || [];
    const fpList = fps.items || [];
    $('blockedIPsList').innerHTML = ipList.length
      ? ipList.map(x => `<div class="info-row"><span class="info-key">${esc(x.ip)}</span><span class="info-val"><button class="btn danger sm" onclick="unblockIP('${esc(x.ip)}')">Unblock</button></span></div>`).join('')
      : '<div class="empty">Tidak ada IP diblokir</div>';
    $('blockedFPsList').innerHTML = fpList.length
      ? fpList.map(x => `<div class="info-row"><span class="info-key" style="font-family:monospace;font-size:11px">${esc(x.fingerprint).slice(0, 32)}...</span><span class="info-val"><button class="btn danger sm" onclick="unblockFP('${esc(x.fingerprint)}')">Unblock</button></span></div>`).join('')
      : '<div class="empty">Tidak ada FP diblokir</div>';
  } catch (e) { await toast('Gagal memuat data blokir', e.message, 'error'); }
}

async function blockNewIP() {
  const r = await Swal.fire({
    ...SwalTheme,
    title: 'Block IP',
    html: `<p style="font-size:13px;color:#64748b;margin:0 0 14px;font-weight:600;text-align:left">Masukkan IP yang ingin diblokir:</p>
           <input id="swalIP" placeholder="contoh: 202.56.166.100" style="${NEO_INPUT_STYLE}">`,
    showCancelButton: true,
    confirmButtonText: 'Block',
    cancelButtonText: 'Batal',
    confirmButtonColor: '#ef4444',
    preConfirm: () => document.getElementById('swalIP').value.trim()
  });
  if (!r.isConfirmed || !r.value) return;
  try { await request('block-ip', { ip: r.value }); await toast('IP diblokir', '', 'success'); loadBlocked(); }
  catch (e) { await toast('Gagal', e.message, 'error'); }
}

async function unblockIP(ip) {
  if (!await confirmBox('Unblock IP ' + ip + '?')) return;
  try { await request('unblock-ip', { ip }); await toast('IP diunblock', '', 'success'); loadBlocked(); }
  catch (e) { await toast('Gagal', e.message, 'error'); }
}

async function blockNewFP() {
  const r = await Swal.fire({
    ...SwalTheme,
    title: 'Block FP',
    html: `<p style="font-size:13px;color:#64748b;margin:0 0 14px;font-weight:600;text-align:left">Masukkan fingerprint yang ingin diblokir:</p>
           <input id="swalFP" placeholder="fingerprint string" style="${NEO_INPUT_STYLE}">`,
    showCancelButton: true,
    confirmButtonText: 'Block',
    cancelButtonText: 'Batal',
    confirmButtonColor: '#ef4444',
    preConfirm: () => document.getElementById('swalFP').value.trim()
  });
  if (!r.isConfirmed || !r.value) return;
  try { await request('block-fp', { fingerprint: r.value }); await toast('FP diblokir', '', 'success'); loadBlocked(); }
  catch (e) { await toast('Gagal', e.message, 'error'); }
}

async function unblockFP(fp) {
  if (!await confirmBox('Unblock FP ini?')) return;
  try { await request('unblock-fp', { fingerprint: fp }); await toast('FP diunblock', '', 'success'); loadBlocked(); }
  catch (e) { await toast('Gagal', e.message, 'error'); }
}

function logHtml(l) {
  const name = l.knownUser
    ? `<b style="color:var(--sky)"><i class="fa-solid fa-user-check"></i> ${esc(l.displayName)}</b>`
    : `<b><i class="fa-solid fa-globe"></i> ${esc(l.ip || '-')}</b>`;
  return `<div class="log-item">
    <div class="log-head">${name} · ${esc(l.action || '-')}</div>
    <div class="log-detail">${esc(l.details || '-')}</div>
    <div class="log-meta">${new Date(l.timestamp || 0).toLocaleString('id-ID')} · IP: ${esc(l.ip || '-')} · FP: ${esc((l.fingerprint || '-').slice(0, 16))}</div>
  </div>`;
}
async function loadLogs() {
  ensureShimmerStyle();
  $('allLogs').innerHTML = skeletonRows(3);
  try {
    const r = await request('logs', { limit: 200 });
    $('allLogs').innerHTML = (r.logs || []).map(logHtml).join('') || '<div class="empty">Belum ada log</div>';
  } catch (e) { await toast('Gagal memuat log', e.message, 'error'); }
}
async function clearLogs() {
  if (!await confirmBox('Hapus semua activity log?')) return;
  try { await request('clear-logs'); await toast('Log dihapus', '', 'success'); loadLogs(); }
  catch (e) { await toast('Gagal', e.message, 'error'); }
}

function suspHtml(l) {
  return `<div class="log-item suspicious">
    <div class="log-head"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(l.username || 'unknown')} · ${esc(l.action || '-')}</div>
    <div class="log-detail">${(l.reasons || []).map(r => esc(r)).join(' · ')}</div>
    <div class="log-meta">${new Date(l.timestamp || 0).toLocaleString('id-ID')} · IP: ${esc(l.ip || '-')} · FP: ${esc((l.fingerprint || '-').slice(0, 16))}</div>
  </div>`;
}
async function loadSuspicious() {
  ensureShimmerStyle();
  $('suspiciousLogs').innerHTML = skeletonRows(3);
  try {
    const r = await request('suspicious-logs');
    $('suspiciousLogs').innerHTML = (r.logs || []).map(suspHtml).join('') || '<div class="empty">Tidak ada aktivitas mencurigakan</div>';
  } catch (e) { await toast('Gagal memuat', e.message, 'error'); }
}
async function clearSuspicious() {
  if (!await confirmBox('Hapus semua log mencurigakan?')) return;
  try { await request('clear-suspicious'); await toast('Log dihapus', '', 'success'); loadSuspicious(); }
  catch (e) { await toast('Gagal', e.message, 'error'); }
}

function renderMaintenancePreview() {
  const title = $('maintTitle').value.trim() || 'SEDANG PERBAIKAN SISTEM';
  const message = $('maintMessage').value.trim() || 'Website sedang dalam perbaikan oleh admin. Silakan kembali beberapa saat lagi.';
  const durKey = $('maintDuration').value;
  const d = DURATION_MAP[durKey];
  let untilText;
  if (durKey === '0' || !d) {
    untilText = 'Mohon maaf atas ketidaknyamanan ini.';
  } else if (d.ms === 0) {
    untilText = 'Durasi: Permanen';
  } else {
    const t = Date.now() + d.ms;
    untilText = 'Estimasi selesai: ' + new Date(t).toLocaleString('id-ID');
  }
  $('maintenancePreview').innerHTML = `
    <div class="preview-icon"><i class="fa-solid fa-screwdriver-wrench"></i></div>
    <h3>${esc(title)}</h3>
    <p>${esc(message)}</p>
    <div class="preview-until">${esc(untilText)}</div>
  `;
  const maintPreview = $('maintPreview');
  if (maintPreview) {
    if (durKey === '0' || !d) maintPreview.textContent = '→ Tidak ada estimasi waktu';
    else if (d.ms === 0) maintPreview.textContent = '→ Permanen (sampai dinonaktifkan manual)';
    else maintPreview.textContent = '→ Berakhir dalam ' + d.label;
  }
}

async function loadMaintenance() {
  try {
    const r = await request('maintenance-status');
    $('maintStatus').textContent = r.maintenance ? 'ON' : 'OFF';
    $('maintStatus').className = 'badge ' + (r.maintenance ? 'red' : 'green');
    $('maintTitle').value = r.title || '';
    $('maintMessage').value = r.message || '';
    $('maintDuration').value = r.until ? '1bln' : '0';
    renderMaintenancePreview();
  } catch (e) { await toast('Gagal memuat maintenance', e.message, 'error'); }
}

async function enableMaintenance() {
  const title = $('maintTitle').value.trim();
  const message = $('maintMessage').value.trim();
  const durKey = $('maintDuration').value;
  if (!title || !message) return toast('Judul dan pesan wajib diisi', '', 'warning');

  const d = DURATION_MAP[durKey];
  let until = 0;
  if (durKey !== '0' && d && d.ms > 0) {
    until = Date.now() + d.ms;
  }

  try {
    await request('set-maintenance', { maintenance: true, title, message, until });
    await toast('Maintenance aktif', '', 'success');
    loadMaintenance();
  } catch (e) { await toast('Gagal', e.message, 'error'); }
}

async function disableMaintenance() {
  if (!await confirmBox('Nonaktifkan maintenance?')) return;
  try {
    await request('set-maintenance', { maintenance: false, title: '', message: '', until: 0 });
    await toast('Maintenance nonaktif', '', 'success');
    loadMaintenance();
  } catch (e) { await toast('Gagal', e.message, 'error'); }
}

async function boot() {
  ensureShimmerStyle();
  try {
    const r = await request('me');
    if (r.success) {
      currentAdmin = r.admin;
      showApp();
      $('navbarUserName').textContent = r.admin.username || 'Admin';
      $('adminAvatar').textContent = (r.admin.username || 'A')[0].toUpperCase();
      await loadDashboard();
      startShareCheck();
      startSessionTimer(3 * 24 * 60 * 60);
      return;
    }
  } catch (e) {}
  showLogin();
  loadRecaptcha().catch(() => {});
}

document.addEventListener('DOMContentLoaded', () => {
  boot();
  const sel = $('newExpiryDuration');
  if (sel) {
    sel.addEventListener('change', updateExpiryPreview);
    updateExpiryPreview();
  }
  ['maintTitle', 'maintMessage', 'maintDuration'].forEach(id => {
    const el = $(id);
    if (el) el.addEventListener('input', renderMaintenancePreview);
    if (el) el.addEventListener('change', renderMaintenancePreview);
  });
});