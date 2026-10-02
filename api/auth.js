// api/auth.js
import crypto from 'node:crypto';
import { db } from './rvns/db.js';
import { CONFIG } from './rvns/config.js';
import {
  hashPassword, verifyPassword, decryptAtRest, sanitize,
  findUserByUsername, findUserByEmail, saveUser, isValidUsername,
  isIPBlocked, isFPBlocked, logActivity,
  verifyRecaptchaV2, getIP, fpOf, signFingerprint,
  checkRegisterLimit, markRegisterLimit,
  checkResetLimit, recordReset
} from './rvns/helper.js';
import {
  createSessionToken, setSessionCookie, clearSessionCookie,
  generateCSRFToken, verifySession
} from './rvns/session.js';
import {
  setSecurityHeaders, setCorsHeaders, enforceOrigin, methodGuard, bodyGuard
} from './rvns/middleware.js';

function _signFingerprint(raw) {
  if (typeof signFingerprint === 'function') return signFingerprint(raw);
  return crypto.createHmac('sha256', CONFIG.SESSION_SECRET).update(String(raw)).digest('base64url');
}

async function handleSignFingerprint(req, res) {
  try {
    const { fp } = req.body || {};
    if (!fp || typeof fp !== 'string' || fp.length < 16 || fp.length > 200) {
      return res.status(400).json({ success: false, message: 'FP tidak valid' });
    }
    const sig = _signFingerprint(fp);
    return res.status(200).json({ success: true, fp, sig });
  } catch (e) {
    console.error('[sign-fp]', e?.message || e);
    return res.status(500).json({ success: false, message: 'Internal error' });
  }
}

async function handleLogin(req, res, ip, fp) {
  const { username, password, captchaToken } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });
  }

  if (CONFIG.RECAPTCHA_V2_SECRET) {
    let captchaOk = false;
    try {
      captchaOk = await verifyRecaptchaV2(captchaToken);
    } catch (e) {
      captchaOk = false;
    }
    if (!captchaOk) {
      await logActivity(username, 'login_captcha_fail', 'reCAPTCHA gagal', ip, fp).catch(() => {});
      return res.status(200).json({ success: false, error: 'captcha_failed', message: 'Verifikasi reCAPTCHA gagal' });
    }
  }

  if (await isIPBlocked(ip).catch(() => false) || (fp && await isFPBlocked(fp).catch(() => false))) {
    await logActivity(username, 'login_blocked', 'IP/FP diblokir', ip, fp).catch(() => {});
    return res.status(200).json({ success: false, error: 'blocked', message: 'IP atau perangkat diblokir' });
  }

  const found = await findUserByUsername(username);
  if (!found) {
    await logActivity(username, 'login_failed', 'User tidak ditemukan', ip, fp).catch(() => {});
    return res.status(200).json({ success: false, message: 'Username atau password salah' });
  }
  if (found.row.status === 'pending') {
    return res.status(200).json({ success: false, error: 'pending_activation', message: 'Akun belum diaktivasi admin' });
  }
  if (found.row.status === 'rejected') {
    return res.status(200).json({ success: false, error: 'rejected', message: 'Akun ditolak admin' });
  }
  if (found.row.banned) {
    await logActivity(username, 'login_banned', 'Akun dibanned', ip, fp).catch(() => {});
    return res.status(200).json({
      success: false, banned: true,
      bannedUntil: found.data.bannedUntil || 0,
      message: 'Akun dibanned'
    });
  }
  if (found.row.accessBanned) {
    await logActivity(username, 'login_ban_akses', 'Ban akses aktif', ip, fp).catch(() => {});
    return res.status(200).json({
      success: false, banAkses: true,
      banAksesUntil: found.data.banAksesUntil || 0,
      message: 'Akses dibatasi'
    });
  }
  if (found.row.forceLogout) {
    await logActivity(username, 'login_force_logout', 'Force logout aktif', ip, fp).catch(() => {});
    return res.status(200).json({ success: false, forceLogout: true, message: 'Akun ditangguhkan' });
  }

  const ok = await verifyPassword(password, found.data.password_hash);
  if (!ok) {
    await logActivity(username, 'login_failed', 'Password salah', ip, fp).catch(() => {});
    return res.status(200).json({ success: false, message: 'Username atau password salah' });
  }

  const updated = { ...found.data };

  const currentLockedFP = updated.lockedFP || '';
  const currentLockedIP = updated.lockedIP || '';
  const fpInHistory = Array.isArray(updated.fpHistory) && updated.fpHistory.includes(fp);
  const ipInHistory = Array.isArray(updated.ipHistory) && updated.ipHistory.includes(ip);

  if (!currentLockedFP && fp) {
    updated.lockedFP = fp;
    updated.lockedIP = ip || '';
    updated.lockedAt = Date.now();
  } else if (currentLockedFP === fp) {
    updated.lockedIP = ip || currentLockedIP;
  } else if (fpInHistory || ipInHistory) {
    updated.lockedFP = fp;
    updated.lockedIP = ip || '';
    updated.fpChangedAt = Date.now();
    updated.fpChangedFrom = currentLockedFP;
  } else {
    updated.lockedFP = fp;
    updated.lockedIP = ip || '';
    updated.fpChangedAt = Date.now();
    updated.fpChangedFrom = currentLockedFP;
  }

  updated.lastLogin = { ip, fingerprint: fp, timestamp: Date.now() };

  const ipH = Array.isArray(updated.ipHistory) ? updated.ipHistory : [];
  if (ip && (!ipH.length || ipH[ipH.length - 1] !== ip)) { ipH.push(ip); if (ipH.length > 10) ipH.shift(); }
  updated.ipHistory = ipH;

  const fpH = Array.isArray(updated.fpHistory) ? updated.fpHistory : [];
  if (fp && (!fpH.length || fpH[fpH.length - 1] !== fp)) { fpH.push(fp); if (fpH.length > 10) fpH.shift(); }
  updated.fpHistory = fpH;

  await saveUser(found.id, {
    ...updated,
    username: found.row.username,
    role: found.row.role,
    status: found.row.status
  });

  const sessionToken = createSessionToken({
    id: found.id,
    username: found.row.username,
    role: found.row.role
  });
  const csrfSession = {
    uid: found.id,
    username: found.row.username,
    role: found.row.role,
    iat: Date.now(),
    exp: Date.now() + CONFIG.SESSION_USER_MAX_AGE * 1000
  };
  const csrfToken = generateCSRFToken(csrfSession);

  setSessionCookie(res, sessionToken, csrfToken, { role: found.row.role });

  await logActivity(username, 'login_success', 'Login berhasil', ip, fp).catch(() => {});

  return res.status(200).json({
    success: true,
    csrfToken,
    user: {
      id: found.id,
      username: found.row.username,
      role: found.row.role,
      email: found.data.email || '',
      expiry_date: found.data.expiry_date || ''
    }
  });
}

async function handleRegister(req, res, ip, fp) {
  const { username, password, confirmPassword, phone, email, paket, harga, captchaToken } = req.body || {};

  const vu = isValidUsername(username);
  if (!vu.valid) return res.status(200).json({ success: false, message: vu.message });
  if (!password || password.length < 6) return res.status(200).json({ success: false, message: 'Password minimal 6 karakter' });
  if (password !== confirmPassword) return res.status(200).json({ success: false, message: 'Konfirmasi password tidak cocok' });
  if (!phone || phone.length < 10) return res.status(200).json({ success: false, message: 'Nomor telepon tidak valid' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(200).json({ success: false, message: 'Email tidak valid' });
  if (!paket) return res.status(200).json({ success: false, message: 'Paket belum dipilih' });

  if (CONFIG.RECAPTCHA_V2_SECRET) {
    let captchaOk = false;
    try { captchaOk = await verifyRecaptchaV2(captchaToken); } catch (e) { captchaOk = false; }
    if (!captchaOk) {
      return res.status(200).json({ success: false, error: 'captcha_failed', message: 'reCAPTCHA tidak valid' });
    }
  }

  if (await isIPBlocked(ip).catch(() => false) || (fp && await isFPBlocked(fp).catch(() => false))) {
    return res.status(200).json({ success: false, error: 'blocked', message: 'Akses ditolak' });
  }
  if (await findUserByUsername(vu.username)) {
    return res.status(200).json({ success: false, error: 'username_exists', message: 'Username sudah terdaftar' });
  }
  if (await findUserByEmail(email)) {
    return res.status(200).json({ success: false, error: 'email_exists', message: 'Email sudah terdaftar' });
  }

  const limit = await checkRegisterLimit(ip, fp);
  if (!limit.allowed) {
    return res.status(200).json({ success: false, error: 'ip_limit', message: limit.reason });
  }

  const id = db.ref('users').push().key;
  const password_hash = await hashPassword(password);

  await saveUser(id, {
    username: vu.username,
    role: 'User',
    status: 'pending',
    banned: false,
    accessBanned: false,
    forceLogout: false,
    createdAt: Date.now(),
    email: sanitize(email, 200),
    phone: sanitize(phone, 30),
    paket: sanitize(paket, 50),
    harga: Number(harga) || 0,
    password_hash,
    ipHistory: ip ? [ip] : [],
    fpHistory: fp ? [fp] : [],
    lockedFP: fp || '',
    lockedIP: ip || '',
    lockedAt: Date.now(),
    resetCount: 0
  });

  await markRegisterLimit(ip, fp, vu.username);
  await logActivity(vu.username, 'register', `Pendaftaran paket ${paket}`, ip, fp).catch(() => {});
  return res.status(200).json({ success: true, message: 'Pendaftaran berhasil, tunggu aktivasi admin' });
}

async function handleLogout(req, res, ip, fp) {
  const session = verifySession(req);
  if (session) await logActivity(session.username, 'logout', 'Logout', ip, fp).catch(() => {});
  clearSessionCookie(res);
  return res.status(200).json({ success: true });
}

async function handleRequestReset(req, res, ip, fp) {
  const { username, captchaToken } = req.body || {};
  if (!username || username.length < 3) {
    return res.status(200).json({ success: false, message: 'Username minimal 3 karakter' });
  }

  if (CONFIG.RECAPTCHA_V2_SECRET) {
    let captchaOk = false;
    try { captchaOk = await verifyRecaptchaV2(captchaToken); } catch (e) { captchaOk = false; }
    if (!captchaOk) {
      return res.status(200).json({ success: false, error: 'captcha_failed', message: 'reCAPTCHA tidak valid' });
    }
  }

  const found = await findUserByUsername(username);
  if (!found || !found.data.email) {
    return res.status(200).json({ success: true, message: 'Jika username terdaftar, link reset akan dikirim' });
  }

  const limit = await checkResetLimit(found.id);
  if (!limit.allowed) {
    return res.status(200).json({ success: false, error: 'reset_limit', message: limit.reason });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = Date.now() + CONFIG.RESET_TOKEN_EXPIRY;

  await db.ref(`reset_tokens/${tokenHash}`).set({
    userId: found.id,
    username: found.row.username,
    expiresAt
  });

  const updated = {
    ...found.data,
    resetToken: token,
    resetTokenExpiry: expiresAt
  };
  await saveUser(found.id, {
    ...updated,
    username: found.row.username,
    role: found.row.role,
    status: found.row.status
  });

  await recordReset(found.id, ip, fp);

  const link = `${CONFIG.BASE_URL}/pages/confirm-password?token=${token}`;

  if (CONFIG.RESEND_API_KEY) {
    try {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${CONFIG.RESEND_API_KEY}`
        },
        body: JSON.stringify({
          from: CONFIG.EMAIL_FROM,
          to: [found.data.email],
          subject: 'Reset Password',
          html: `<p>Klik link berikut untuk reset password:</p><p><a href="${link}">${link}</a></p><p>Link expired dalam 15 menit.</p>`
        })
      });
    } catch (e) { console.error('email error:', e?.message); }
  }

  await logActivity(username, 'request_reset', 'Link reset dikirim', ip, fp).catch(() => {});
  const parts = found.data.email.split('@');
  const masked = parts[0].slice(0, 1) + '***@' + parts[1];
  return res.status(200).json({ success: true, maskedEmail: masked, message: 'Link reset dikirim' });
}

async function handleVerifyToken(req, res) {
  const { token } = req.body || {};
  if (!token || token.length < 10) {
    return res.status(200).json({ valid: false, message: 'Link tidak valid' });
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const snap = await db.ref(`reset_tokens/${tokenHash}`).once('value');

  if (!snap.exists()) {
    return res.status(200).json({ valid: false, message: 'Link tidak valid' });
  }

  const d = snap.val();
  if (Date.now() > (d.expiresAt || 0)) {
    await db.ref(`reset_tokens/${tokenHash}`).remove();
    return res.status(200).json({ valid: false, error: 'token_expired', message: 'Link expired' });
  }

  return res.status(200).json({ valid: true });
}

async function handleConfirmReset(req, res, ip, fp) {
  const { token, newPassword, captchaToken } = req.body || {};
  if (!token || !newPassword || newPassword.length < 6) {
    return res.status(200).json({ success: false, message: 'Data tidak valid' });
  }

  if (CONFIG.RECAPTCHA_V2_SECRET) {
    let captchaOk = false;
    try { captchaOk = await verifyRecaptchaV2(captchaToken); } catch (e) { captchaOk = false; }
    if (!captchaOk) {
      return res.status(200).json({ success: false, message: 'reCAPTCHA tidak valid' });
    }
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const snap = await db.ref(`reset_tokens/${tokenHash}`).once('value');

  if (!snap.exists()) {
    return res.status(200).json({ success: false, message: 'Link tidak valid' });
  }

  const tokenData = snap.val();
  if (Date.now() > (tokenData.expiresAt || 0)) {
    await db.ref(`reset_tokens/${tokenHash}`).remove();
    return res.status(200).json({ success: false, error: 'token_expired', message: 'Link expired' });
  }

  const userSnap = await db.ref(`users/${tokenData.userId}`).once('value');
  if (!userSnap.exists()) {
    await db.ref(`reset_tokens/${tokenHash}`).remove();
    return res.status(200).json({ success: false, message: 'User tidak ditemukan' });
  }

  const row = userSnap.val();
  const d = decryptAtRest(row.data) || {};
  const password_hash = await hashPassword(newPassword);

  const updated = { ...d, password_hash, resetCount: Number(d.resetCount || 0) + 1 };
  delete updated.resetToken;
  delete updated.resetTokenExpiry;

  await saveUser(tokenData.userId, {
    ...updated,
    username: row.username,
    role: row.role,
    status: row.status
  });

  await db.ref(`reset_tokens/${tokenHash}`).remove();
  await logActivity(row.username, 'reset_password', 'Password direset', ip, fp).catch(() => {});

  return res.status(200).json({ success: true, message: 'Password berhasil diubah' });
}

export default async function handler(req, res) {
  try {
    setSecurityHeaders(res);
    setCorsHeaders(req, res);
    if (!methodGuard(req, res, ['GET', 'POST'])) return;
    if (!enforceOrigin(req, res)) return;
    if (!bodyGuard(req, res)) return;

    const action = String(req.query.action || '').toLowerCase();
    const ip = getIP(req);
    const fp = fpOf(req);

    if (action === 'sign-fp') return await handleSignFingerprint(req, res);
    if (action === 'login') return await handleLogin(req, res, ip, fp);
    if (action === 'register') return await handleRegister(req, res, ip, fp);
    if (action === 'logout') return await handleLogout(req, res, ip, fp);
    if (action === 'request-reset') return await handleRequestReset(req, res, ip, fp);
    if (action === 'verify-token') return await handleVerifyToken(req, res);
    if (action === 'confirm-reset') return await handleConfirmReset(req, res, ip, fp);
    return res.status(404).json({ success: false, message: `Action tidak dikenal: ${action}` });
  } catch (e) {
    console.error('[auth] FATAL:', e?.stack || e?.message || e);
    if (!res.headersSent) {
      return res.status(500).json({ success: false, message: 'Internal server error', error: e?.message });
    }
  }
}