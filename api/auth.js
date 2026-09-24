import crypto from 'node:crypto';
import { db } from './rvns/db.js';
import { CONFIG } from './rvns/config.js';
import {
  hashPassword,
  verifyPassword,
  decryptAny,
  sanitize,
  findUserByUsername,
  findUserByEmail,
  saveUser,
  isValidUsername,
  isIPBlocked,
  isFPBlocked,
  logActivity,
  verifyRecaptchaV2,
  ipOf,
  fpOf,
  checkRegisterLimit,
  markRegisterLimit,
  releaseRegisterLimit,
  checkResetLimit,
  recordReset
} from './rvns/helper.js';
import {
  createSessionToken,
  setSessionCookie,
  clearSessionCookie,
  generateCSRFToken,
  verifySession
} from './rvns/session.js';
import {
  setSecurityHeaders,
  setCorsHeaders,
  enforceOrigin,
  methodGuard,
  bodyGuard
} from './rvns/middleware.js';

function requestBody(req) {
  return req.body && typeof req.body === 'object' ? req.body : {};
}

function baseUrl(req) {
  const configured = String(CONFIG.BASE_URL || '').replace(/\/$/, '');
  if (configured) return configured;
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = String(req.headers.host || '').trim();
  return host ? `${proto}://${host}` : '';
}

function maskEmail(email) {
  const [name, domain] = String(email || '').split('@');
  if (!name || !domain) return '';
  return `${name.slice(0, 1)}***@${domain}`;
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function handleLogin(req, res, ip, fp) {
  const { username, password, captchaToken } = requestBody(req);
  if (!username || !password) return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });
  if (!(await verifyRecaptchaV2(captchaToken))) {
    await logActivity(username, 'login_captcha_fail', 'reCAPTCHA gagal', ip, fp);
    return res.status(200).json({ success: false, error: 'captcha_failed', message: 'Verifikasi reCAPTCHA gagal' });
  }
  if (await isIPBlocked(ip) || (fp && await isFPBlocked(fp))) {
    await logActivity(username, 'login_blocked', 'IP/FP diblokir', ip, fp);
    return res.status(200).json({ success: false, error: 'blocked', message: 'IP atau perangkat diblokir' });
  }

  const found = await findUserByUsername(username);
  if (!found) {
    await logActivity(username, 'login_failed', 'User tidak ditemukan', ip, fp);
    return res.status(200).json({ success: false, message: 'Username atau password salah' });
  }

  if (found.row.activationStatus === 'pending' || found.row.status === 'pending') {
    return res.status(200).json({ success: false, error: 'pending_activation', message: 'Akun belum diaktivasi admin' });
  }
  if (found.row.activationStatus === 'rejected' || found.row.status === 'rejected') {
    return res.status(200).json({ success: false, error: 'rejected', message: 'Akun ditolak admin' });
  }
  if (found.row.banned) {
    await logActivity(username, 'login_banned', 'Akun dibanned', ip, fp);
    return res.status(200).json({ success: false, banned: true, bannedUntil: found.data.bannedUntil || 0, message: 'Akun dibanned' });
  }
  if (found.row.accessBanned) {
    await logActivity(username, 'login_ban_akses', 'Ban akses aktif', ip, fp);
    return res.status(200).json({ success: false, banAkses: true, banAksesUntil: found.data.banAksesUntil || 0, message: 'Akses dibatasi' });
  }
  if (found.row.forceLogout) {
    await logActivity(username, 'login_force_logout', 'Force logout aktif', ip, fp);
    return res.status(200).json({ success: false, forceLogout: true, message: 'Akun ditangguhkan' });
  }

  if (!(await verifyPassword(password, found.data.password_hash))) {
    await logActivity(username, 'login_failed', 'Password salah', ip, fp);
    return res.status(200).json({ success: false, message: 'Username atau password salah' });
  }

  const updated = { ...found.data };
  updated.lastLogin = { ip, fingerprint: fp, timestamp: Date.now() };
  updated.lastIP = ip;
  updated.lastFP = fp;
  const ipH = Array.isArray(updated.ipHistory) ? updated.ipHistory : [];
  if (ip && (!ipH.length || ipH[ipH.length - 1] !== ip)) ipH.push(ip);
  updated.ipHistory = ipH.slice(-20);
  const fpH = Array.isArray(updated.fpHistory) ? updated.fpHistory : [];
  if (fp && (!fpH.length || fpH[fpH.length - 1] !== fp)) fpH.push(fp);
  updated.fpHistory = fpH.slice(-20);
  if (!updated.lockedIP) updated.lockedIP = ip;
  if (!updated.lockedFP && fp) updated.lockedFP = fp;

  await saveUser(found.id, {
    ...updated,
    username: found.row.username,
    role: found.row.role,
    status: found.row.status,
    registered: found.row.registered,
    activationStatus: found.row.activationStatus,
    approvedAt: found.row.approvedAt,
    approvedBy: found.row.approvedBy,
    approvedIP: found.row.approvedIP,
    approvedFP: found.row.approvedFP,
    rejectedAt: found.row.rejectedAt,
    rejectedBy: found.row.rejectedBy,
    rejectionReason: found.row.rejectionReason,
    banned: found.row.banned,
    accessBanned: found.row.accessBanned,
    forceLogout: found.row.forceLogout,
    createdAt: found.row.createdAt
  });

  const sessionToken = createSessionToken({ id: found.id, username: found.row.username, role: found.row.role });
  const csrfToken = generateCSRFToken({ uid: found.id });
  setSessionCookie(res, sessionToken, csrfToken, { role: found.row.role });
  await logActivity(username, 'login_success', 'Login berhasil', ip, fp);

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
  const body = requestBody(req);
  const { username, password, confirmPassword, phone, email, paket, harga, captchaToken } = body;
  const vu = isValidUsername(username);
  if (!vu.valid) return res.status(200).json({ success: false, message: vu.message });
  if (!password || password.length < 8) return res.status(200).json({ success: false, message: 'Password minimal 8 karakter' });
  if (password !== confirmPassword) return res.status(200).json({ success: false, message: 'Konfirmasi password tidak cocok' });
  if (!phone || !/^\+?62|^08/.test(String(phone))) return res.status(200).json({ success: false, message: 'Nomor telepon tidak valid' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(200).json({ success: false, message: 'Email tidak valid' });
  if (!paket) return res.status(200).json({ success: false, message: 'Paket belum dipilih' });
  if (!(await verifyRecaptchaV2(captchaToken))) return res.status(200).json({ success: false, error: 'captcha_failed', message: 'reCAPTCHA tidak valid' });
  if (await isIPBlocked(ip) || (fp && await isFPBlocked(fp))) return res.status(200).json({ success: false, error: 'blocked', message: 'Akses ditolak' });

  const limit = await checkRegisterLimit(ip, fp);
  if (!limit.allowed) return res.status(200).json({ success: false, error: limit.error, message: limit.reason, retryAfterSeconds: limit.retryAfterSeconds });
  if (await findUserByUsername(vu.username)) return res.status(200).json({ success: false, error: 'username_exists', message: 'Username sudah terdaftar' });
  if (await findUserByEmail(email)) return res.status(200).json({ success: false, error: 'email_exists', message: 'Email sudah terdaftar' });

  const claim = await markRegisterLimit(ip, fp, vu.username);
  if (!claim.allowed) return res.status(200).json({ success: false, error: claim.error, message: 'Kamu sudah mendaftar sebelumnya. Coba lagi nanti.' });

  const id = db.ref('users').push().key;
  const now = Date.now();
  try {
    const password_hash = await hashPassword(password);
    await saveUser(id, {
      username: vu.username,
      role: 'User',
      status: 'pending',
      banned: false,
      accessBanned: false,
      forceLogout: false,
      registered: true,
      activationStatus: 'pending',
      createdAt: now,
      registeredAt: now,
      registeredIP: ip,
      registeredFP: fp,
      email: sanitize(email, 200),
      phone: sanitize(phone, 30),
      paket: sanitize(paket, 50),
      harga: Number(harga) || 0,
      password_hash,
      ipHistory: ip && ip !== 'unknown' ? [ip] : [],
      fpHistory: fp ? [fp] : [],
      resetCount: 0,
      resetHistory: []
    });
  } catch (e) {
    await releaseRegisterLimit(ip, fp);
    throw e;
  }

  await logActivity(vu.username, 'register', `Pendaftaran paket ${paket}`, ip, fp);
  return res.status(200).json({ success: true, message: 'Pendaftaran berhasil, tunggu aktivasi admin' });
}

async function handleLogout(req, res, ip, fp) {
  const session = verifySession(req);
  if (session) await logActivity(session.username, 'logout', 'Logout', ip, fp);
  clearSessionCookie(res);
  return res.status(200).json({ success: true });
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function generateResetToken() {
  const token = crypto.randomBytes(32).toString('hex');
  return {
    token,
    hash: tokenHash(token),
    expiresAt: Date.now() + CONFIG.RESET_TOKEN_EXPIRY
  };
}

function buildResetEmailHtml({ username, email, link }) {
  const safeUsername = escapeHtml(username);
  const safeEmail = escapeHtml(email);
  const safeLink = escapeHtml(link);
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light">
<title>Reset password</title>
<style>
body{margin:0;padding:0;width:100%;background:#F5F7FA;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
table{border-collapse:collapse}
a{color:#00BFFF}
@media screen and (max-width:600px){.container{width:100%!important}.px{padding-left:24px!important;padding-right:24px!important}.h1{font-size:22px!important;line-height:30px!important}.btn{display:block!important;width:100%!important;box-sizing:border-box!important}}
</style>
</head>
<body>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F5F7FA">
<tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="600" class="container" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px">
<tr><td style="padding:0 0 24px">
<table role="presentation" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:999px">
<tr><td style="padding:6px"><div style="width:32px;height:32px;border-radius:50%;background:#00BFFF;color:#fff;text-align:center;font-weight:700;font-size:14px;line-height:32px">U</div></td>
<td style="padding:0 20px 0 12px"><span style="font-size:15px;font-weight:600;color:#0F172A">${safeUsername}</span></td></tr>
</table></td></tr>
<tr><td style="background:#fff;border-radius:12px;overflow:hidden">
<div style="height:4px;background:#00BFFF"></div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td class="px" style="padding:40px 40px 8px">
<h1 class="h1" style="margin:0 0 12px;font-size:24px;line-height:32px;font-weight:600;color:#0F172A">Reset password</h1>
<p style="margin:0;font-size:15px;line-height:24px;color:#64748B">Kami menerima permintaan reset password untuk akun <strong style="color:#0F172A">${safeEmail}</strong>.</p>
</td></tr></table>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td class="px" style="padding:24px 40px 0"><div style="background:#EBF8FF;border-radius:8px;padding:14px 16px;font-size:13px;line-height:20px;color:#0369A1">Link berlaku <strong>15 menit</strong>.</div></td></tr></table>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td class="px" style="padding:32px 40px"><a href="${safeLink}" class="btn" style="display:block;padding:14px 40px;background:#00BFFF;color:#fff;font-size:15px;font-weight:600;text-decoration:none;border-radius:12px;text-align:center">Reset password</a></td></tr></table>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td class="px" style="padding:0 40px 40px"><div style="border-top:1px solid #E2E8F0;padding-top:20px"><p style="margin:0 0 6px;font-size:12px;line-height:18px;color:#94A3B8">Jika tombol tidak berfungsi, buka link berikut:</p><a href="${safeLink}" style="font-size:12px;line-height:18px;word-break:break-all;color:#00BFFF">${safeLink}</a></div></td></tr></table>
</td></tr>
</table></td></tr>
</table>
</body></html>`;
}

async function sendResetPasswordEmail({ email, username, link }) {
  if (!CONFIG.RESEND_API_KEY) return false;
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${CONFIG.RESEND_API_KEY}`
    },
    body: JSON.stringify({
      from: CONFIG.EMAIL_FROM,
      to: [email],
      subject: 'Reset password',
      html: buildResetEmailHtml({ email, username, link })
    })
  });
  return response.ok;
}

async function handleRequestReset(req, res, ip, fp) {
  const { username, captchaToken } = requestBody(req);
  if (!username || username.length < 3) return res.status(200).json({ success: false, error: 'invalid_username', message: 'Username minimal 3 karakter' });
  if (!(await verifyRecaptchaV2(captchaToken))) return res.status(200).json({ success: false, error: 'captcha_failed', message: 'reCAPTCHA tidak valid' });
  if (await isIPBlocked(ip) || (fp && await isFPBlocked(fp))) return res.status(200).json({ success: false, error: 'blocked', message: 'Akses ditolak' });

  const found = await findUserByUsername(username);
  if (!found || !found.data.email) return res.status(200).json({ success: true, message: 'Jika username terdaftar, link reset akan dikirim' });

  const limit = await checkResetLimit(found.id);
  if (!limit.allowed) return res.status(200).json({ success: false, error: 'reset_limit', message: 'Kuota reset habis. Coba lagi nanti.', resetUsed: limit.used, resetRemaining: limit.remaining });

  const generated = generateResetToken();
  await db.ref(`reset_tokens/${generated.hash}`).set({
    userId: found.id,
    expiresAt: generated.expiresAt,
    used: false,
    createdAt: Date.now()
  });

  const oldHash = found.data.resetTokenHash;
  if (oldHash) await db.ref(`reset_tokens/${oldHash}`).remove();

  await saveUser(found.id, {
    ...found.data,
    resetTokenHash: generated.hash,
    username: found.row.username,
    role: found.row.role,
    status: found.row.status,
    registered: found.row.registered,
    activationStatus: found.row.activationStatus,
    approvedAt: found.row.approvedAt,
    approvedBy: found.row.approvedBy,
    approvedIP: found.row.approvedIP,
    approvedFP: found.row.approvedFP,
    rejectedAt: found.row.rejectedAt,
    rejectedBy: found.row.rejectedBy,
    rejectionReason: found.row.rejectionReason,
    banned: found.row.banned,
    accessBanned: found.row.accessBanned,
    forceLogout: found.row.forceLogout,
    createdAt: found.row.createdAt
  });

  const link = `${baseUrl(req)}/pages/confirm-password?token=${encodeURIComponent(generated.token)}`;
  let emailSent = false;
  try {
    emailSent = await sendResetPasswordEmail({
      email: found.data.email,
      username: found.row.username,
      link
    });
  } catch (error) {
    console.error('sendResetPasswordEmail:', error?.message || error);
  }

  if (!emailSent) {
    await db.ref(`reset_tokens/${generated.hash}`).remove();
    await saveUser(found.id, {
      ...found.data,
      username: found.row.username,
      role: found.row.role,
      status: found.row.status,
      registered: found.row.registered,
      activationStatus: found.row.activationStatus,
      approvedAt: found.row.approvedAt,
      approvedBy: found.row.approvedBy,
      approvedIP: found.row.approvedIP,
      approvedFP: found.row.approvedFP,
      rejectedAt: found.row.rejectedAt,
      rejectedBy: found.row.rejectedBy,
      rejectionReason: found.row.rejectionReason,
      banned: found.row.banned,
      accessBanned: found.row.accessBanned,
      forceLogout: found.row.forceLogout,
      createdAt: found.row.createdAt
    });
    return res.status(200).json({ success: false, error: 'email_error', message: 'Gagal mengirim email. Coba lagi nanti.' });
  }

  const resetStats = await checkResetLimit(found.id);
  await logActivity(found.row.username, 'request_reset', 'Link reset password dikirim', ip, fp);
  return res.status(200).json({
    success: true,
    maskedEmail: maskEmail(found.data.email),
    expiresAt: generated.expiresAt,
    message: 'Link reset dikirim',
    resetUsed: resetStats.used,
    resetRemaining: resetStats.remaining
  });
}

async function handleVerifyToken(req, res) {
  const { token } = requestBody(req);
  if (!token || token.length < 32) return res.status(200).json({ valid: false, error: 'token_not_found', message: 'Link tidak valid' });
  const hash = tokenHash(token);
  const snap = await db.ref(`reset_tokens/${hash}`).once('value');
  if (!snap.exists()) return res.status(200).json({ valid: false, error: 'token_not_found', message: 'Link tidak valid' });
  const row = snap.val();
  if (row.used || Number(row.expiresAt || 0) <= Date.now()) {
    if (Number(row.expiresAt || 0) <= Date.now()) await db.ref(`reset_tokens/${hash}`).remove();
    return res.status(200).json({ valid: false, error: 'token_expired', message: 'Link expired' });
  }
  return res.status(200).json({ valid: true, expiresAt: row.expiresAt });
}

async function handleConfirmReset(req, res, ip, fp) {
  const { token, newPassword, captchaToken } = requestBody(req);
  if (!token || !newPassword || newPassword.length < 8) return res.status(200).json({ success: false, message: 'Password minimal 8 karakter' });
  if (!(await verifyRecaptchaV2(captchaToken))) return res.status(200).json({ success: false, error: 'captcha_failed', message: 'reCAPTCHA tidak valid' });

  const hash = tokenHash(token);
  const tokenRef = db.ref(`reset_tokens/${hash}`);
  const claim = await tokenRef.transaction(current => {
    if (!current || current.used || Number(current.expiresAt || 0) <= Date.now()) return;
    return { ...current, used: true, usedAt: Date.now() };
  });
  if (!claim.committed || !claim.snapshot.exists()) {
    const current = (await tokenRef.once('value')).val();
    if (current && Number(current.expiresAt || 0) <= Date.now()) await tokenRef.remove();
    return res.status(200).json({ success: false, error: current?.used ? 'token_not_found' : 'token_expired', message: 'Link tidak valid atau sudah digunakan' });
  }
  const tokenRow = claim.snapshot.val();

  const found = await db.ref(`users/${tokenRow.userId}`).once('value');
  if (!found.exists()) {
    await db.ref(`reset_tokens/${hash}`).remove();
    return res.status(200).json({ success: false, error: 'token_not_found', message: 'Link tidak valid' });
  }

  const row = found.val();
  const data = decryptAny(row.data) || {};
  if (data.resetTokenHash !== hash) return res.status(200).json({ success: false, error: 'token_not_found', message: 'Link tidak valid' });

  const password_hash = await hashPassword(newPassword);
  delete data.resetTokenHash;
  await saveUser(tokenRow.userId, {
    ...data,
    password_hash,
    username: row.username,
    role: row.role,
    status: row.status,
    registered: row.registered,
    activationStatus: row.activationStatus,
    approvedAt: row.approvedAt,
    approvedBy: row.approvedBy,
    approvedIP: row.approvedIP,
    approvedFP: row.approvedFP,
    rejectedAt: row.rejectedAt,
    rejectedBy: row.rejectedBy,
    rejectionReason: row.rejectionReason,
    banned: row.banned,
    accessBanned: row.accessBanned,
    forceLogout: false,
    createdAt: row.createdAt
  });
  const recorded = await recordReset(tokenRow.userId, ip, fp);
  await logActivity(row.username, 'reset_password', 'Password berhasil direset', ip, fp);
  await db.ref(`reset_tokens/${hash}`).remove();

  return res.status(200).json({
    success: true,
    message: 'Password berhasil diubah',
    resetUsed: recorded.used,
    resetRemaining: recorded.remaining
  });
}

export default async function handler(req, res) {
  setSecurityHeaders(res);
  setCorsHeaders(req, res);
  if (!methodGuard(req, res, ['GET', 'POST'])) return;
  if (!enforceOrigin(req, res)) return;
  if (!bodyGuard(req, res)) return;

  const action = String(req.query.action || '').toLowerCase();
  const ip = ipOf(req);
  const fp = fpOf(req);

  try {
    if (action === 'login') return handleLogin(req, res, ip, fp);
    if (action === 'register') return handleRegister(req, res, ip, fp);
    if (action === 'logout') return handleLogout(req, res, ip, fp);
    if (action === 'request-reset' || action === 'request_reset') return handleRequestReset(req, res, ip, fp);
    if (action === 'verify-token' || action === 'verify_token') return handleVerifyToken(req, res);
    if (action === 'confirm-reset' || action === 'confirm_reset') return handleConfirmReset(req, res, ip, fp);
    return res.status(404).json({ success: false, message: `Action tidak dikenal: ${action}` });
  } catch (e) {
    console.error('[auth]', e?.stack || e?.message || e);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
}
