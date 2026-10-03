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

function verifySessionFromToken(token) {
  const parts = token.split('.');
  if (parts.length !== 5) return null;
  try {
    const iv = Buffer.from(parts[1], 'base64url');
    const tag = Buffer.from(parts[2], 'base64url');
    const ct = Buffer.from(parts[3], 'base64url');
    const SESSION_KEY = crypto.createHash('sha256').update(CONFIG.SESSION_SECRET || 'fallback').digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', SESSION_KEY, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
    return JSON.parse(pt);
  } catch {
    return null;
  }
}

function resetEmailHtml(resetLink) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Reset Password - Web Top Up BUSSID</title>
<style>
  body,table,td,a{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}
  table,td{mso-table-lspace:0;mso-table-rspace:0}
  img{-ms-interpolation-mode:bicubic;border:0;height:auto;line-height:100%;outline:none;text-decoration:none}
  body{margin:0;padding:0;width:100%!important;background:#F0F4F8;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif}
  a{text-decoration:none}
  @media screen and (max-width:600px){.container{width:100%!important}.px{padding-left:24px!important;padding-right:24px!important}.h1{font-size:24px!important}.btn-link{display:block!important;width:100%!important;padding:16px 20px!important;box-sizing:border-box!important}}
</style>
</head>
<body style="margin:0;padding:0;background:#F0F4F8;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
<div style="display:none;font-size:1px;color:#F0F4F8;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;">Reset password untuk akun Web Top Up BUSSID kamu.</div>
<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background:#F0F4F8;">
<tr><td align="center" style="padding:48px 20px;">
<table class="container" role="presentation" border="0" cellpadding="0" cellspacing="0" width="480" style="max-width:480px;background:#FFFFFF;border:3px solid #0F172A;border-radius:16px;box-shadow:8px 8px 0 #0F172A;">
<tr><td class="px" style="padding:40px 40px 32px;">
<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
<tr><td align="center">
<table role="presentation" border="0" cellpadding="0" cellspacing="0" align="center">
<tr><td style="display:inline-block;padding:6px 16px;background:#00BFFF;border:2px solid #0F172A;border-radius:999px;box-shadow:3px 3px 0 #0F172A;">
<span style="font-size:11px;font-weight:800;letter-spacing:1.5px;color:#FFFFFF;text-transform:uppercase;font-family:'Inter',Arial,sans-serif;white-space:nowrap;">Web Top Up BUSSID</span>
</td></tr>
</table>
</td></tr>
</table>
<h1 class="h1" style="margin:0 0 16px;font-size:28px;font-weight:900;letter-spacing:-0.8px;color:#0F172A;line-height:1.15;font-family:'Inter',Arial,sans-serif;">Reset password</h1>
<p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#475569;font-weight:400;font-family:'Inter',Arial,sans-serif;">Kami menerima permintaan reset password untuk akun kamu. Klik tombol di bawah untuk membuat password baru.</p>
<p style="margin:0 0 28px;font-size:15px;line-height:1.6;color:#475569;font-weight:400;font-family:'Inter',Arial,sans-serif;">Link ini berlaku selama <strong style="color:#B45309;font-weight:800;background:#FEF3C7;padding:1px 6px;border-radius:4px;">15 menit</strong>. Kalau kamu tidak meminta reset password, abaikan email ini.</p>
<table role="presentation" border="0" cellpadding="0" cellspacing="0" align="center" style="margin:0 auto 36px;">
<tr><td align="center" valign="middle" bgcolor="#00BFFF" style="background:#00BFFF;border:3px solid #0F172A;border-radius:10px;box-shadow:4px 4px 0 #0F172A;">
<a class="btn-link" href="${resetLink}" target="_blank" style="display:inline-block;padding:14px 32px;font-size:14px;font-weight:900;letter-spacing:0.8px;text-transform:uppercase;color:#FFFFFF;text-decoration:none;font-family:'Inter',Arial,sans-serif;text-align:center;line-height:1.2;">Reset password</a>
</td></tr>
</table>
<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:20px;">
<tr><td style="border-top:2px dashed #CBD5E1;height:1px;line-height:1px;font-size:0;">&nbsp;</td></tr>
</table>
<p style="margin:0 0 8px;font-size:13px;line-height:1.5;color:#94A3B8;font-weight:400;font-family:'Inter',Arial,sans-serif;">Tombol tidak berfungsi? Copy link di bawah ini ke browser kamu.</p>
<p style="margin:0;font-size:13px;line-height:1.5;font-weight:600;font-family:'Inter',Arial,sans-serif;word-break:break-all;"><a href="${resetLink}" style="color:#0095CC;text-decoration:none;word-break:break-all;">${resetLink}</a></p>
</td></tr>
</table>
<table class="container" role="presentation" border="0" cellpadding="0" cellspacing="0" width="480" style="max-width:480px;margin-top:24px;">
<tr><td class="px" style="padding:0 20px;text-align:center;">
<p style="margin:0;font-size:12px;line-height:1.5;color:#94A3B8;font-weight:400;font-family:'Inter',Arial,sans-serif;">Email otomatis. Jangan dibalas.</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
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

  // ─── FIX: kalau user tidak ada ATAU role-nya admin, anggap "username atau password salah"
  //          (jangan bocorkan info kalau dia admin)
  if (!found) {
    await logActivity(username, 'login_failed', 'User tidak ditemukan', ip, fp).catch(() => {});
    return res.status(200).json({ success: false, message: 'Username atau password salah' });
  }

  if (String(found.row.role || '').toLowerCase() === 'admin') {
    await logActivity(username, 'login_admin_via_user_page', 'Admin coba login di halaman user', ip, fp).catch(() => {});
    // samarkan sebagai "username atau password salah" biar tidak bisa enumerasi role
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

  const expiry = found.data.expiry_date || '';
  if (!expiry) {
    await logActivity(username, 'login_no_expiry', 'Masa aktif tidak diset', ip, fp).catch(() => {});
    return res.status(200).json({
      success: false,
      message: 'Username atau password salah'
    });
  }
  if (!String(expiry).includes('9999')) {
    const expiryDate = new Date(expiry);
    if (isNaN(expiryDate.getTime())) {
      await logActivity(username, 'login_bad_expiry', 'Format masa aktif tidak valid', ip, fp).catch(() => {});
      return res.status(200).json({
        success: false,
        message: 'Username atau password salah'
      });
    }
    expiryDate.setHours(23, 59, 59, 999);
    if (Date.now() > expiryDate.getTime()) {
      await logActivity(username, 'login_expired', 'Akun expired', ip, fp).catch(() => {});
      return res.status(200).json({
        success: false,
        expired: true,
        message: 'Masa aktif akun habis. Hubungi admin untuk perpanjang.'
      });
    }
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

  const session = verifySessionFromToken(sessionToken);
  const csrfToken = generateCSRFToken(session);

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

function maskEmail(email) {
  if (!email || typeof email !== 'string') return '';
  const parts = email.split('@');
  if (parts.length !== 2) return email;
  const local = parts[0];
  const domain = parts[1];
  if (local.length <= 2) return local[0] + '***@' + domain;
  return local.slice(0, 2) + '***' + local.slice(-1) + '@' + domain;
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

  // Samarkan: kalau user tidak ada ATAU role admin ATAU tidak punya email, kasih response generic
  const isUserReal = found
    && String(found.row.role || '').toLowerCase() !== 'admin'
    && found.data.email;

  if (!isUserReal) {
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

  await recordReset(found.id, ip, fp);

  const resetLink = `${CONFIG.BASE_URL}/pages/confirm-password?token=${token}`;

  if (CONFIG.RESEND_API_KEY) {
    try {
      const emailRes = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${CONFIG.RESEND_API_KEY}`
        },
        body: JSON.stringify({
          from: CONFIG.EMAIL_FROM,
          to: [found.data.email],
          subject: 'Reset Password - Web Top Up BUSSID',
          html: resetEmailHtml(resetLink)
        })
      });
      if (!emailRes.ok) {
        console.error('Resend error:', await emailRes.text());
      }
    } catch (e) { console.error('email error:', e?.message); }
  } else {
    console.warn('[auth] RESEND_API_KEY tidak di-set. Email tidak dikirim. Link:', resetLink);
  }

  await logActivity(username, 'request_reset', 'Link reset dikirim', ip, fp).catch(() => {});
  const masked = maskEmail(found.data.email);
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
  if (String(row.role || '').toLowerCase() === 'admin') {
    await db.ref(`reset_tokens/${tokenHash}`).remove();
    return res.status(200).json({ success: false, message: 'Link tidak valid' });
  }

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