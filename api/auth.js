import crypto from 'node:crypto';
import { db } from './rvns/db.js';
import { CONFIG } from './rvns/config.js';
import {
  hashPassword, verifyPassword, decryptAtRest, sanitize,
  findUserByUsername, findUserByEmail, saveUser, isValidUsername,
  isIPBlocked, isFPBlocked, logActivity,
  verifyRecaptchaV2, ipOf, fpOf
} from './rvns/helper.js';
import {
  createSessionToken, setSessionCookie, clearSessionCookie,
  generateCSRFToken, verifySession
} from './rvns/session.js';
import {
  setSecurityHeaders, setCorsHeaders, enforceOrigin, methodGuard, bodyGuard
} from './rvns/middleware.js';

async function handleLogin(req, res, ip, fp) {
  const { username, password, captchaToken } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });
  }
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
  if (found.row.status === 'pending') {
    return res.status(200).json({ success: false, error: 'pending_activation', message: 'Akun belum diaktivasi admin' });
  }
  if (found.row.status === 'rejected') {
    return res.status(200).json({ success: false, error: 'rejected', message: 'Akun ditolak admin' });
  }
  if (found.row.banned) {
    await logActivity(username, 'login_banned', 'Akun dibanned', ip, fp);
    return res.status(200).json({
      success: false, banned: true,
      bannedUntil: found.data.bannedUntil || 0,
      message: 'Akun dibanned'
    });
  }
  if (found.row.accessBanned) {
    await logActivity(username, 'login_ban_akses', 'Ban akses aktif', ip, fp);
    return res.status(200).json({
      success: false, banAkses: true,
      banAksesUntil: found.data.banAksesUntil || 0,
      message: 'Akses dibatasi'
    });
  }
  if (found.row.forceLogout) {
    await logActivity(username, 'login_force_logout', 'Force logout aktif', ip, fp);
    return res.status(200).json({ success: false, forceLogout: true, message: 'Akun ditangguhkan' });
  }

  const ok = await verifyPassword(password, found.data.password_hash);
  if (!ok) {
    await logActivity(username, 'login_failed', 'Password salah', ip, fp);
    return res.status(200).json({ success: false, message: 'Username atau password salah' });
  }

  const updated = { ...found.data };

  // ═══ SET lockedFP + lockedIP di login (KUNCI ANTI MENTAL) ═══
  const currentLockedFP = updated.lockedFP || '';
  const currentLockedIP = updated.lockedIP || '';
  const fpInHistory = Array.isArray(updated.fpHistory) && updated.fpHistory.includes(fp);
  const ipInHistory = Array.isArray(updated.ipHistory) && updated.ipHistory.includes(ip);

  if (!currentLockedFP && fp) {
    updated.lockedFP = fp;
    updated.lockedIP = ip || '';
    updated.lockedAt = Date.now();
  }
  else if (currentLockedFP === fp) {
    updated.lockedIP = ip || currentLockedIP;
  }
  else if (fpInHistory || ipInHistory) {
    updated.lockedFP = fp;
    updated.lockedIP = ip || '';
    updated.fpChangedAt = Date.now();
    updated.fpChangedFrom = currentLockedFP;
  }
  else {
    updated.lockedFP = fp;
    updated.lockedIP = ip || '';
    updated.fpChangedAt = Date.now();
    updated.fpChangedFrom = currentLockedFP;
  }
  // ══════════════════════════════════════════════════════════

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
  const csrfSession = { uid: found.id, username: found.row.username, role: found.row.role };
  const csrfToken = generateCSRFToken(csrfSession);
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
  const { username, password, confirmPassword, phone, email, paket, harga, captchaToken } = req.body || {};

  const vu = isValidUsername(username);
  if (!vu.valid) return res.status(200).json({ success: false, message: vu.message });
  if (!password || password.length < 6) return res.status(200).json({ success: false, message: 'Password minimal 6 karakter' });
  if (password !== confirmPassword) return res.status(200).json({ success: false, message: 'Konfirmasi password tidak cocok' });
  if (!phone || phone.length < 10) return res.status(200).json({ success: false, message: 'Nomor telepon tidak valid' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(200).json({ success: false, message: 'Email tidak valid' });
  if (!paket) return res.status(200).json({ success: false, message: 'Paket belum dipilih' });

  if (!(await verifyRecaptchaV2(captchaToken))) {
    return res.status(200).json({ success: false, error: 'captcha_failed', message: 'reCAPTCHA tidak valid' });
  }
  if (await isIPBlocked(ip) || (fp && await isFPBlocked(fp))) {
    return res.status(200).json({ success: false, error: 'blocked', message: 'Akses ditolak' });
  }
  if (await findUserByUsername(vu.username)) {
    return res.status(200).json({ success: false, error: 'username_exists', message: 'Username sudah terdaftar' });
  }
  if (await findUserByEmail(email)) {
    return res.status(200).json({ success: false, error: 'email_exists', message: 'Email sudah terdaftar' });
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

  await logActivity(vu.username, 'register', `Pendaftaran paket ${paket}`, ip, fp);
  return res.status(200).json({ success: true, message: 'Pendaftaran berhasil, tunggu aktivasi admin' });
}

async function handleLogout(req, res, ip, fp) {
  const session = verifySession(req);
  if (session) await logActivity(session.username, 'logout', 'Logout', ip, fp);
  clearSessionCookie(res);
  return res.status(200).json({ success: true });
}

async function handleRequestReset(req, res, ip, fp) {
  const { username, captchaToken } = req.body || {};
  if (!username || username.length < 3) {
    return res.status(200).json({ success: false, message: 'Username minimal 3 karakter' });
  }
  if (!(await verifyRecaptchaV2(captchaToken))) {
    return res.status(200).json({ success: false, error: 'captcha_failed', message: 'reCAPTCHA tidak valid' });
  }

  const found = await findUserByUsername(username);
  if (!found || !found.data.email) {
    return res.status(200).json({ success: true, message: 'Jika username terdaftar, link reset akan dikirim' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const updated = {
    ...found.data,
    resetToken: token,
    resetTokenExpiry: Date.now() + CONFIG.RESET_TOKEN_EXPIRY
  };
  await saveUser(found.id, {
    ...updated,
    username: found.row.username,
    role: found.row.role,
    status: found.row.status
  });

  // ═══ FIX: BASE_URL fallback ke Vercel URL ═══
  const baseUrl = (CONFIG.BASE_URL || '').replace(/\/$/, '') ||
                  (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : '') ||
                  'https://hsvshsvavah-fawn.vercel.app';
  const link = `${baseUrl}/pages/confirm-password?token=${token}`;

  if (CONFIG.RESEND_API_KEY) {
    try {
      const emailHtml = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>Reset Password - Top Up BUSSID</title>
<style>
  body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
  table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
  img { -ms-interpolation-mode: bicubic; border: 0; height: auto; line-height: 100%; outline: none; text-decoration: none; }
  body { margin: 0; padding: 0; width: 100% !important; background: #F0F4F8; font-family: 'Inter', Arial, Helvetica, sans-serif; }
  a { text-decoration: none; }
  @media screen and (max-width: 600px) {
    .container { width: 100% !important; }
    .px { padding-left: 20px !important; padding-right: 20px !important; }
    .h1 { font-size: 22px !important; line-height: 1.2 !important; }
    .btn { display: block !important; width: 100% !important; padding: 18px 20px !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#F0F4F8;font-family:'Inter',Arial,Helvetica,sans-serif;">

  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background:#F0F4F8;">
    <tr>
      <td align="center" style="padding:40px 20px;">

        <table class="container" role="presentation" border="0" cellpadding="0" cellspacing="0" width="520" style="max-width:520px;background:#FFFFFF;border:3px solid #0F172A;border-radius:14px;box-shadow:6px 6px 0 #0F172A;">

          <tr>
            <td class="px" style="padding:40px 40px 8px;text-align:center;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" align="center" style="margin:0 auto;">
                <tr>
                  <td style="display:inline-block;padding:7px 16px;background:#00BFFF;border:2px solid #0F172A;border-radius:999px;box-shadow:3px 3px 0 #0F172A;">
                    <span style="font-size:11px;font-weight:900;letter-spacing:2px;color:#FFFFFF;text-transform:uppercase;font-family:'Inter',Arial,sans-serif;">
                      TOP UP BUSSID
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td class="px" style="padding:24px 40px 12px;text-align:center;">
              <h1 class="h1" style="margin:0;font-size:26px;font-weight:900;letter-spacing:-0.5px;color:#0F172A;line-height:1.2;font-family:'Inter',Arial,sans-serif;">
                Reset Password
              </h1>
            </td>
          </tr>

          <tr>
            <td class="px" style="padding:0 40px 32px;text-align:center;">
              <p style="margin:0;font-size:14px;line-height:1.6;color:#64748B;font-weight:500;font-family:'Inter',Arial,sans-serif;">
                Kami menerima permintaan reset password untuk akun kamu. Klik tombol di bawah untuk membuat password baru.
              </p>
            </td>
          </tr>

          <tr>
            <td class="px" style="padding:0 40px 20px;text-align:center;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:separate;">
                <tr>
                  <td align="center" style="background:#00BFFF;border:3px solid #0F172A;border-radius:12px;box-shadow:4px 4px 0 #0F172A;text-align:center;">
                    <a class="btn" href="${link}" target="_blank" style="display:block;padding:16px 32px;font-size:13px;font-weight:900;letter-spacing:1.5px;text-transform:uppercase;color:#FFFFFF;text-decoration:none;font-family:'Inter',Arial,sans-serif;text-align:center;line-height:1.2;">
                      Ganti Password
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td class="px" style="padding:0 40px 32px;text-align:center;">
              <p style="margin:0 0 8px;font-size:12px;line-height:1.6;color:#94A3B8;font-weight:600;font-family:'Inter',Arial,sans-serif;">
                Jika tombol tidak berfungsi, pencet link di bawah ini:
              </p>
              <p style="margin:0;font-size:11px;line-height:1.5;color:#0095CC;font-weight:700;font-family:'JetBrains Mono','Courier New',monospace;word-break:break-all;">
                <a href="${link}" style="color:#0095CC;text-decoration:underline;word-break:break-all;">
                  ${link}
                </a>
              </p>
            </td>
          </tr>

          <tr>
            <td class="px" style="padding:0 40px 32px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td style="border-top:2px dashed #94A3B8;height:1px;line-height:1px;font-size:0;">&nbsp;</td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td class="px" style="padding:0 40px 40px;text-align:center;">
              <p style="margin:0;font-size:12px;line-height:1.6;color:#94A3B8;font-weight:600;font-family:'Inter',Arial,sans-serif;">
                Link berlaku 1x24 jam. Kalau kamu tidak meminta reset password, abaikan email ini.
              </p>
            </td>
          </tr>

        </table>

        <table class="container" role="presentation" border="0" cellpadding="0" cellspacing="0" width="520" style="max-width:520px;margin-top:20px;">
          <tr>
            <td class="px" style="padding:0 20px;text-align:center;">
              <p style="margin:0;font-size:11px;line-height:1.6;color:#94A3B8;font-weight:600;font-family:'Inter',Arial,sans-serif;">
                © 2026 Revan Store · Email otomatis, jangan dibalas
              </p>
            </td>
          </tr>
        </table>

      </td>
    </tr>
  </table>

</body>
</html>`;

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
          html: emailHtml
        })
      });
    } catch (e) { console.error('email error:', e?.message); }
  }

  await logActivity(username, 'request_reset', 'Link reset dikirim', ip, fp);
  const parts = found.data.email.split('@');
  const masked = parts[0].slice(0, 1) + '***@' + parts[1];
  return res.status(200).json({ success: true, maskedEmail: masked, message: 'Link reset dikirim' });
}

async function handleVerifyToken(req, res) {
  const { token } = req.body || {};
  if (!token || token.length < 10) {
    return res.status(200).json({ valid: false, message: 'Link tidak valid' });
  }
  const all = await db.ref('users').once('value');
  for (const [id, row] of Object.entries(all.val() || {})) {
    const d = decryptAtRest(row.data) || {};
    if (d.resetToken === token) {
      if (Date.now() > (d.resetTokenExpiry || 0)) {
        return res.status(200).json({ valid: false, error: 'token_expired', message: 'Link expired' });
      }
      return res.status(200).json({ valid: true });
    }
  }
  return res.status(200).json({ valid: false, message: 'Link tidak valid' });
}

async function handleConfirmReset(req, res, ip, fp) {
  const { token, newPassword, captchaToken } = req.body || {};
  if (!token || !newPassword || newPassword.length < 6) {
    return res.status(200).json({ success: false, message: 'Data tidak valid' });
  }
  if (!(await verifyRecaptchaV2(captchaToken))) {
    return res.status(200).json({ success: false, message: 'reCAPTCHA tidak valid' });
  }

  const all = await db.ref('users').once('value');
  for (const [id, row] of Object.entries(all.val() || {})) {
    const d = decryptAtRest(row.data) || {};
    if (d.resetToken === token) {
      if (Date.now() > (d.resetTokenExpiry || 0)) {
        return res.status(200).json({ success: false, error: 'token_expired', message: 'Link expired' });
      }
      const password_hash = await hashPassword(newPassword);
      const updated = { ...d, password_hash, resetCount: Number(d.resetCount || 0) + 1 };
      delete updated.resetToken;
      delete updated.resetTokenExpiry;
      await saveUser(id, {
        ...row,
        ...updated,
        username: row.username,
        role: row.role,
        status: row.status
      });
      await logActivity(row.username, 'reset_password', 'Password direset', ip, fp);
      return res.status(200).json({ success: true, message: 'Password berhasil diubah' });
    }
  }
  return res.status(200).json({ success: false, message: 'Link tidak valid' });
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
    if (action === 'request-reset') return handleRequestReset(req, res, ip, fp);
    if (action === 'verify-token') return handleVerifyToken(req, res);
    if (action === 'confirm-reset') return handleConfirmReset(req, res, ip, fp);
    return res.status(404).json({ success: false, message: `Action tidak dikenal: ${action}` });
  } catch (e) {
    console.error('[auth]', e?.stack || e?.message || e);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
}