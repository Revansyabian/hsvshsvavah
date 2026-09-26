import { db } from './rvns/db.js';
import { CONFIG } from './rvns/config.js';
import {
  hashPassword,
  isValidUsername,
  logActivity,
  encryptAtRest,
  sanitize,
  getIP,
  fpOf
} from './rvns/helper.js';
import {
  setSecurityHeaders,
  setCorsHeaders,
  enforceOrigin,
  methodGuard,
  bodyGuard
} from './rvns/middleware.js';
import crypto from 'node:crypto';

/**
 * Constant-time string compare via SHA-256 hash.
 * Lebih aman dari compare panjang dulu, karena hash-nya selalu 32 byte
 * dan tidak bocorkan panjang string asli lewat timing.
 */
function timingSafeEqualStr(a, b) {
  try {
    const ha = crypto.createHash('sha256').update(String(a || '')).digest();
    const hb = crypto.createHash('sha256').update(String(b || '')).digest();
    return crypto.timingSafeEqual(ha, hb);
  } catch (e) {
    return false;
  }
}

/**
 * Cek apakah value adalah admin row (bukan key lain seperti 'auth', 'session', dll)
 */
function isAdminRow(row) {
  if (!row || typeof row !== 'object') return false;
  // Admin row minimal punya: username, role, data
  return typeof row.username === 'string' && typeof row.data === 'object';
}

export default async function handler(req, res) {
  setSecurityHeaders(res);
  setCorsHeaders(req, res);
  if (!methodGuard(req, res, ['POST'])) return;
  if (!enforceOrigin(req, res)) return;
  if (!bodyGuard(req, res)) return;

  const ip = getIP(req);
  const fp = fpOf(req);

  try {
    // ── Cek sudah ada admin atau belum ──
    const existingSnap = await db.ref('admin').once('value');
    const admins = existingSnap.val() || {};
    let adminCount = 0;
    for (const [key, row] of Object.entries(admins)) {
      if (isAdminRow(row)) adminCount++;
    }
    if (adminCount > 0) {
      return res.status(403).json({ success: false, message: 'Admin sudah terdaftar. Registrasi ditutup.' });
    }

    const { secretKey, username, email, password, confirmPassword } = req.body || {};

    // ── Validasi secretKey (constant-time) ──
    if (!secretKey || !timingSafeEqualStr(secretKey, CONFIG.ADMIN_KEY)) {
      await logActivity(username || 'unknown', 'admin_register_forbidden', 'Kode akses salah', ip, fp);
      return res.status(403).json({ success: false, message: 'Kode akses salah' });
    }

    // ── Validasi username ──
    const vu = isValidUsername(username);
    if (!vu.valid) return res.status(400).json({ success: false, message: vu.message });

    // ── Validasi email ──
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Email tidak valid' });
    }

    // ── Validasi password ──
    if (!password || password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password minimal 8 karakter' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Konfirmasi password tidak cocok' });
    }

    // ── Validasi FP ──
    if (!fp) {
      return res.status(400).json({ success: false, message: 'Fingerprint tidak terdeteksi' });
    }

    // ── Simpan admin baru ──
    const id = db.ref('admin').push().key;
    const password_hash = await hashPassword(password);

    // Bersihkan history: hanya masukkan kalau valid
    const ipHistory = ip ? [ip] : [];
    const fpHistory = fp ? [fp] : [];

    const adminData = {
      email: sanitize(email, 200),
      password_hash,
      createdAt: Date.now(),
      createdByIP: ip || '',
      createdByFP: fp,
      lockedIP: ip || '',
      lockedFP: fp,
      lastLoginIP: '',
      lastLoginFP: '',
      lastLoginAt: 0,
      ipHistory,
      fpHistory
    };

    await db.ref(`admin/${id}`).set({
      username: sanitize(vu.username, 50),
      role: 'admin',
      status: 'active',
      createdAt: Date.now(),
      lockedIP: ip || '',
      lockedFP: fp,
      data: encryptAtRest(adminData)
    });

    await logActivity(vu.username, 'admin_register_success',
      `Admin baru: ${vu.username} dari IP ${ip || 'unknown'}`, ip, fp);

    return res.status(200).json({
      success: true,
      message: 'Admin berhasil dibuat. Login cuma bisa dari device ini.',
      username: vu.username,
      lockedIP: ip || ''
    });
  } catch (e) {
    console.error('[admin-register]', e?.stack || e?.message || e);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
}