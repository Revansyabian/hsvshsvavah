
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

function timingSafeEqualStr(a, b) {
  try {
    const ha = crypto.createHash('sha256').update(String(a || '')).digest();
    const hb = crypto.createHash('sha256').update(String(b || '')).digest();
    return crypto.timingSafeEqual(ha, hb);
  } catch (e) { return false; }
}

function isAdminRow(row) {
  if (!row || typeof row !== 'object') return false;
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
    if (!CONFIG.ADMIN_KEY) {
      console.error('[admin-register] ADMIN_KEY tidak di-set');
      return res.status(500).json({ success: false, message: 'Server misconfigured' });
    }

    const { secretKey, username, email, password, confirmPassword } = req.body || {};

    if (!secretKey || !timingSafeEqualStr(secretKey, CONFIG.ADMIN_KEY)) {
      await logActivity(username || 'unknown', 'admin_register_forbidden', 'Kode akses salah', ip, fp);
      return res.status(403).json({ success: false, message: 'Kode akses salah' });
    }

    const vu = isValidUsername(username);
    if (!vu.valid) return res.status(400).json({ success: false, message: vu.message });

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Email tidak valid' });
    }

    if (!password || password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password minimal 8 karakter' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Konfirmasi password tidak cocok' });
    }

    if (!fp) {
      return res.status(400).json({ success: false, message: 'Fingerprint tidak terdeteksi' });
    }

    const password_hash = await hashPassword(password);
    const ipHistory = ip && ip !== 'unknown' ? [ip] : [];
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

    // ─── FIX RACE CONDITION: Firebase Transaction ───
    const adminRef = db.ref('admin');
    const result = await adminRef.transaction((current) => {
      if (current) {
        const hasAdmin = Object.values(current).some(isAdminRow);
        if (hasAdmin) {
          return; // abort — admin sudah ada
        }
      }
      const id = adminRef.push().key;
      const next = current || {};
      next[id] = {
        username: sanitize(vu.username, 50),
        role: 'admin',
        status: 'active',
        createdAt: Date.now(),
        lockedIP: ip || '',
        lockedFP: fp,
        data: encryptAtRest(adminData)
      };
      return next;
    });

    if (!result.committed) {
      await logActivity(username || 'unknown', 'admin_register_race', 'Race condition dicegah', ip, fp);
      return res.status(403).json({ success: false, message: 'Admin sudah terdaftar. Registrasi ditutup.' });
    }

    await logActivity(vu.username, 'admin_register_success',
      `Admin baru: ${vu.username} dari IP ${ip || 'unknown'}`, ip, fp);

    return res.status(200).json({
      success: true,
      message: 'Admin berhasil dibuat. Login cuma bisa dari device ini.',
      username: vu.username,
      lockedIP: ip || ''
    });
  } catch (e) {
    console.error('[admin-register]', e?.message || e);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
}