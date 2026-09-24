import { CONFIG } from './config.js';
import { verifySession, verifyCSRF, generateCSRFToken } from './session.js';
import { decryptAny } from './helper.js';
import { db } from './db.js';

export function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control', 'no-store');
}

export function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && CONFIG.ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Fingerprint, X-CSRF-Token');
}

function extractOriginFromReferer(referer) {
  if (!referer) return '';
  try {
    const u = new URL(referer);
    return `${u.protocol}//${u.host}`;
  } catch { return ''; }
}

export function enforceOrigin(req, res) {
  if (!CONFIG.ALLOWED_ORIGINS.length) return true;
  const origin = req.headers.origin || '';
  const referer = req.headers.referer || req.headers.referrer || '';
  const secFetchSite = req.headers['sec-fetch-site'] || '';
  if (origin) {
    if (CONFIG.ALLOWED_ORIGINS.includes(origin)) return true;
    res.status(403).json({ success: false, error: 'origin_denied', message: 'Origin tidak diizinkan' });
    return false;
  }
  if (referer) {
    const refOrigin = extractOriginFromReferer(referer);
    if (refOrigin && CONFIG.ALLOWED_ORIGINS.includes(refOrigin)) return true;
    res.status(403).json({ success: false, error: 'referer_denied', message: 'Referer tidak diizinkan' });
    return false;
  }
  if (secFetchSite === 'same-origin' || secFetchSite === 'same-site' || secFetchSite === 'none') return true;
  res.status(403).json({ success: false, error: 'origin_required', message: 'Request tanpa Origin tidak diizinkan' });
  return false;
}

export function methodGuard(req, res, allowed = ['GET', 'POST']) {
  if (req.method === 'OPTIONS') { res.status(204).end(); return false; }
  if (!allowed.includes(req.method)) {
    res.status(405).json({ success: false, message: `Method ${req.method} tidak diizinkan` });
    return false;
  }
  return true;
}

export function bodyGuard(req, res, maxBytes = 10 * 1024) {
  const len = Number(req.headers['content-length'] || 0);
  if (len > maxBytes) {
    res.status(413).json({ success: false, message: 'Body terlalu besar' });
    return false;
  }
  return true;
}

async function findAdminById(id) {
  const snap = await db.ref(`admin/${id}`).once('value');
  if (!snap.exists()) return null;
  const row = snap.val();
  return { id, row, data: decryptAny(row.data) || {} };
}

async function findUserByIdSafe(id) {
  const snap = await db.ref(`users/${id}`).once('value');
  if (!snap.exists()) return null;
  const row = snap.val();
  return { id, row, data: decryptAny(row.data) || {} };
}

export async function requireAuth(req, res, opts = {}) {
  const session = verifySession(req);
  if (!session) {
    res.status(401).json({ success: false, message: 'Sesi tidak valid atau sudah berakhir' });
    return null;
  }
  if (opts.csrf !== false && ['POST', 'PATCH', 'DELETE', 'PUT'].includes(req.method)) {
    if (!verifyCSRF(req, session)) {
      res.status(403).json({ success: false, error: 'csrf_invalid', message: 'CSRF token tidak valid' });
      return null;
    }
  }
  const role = String(session.role || '').toLowerCase();
  if (role === 'admin' || role === 'superadmin') {
    const adminUser = await findAdminById(session.uid);
    if (!adminUser) {
      res.status(401).json({ success: false, message: 'Admin tidak ditemukan' });
      return null;
    }
    return { session, user: adminUser, csrfToken: generateCSRFToken(session) };
  }
  const user = await findUserByIdSafe(session.uid);
  if (!user) {
    res.status(401).json({ success: false, message: 'User tidak ditemukan' });
    return null;
  }
  return { session, user, csrfToken: generateCSRFToken(session) };
}

export async function requireAdmin(req, res, opts = {}) {
  const auth = await requireAuth(req, res, opts);
  if (!auth) return null;
  const role = String(auth.session.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'superadmin') {
    res.status(403).json({ success: false, message: 'Akses admin diperlukan' });
    return null;
  }
  return auth;
}