import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import CryptoJS from 'crypto-js';
import { db } from './db.js';
import { CONFIG } from './config.js';

const keyFromSecret = s => crypto.createHash('sha256').update(String(s)).digest();

export function encryptAtRest(value) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', keyFromSecret(CONFIG.ADMIN_KEY), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(value ?? null), 'utf8'), c.final()]);
  return 'v2.' + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64url');
}

export function decryptAtRest(raw) {
  if (typeof raw !== 'string' || !raw.startsWith('v2.')) return null;
  try {
    const b = Buffer.from(raw.slice(3), 'base64url');
    const d = crypto.createDecipheriv('aes-256-gcm', keyFromSecret(CONFIG.ADMIN_KEY), b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'));
  } catch { return null; }
}

export function decryptAtRestLegacy(raw) {
  if (typeof raw !== 'string' || !raw.startsWith('U2F')) return null;
  try {
    const dec = CryptoJS.AES.decrypt(raw, CONFIG.ADMIN_KEY).toString(CryptoJS.enc.Utf8);
    if (!dec) return null;
    return JSON.parse(dec);
  } catch { return null; }
}

export function decryptAny(raw) {
  const v2 = decryptAtRest(raw);
  if (v2) return v2;
  return decryptAtRestLegacy(raw);
}

export const sanitize = (s, m = 500) => s ? String(s).slice(0, m).replace(/[<>"'`]/g, '') : '';
export const safeKey = v => String(v || 'unknown').replace(/[.#$\[\]\/]/g, '_');

export function getIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const parts = String(xff).split(',');
    return (parts[0] || '').trim() || 'unknown';
  }
  const realIP = req.headers['x-real-ip'];
  if (realIP) return String(realIP).trim();
  return (req.socket && req.socket.remoteAddress) || (req.connection && req.connection.remoteAddress) || 'unknown';
}

export const ipOf = getIP;
export const fpOf = req => String(req.headers['x-fingerprint'] || '');

export const hashPassword = p => bcrypt.hash(String(p), CONFIG.SALT_ROUNDS);
export const verifyPassword = async (p, h) => {
  if (!h) return false;
  try { return await bcrypt.compare(String(p), h); } catch { return false; }
};

export function initialColor(username) {
  if (!username || typeof username !== 'string' || username.length === 0) return '#64748b';
  const ch = username[0];
  if (ch >= 'A' && ch <= 'Z') return '#00BFFF';
  if (ch >= 'a' && ch <= 'z') return '#10b981';
  return '#64748b';
}

export function initialLetter(username) {
  if (!username || typeof username !== 'string') return '?';
  return username[0].toUpperCase();
}

export function daysLeft(expiryDate) {
  if (!expiryDate) return null;
  if (String(expiryDate).includes('9999')) return 999999;
  const t = new Date(expiryDate).getTime();
  if (!Number.isFinite(t)) return null;
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  return Math.ceil((t - now.getTime()) / 86400000);
}

export function computeExpiryFromDuration(duration) {
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const add = (days) => {
    const d = new Date(now.getTime() + days * 86400000);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  };
  switch (String(duration || '').toLowerCase()) {
    case '1mgg': return add(7);
    case '2mgg': return add(14);
    case '3mgg': return add(21);
    case '1bln': return add(30);
    case '2bln': return add(60);
    case '1thn': return add(365);
    case 'permanen': return '9999-12-31';
    default: return add(30);
  }
}

export function getBanDurationMs(durationKey) {
  return CONFIG.BAN_DURATIONS[durationKey] !== undefined ? CONFIG.BAN_DURATIONS[durationKey] : 0;
}

export async function findUserByUsername(username) {
  const target = String(username || '').toLowerCase().trim();
  if (!target) return null;
  const snap = await db.ref('users').once('value');
  for (const [id, row] of Object.entries(snap.val() || {})) {
    if (String(row.username || '').toLowerCase() === target) {
      return { id, row, data: decryptAny(row.data) || {} };
    }
  }
  return null;
}

export async function findUserById(id) {
  const snap = await db.ref(`users/${id}`).once('value');
  if (!snap.exists()) return null;
  const row = snap.val();
  return { id, row, data: decryptAny(row.data) || {} };
}

export async function findUserByEmail(email) {
  const target = String(email || '').toLowerCase().trim();
  if (!target) return null;
  const snap = await db.ref('users').once('value');
  for (const [id, row] of Object.entries(snap.val() || {})) {
    const d = decryptAny(row.data) || {};
    if (d.email && String(d.email).toLowerCase() === target) {
      return { id, row, data: d };
    }
  }
  return null;
}

export async function saveUser(id, plain = {}) {
  const ref = db.ref(`users/${id}`);
  const existingSnap = await ref.once('value');
  const existing = existingSnap.exists() ? existingSnap.val() : {};
  const sensitive = { ...plain };
  const topLevel = [
    'username', 'role', 'status', 'banned', 'accessBanned', 'forceLogout',
    'registered', 'activationStatus', 'createdAt', 'approvedAt', 'approvedBy',
    'approvedIP', 'approvedFP', 'rejectedAt', 'rejectedBy', 'rejectionReason'
  ];
  for (const key of topLevel) delete sensitive[key];

  await ref.set({
    username: sanitize(plain.username ?? existing.username ?? '', 50),
    role: sanitize(plain.role ?? existing.role ?? 'User', 20),
    status: sanitize(plain.status ?? existing.status ?? 'active', 20),
    banned: Boolean(plain.banned ?? existing.banned ?? false),
    accessBanned: Boolean(plain.accessBanned ?? existing.accessBanned ?? false),
    forceLogout: Boolean(plain.forceLogout ?? existing.forceLogout ?? false),
    registered: Boolean(plain.registered ?? existing.registered ?? true),
    activationStatus: sanitize(plain.activationStatus ?? existing.activationStatus ?? 'approved', 20),
    approvedAt: Number(plain.approvedAt ?? existing.approvedAt ?? 0) || 0,
    approvedBy: sanitize(plain.approvedBy ?? existing.approvedBy ?? '', 100),
    approvedIP: sanitize(plain.approvedIP ?? existing.approvedIP ?? '', 80),
    approvedFP: sanitize(plain.approvedFP ?? existing.approvedFP ?? '', 200),
    rejectedAt: Number(plain.rejectedAt ?? existing.rejectedAt ?? 0) || 0,
    rejectedBy: sanitize(plain.rejectedBy ?? existing.rejectedBy ?? '', 100),
    rejectionReason: sanitize(plain.rejectionReason ?? existing.rejectionReason ?? '', 500),
    createdAt: Number(plain.createdAt ?? existing.createdAt ?? Date.now()),
    data: encryptAtRest(sensitive)
  });
}

export function toPublicUser(id, row) {
  const d = decryptAny(row.data) || {};
  const dl = daysLeft(d.expiry_date);
  const resetHistory = Array.isArray(d.resetHistory) ? d.resetHistory : [];
  const resetCount24h = resetHistory.filter(x => Date.now() - Number(x.at || 0) < 86400000).length;
  return {
    id,
    username: row.username || '',
    role: row.role || 'User',
    status: row.status || 'active',
    banned: row.banned === true,
    accessBanned: row.accessBanned === true,
    forceLogout: row.forceLogout === true,
    registered: row.registered !== false,
    activationStatus: row.activationStatus || 'approved',
    approvedAt: row.approvedAt || 0,
    approvedBy: row.approvedBy || '',
    registeredAt: d.registeredAt || 0,
    registeredIP: d.registeredIP || '',
    registeredFP: d.registeredFP || '',
    approvedIP: row.approvedIP || d.registeredIP || '',
    approvedFP: row.approvedFP || d.registeredFP || '',
    rejectedAt: row.rejectedAt || 0,
    rejectedBy: row.rejectedBy || '',
    rejectionReason: row.rejectionReason || d.rejectionReason || '',
    createdAt: row.createdAt || 0,
    email: d.email || '',
    phone: d.phone || '',
    paket: d.paket || '',
    harga: d.harga || 0,
    expiry_date: d.expiry_date || '',
    daysLeft: dl,
    bannedUntil: d.bannedUntil || 0,
    banAksesUntil: d.banAksesUntil || 0,
    forceLogoutUntil: d.forceLogoutUntil || 0,
    banReason: d.banReason || '',
    lastLogin: d.lastLogin || null,
    ip: d.ip || '',
    fp: d.fp || '',
    ipHistory: Array.isArray(d.ipHistory) ? d.ipHistory.slice(-5) : [],
    fpHistory: Array.isArray(d.fpHistory) ? d.fpHistory.slice(-5) : [],
    resetCount: Number(d.resetCount || 0),
    resetCount24h: resetCount24h,
    resetRemaining: Math.max(0, CONFIG.RESET_DAILY_MAX - resetCount24h),
    initialColor: initialColor(row.username || ''),
    initialLetter: initialLetter(row.username || '')
  };
}

export function isValidUsername(u) {
  if (!u || typeof u !== 'string') return { valid: false, message: 'Username tidak valid' };
  const t = u.trim();
  if (t.length < 3) return { valid: false, message: 'Username minimal 3 karakter' };
  if (t.length > 30) return { valid: false, message: 'Username maksimal 30 karakter' };
  if (!/^[a-zA-Z0-9_.]+$/.test(t)) return { valid: false, message: 'Username hanya huruf, angka, underscore, titik' };
  return { valid: true, username: t };
}

export async function logActivity(username, action, details, ip, fp) {
  try {
    await db.ref('activity_logs').push({
      username: sanitize(username, 100),
      action: sanitize(action, 100),
      ip: sanitize(ip, 50),
      fingerprint: sanitize(fp, 100),
      timestamp: Date.now(),
      details: encryptAtRest({ text: details || '' })
    });
  } catch (e) { console.error('logActivity:', e?.message); }
}

export async function readLogs(limit = 100, filterFn = null) {
  const snap = await db.ref('activity_logs').limitToLast(limit).once('value');
  return Object.values(snap.val() || {})
    .map(r => ({
      username: r.username || '',
      action: r.action || '',
      ip: r.ip || '',
      fingerprint: r.fingerprint || '',
      timestamp: r.timestamp || 0,
      details: decryptAny(r.details)?.text || ''
    }))
    .filter(x => !filterFn || filterFn(x))
    .sort((a, b) => b.timestamp - a.timestamp);
}

export async function isIPBlocked(ip) {
  if (!ip || ip === 'unknown') return false;
  const s = await db.ref(`blocked_ips/${safeKey(ip)}`).once('value');
  return s.exists();
}

export async function isFPBlocked(fp) {
  if (!fp) return false;
  const s = await db.ref(`blocked_fp/${safeKey(fp)}`).once('value');
  return s.exists();
}

export async function blockIP(ip, reason, by) {
  if (!ip || ip === 'unknown') return;
  await db.ref(`blocked_ips/${safeKey(ip)}`).set({
    ip: sanitize(ip, 50),
    blockedAt: Date.now(),
    blockedBy: sanitize(by || 'system', 100),
    data: encryptAtRest({ reason: reason || '' })
  });
}

export async function unblockIP(ip) {
  await db.ref(`blocked_ips/${safeKey(ip)}`).remove();
}

export async function blockFP(fp, reason, by) {
  if (!fp) return;
  await db.ref(`blocked_fp/${safeKey(fp)}`).set({
    fingerprint: sanitize(fp, 200),
    blockedAt: Date.now(),
    blockedBy: sanitize(by || 'system', 100),
    data: encryptAtRest({ reason: reason || '' })
  });
}

export async function unblockFP(fp) {
  await db.ref(`blocked_fp/${safeKey(fp)}`).remove();
}

export async function listBlockedIPs() {
  const s = await db.ref('blocked_ips').once('value');
  return Object.entries(s.val() || {}).map(([k, v]) => ({
    key: k, ip: v.ip || k,
    blockedAt: v.blockedAt || 0,
    blockedBy: v.blockedBy || '',
    reason: decryptAny(v.data)?.reason || ''
  })).sort((a, b) => b.blockedAt - a.blockedAt);
}

export async function listBlockedFPs() {
  const s = await db.ref('blocked_fp').once('value');
  return Object.entries(s.val() || {}).map(([k, v]) => ({
    key: k, fingerprint: v.fingerprint || k,
    blockedAt: v.blockedAt || 0,
    blockedBy: v.blockedBy || '',
    reason: decryptAny(v.data)?.reason || ''
  })).sort((a, b) => b.blockedAt - a.blockedAt);
}

export async function getMaintenance() {
  const s = await db.ref('maintenance_status').once('value');
  const raw = s.val();
  if (!raw) return { maintenance: false, title: '', message: '', until: 0, updatedAt: 0, updatedBy: '' };
  const d = raw.data ? (decryptAny(raw.data) || {}) : raw;
  return {
    maintenance: d.maintenance === true,
    title: d.title || '', message: d.message || '', until: d.until || 0,
    updatedAt: d.updatedAt || 0, updatedBy: d.updatedBy || ''
  };
}

export async function setMaintenance(p, by) {
  const data = {
    maintenance: Boolean(p.maintenance),
    title: sanitize(p.title || '', 200),
    message: sanitize(p.message || '', 1000),
    until: Number(p.until) || 0,
    updatedAt: Date.now(),
    updatedBy: sanitize(by || 'system', 100)
  };
  await db.ref('maintenance_status').set({ data: encryptAtRest(data), updatedAt: data.updatedAt });
  return data;
}

export async function verifyRecaptchaV2(token) {
  if (!CONFIG.RECAPTCHA_V2_SECRET) return true;
  if (!token) return false;
  try {
    const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${CONFIG.RECAPTCHA_V2_SECRET}&response=${token}`
    });
    const d = await r.json();
    return d.success === true;
  } catch { return false; }
}

export async function verifyRecaptchaV3(token, action) {
  if (!CONFIG.RECAPTCHA_V3_SECRET) return true;
  if (!token) return false;
  try {
    const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${CONFIG.RECAPTCHA_V3_SECRET}&response=${token}`
    });
    const d = await r.json();
    if (!d.success) return false;
    if (d.score < 0.5) return false;
    if (action && d.action !== action) return false;
    return true;
  } catch { return false; }
}

export async function trackUserIPFP(userId, ip, fp) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return;
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  const ips = Array.isArray(d.ipHistory) ? d.ipHistory : [];
  const fps = Array.isArray(d.fpHistory) ? d.fpHistory : [];
  if (ip && ip !== 'unknown' && (ips.length === 0 || ips[ips.length - 1] !== ip)) {
    ips.push(ip);
    if (ips.length > 20) ips.shift();
  }
  if (fp && (fps.length === 0 || fps[fps.length - 1] !== fp)) {
    fps.push(fp);
    if (fps.length > 20) fps.shift();
  }
  d.ipHistory = ips;
  d.fpHistory = fps;
  d.lastIP = ip;
  d.lastFP = fp;
  d.lastSeenAt = Date.now();
  await saveUser(userId, {
    ...d,
    username: row.username,
    role: row.role,
    status: row.status,
    banned: row.banned,
    accessBanned: row.accessBanned,
    forceLogout: row.forceLogout,
    registered: row.registered,
    activationStatus: row.activationStatus,
    approvedAt: row.approvedAt,
    approvedBy: row.approvedBy,
    rejectedAt: row.rejectedAt,
    rejectedBy: row.rejectedBy,
    createdAt: row.createdAt
  });
}

export async function checkRegisterLimit(ip, fp) {
  const now = Date.now();
  const checks = [
    ip && ip !== 'unknown' ? ['ip', ip] : null,
    fp ? ['fp', fp] : null
  ].filter(Boolean);
  for (const [type, value] of checks) {
    const snap = await db.ref(`register_limits/${type}_${safeKey(value)}`).once('value');
    const raw = snap.val();
    const lastRegister = Number(raw?.lastRegister || decryptAny(raw?.data)?.lastRegister || 0);
    if (lastRegister && now - lastRegister < CONFIG.REGISTER_COOLDOWN) {
      const remainingMs = CONFIG.REGISTER_COOLDOWN - (now - lastRegister);
      const hours = Math.ceil(remainingMs / 3600000);
      return {
        allowed: false,
        error: type === 'ip' ? 'ip_limit' : 'fp_limit',
        reason: `Kamu sudah mendaftar sebelumnya. Coba lagi ${hours} jam lagi.`,
        remainingMs,
        retryAfterSeconds: Math.ceil(remainingMs / 1000)
      };
    }
  }
  return { allowed: true, error: null, reason: '', remainingMs: 0, retryAfterSeconds: 0 };
}

export async function markRegisterLimit(ip, fp, username) {
  const now = Date.now();
  const entries = [];
  if (ip && ip !== 'unknown') entries.push(['ip', ip]);
  if (fp) entries.push(['fp', fp]);
  const claimed = [];
  for (const [type, value] of entries) {
    const ref = db.ref(`register_limits/${type}_${safeKey(value)}`);
    const result = await ref.transaction(current => {
      const currentLast = Number(current?.lastRegister || decryptAny(current?.data)?.lastRegister || 0);
      if (currentLast && now - currentLast < CONFIG.REGISTER_COOLDOWN) return;
      return { lastRegister: now, username: sanitize(username, 50) };
    });
    if (!result.committed) {
      for (const path of claimed) await db.ref(path).remove();
      return { allowed: false, error: type === 'ip' ? 'ip_limit' : 'fp_limit' };
    }
    claimed.push(`register_limits/${type}_${safeKey(value)}`);
  }
  return { allowed: true };
}

export async function releaseRegisterLimit(ip, fp) {
  const entries = [];
  if (ip && ip !== 'unknown') entries.push(['ip', ip]);
  if (fp) entries.push(['fp', fp]);
  for (const [type, value] of entries) await db.ref(`register_limits/${type}_${safeKey(value)}`).remove();
}

export async function checkResetLimit(userId) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { allowed: false, reason: 'User tidak ditemukan', used: 0, remaining: 0 };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  const now = Date.now();
  const history = Array.isArray(d.resetHistory) ? d.resetHistory : [];
  const recent = history.filter(x => now - Number(x.at || 0) < 86400000);
  const used = recent.length;
  const remaining = Math.max(0, CONFIG.RESET_DAILY_MAX - used);
  return {
    allowed: used < CONFIG.RESET_DAILY_MAX,
    reason: used >= CONFIG.RESET_DAILY_MAX ? 'Kuota reset habis. Coba lagi nanti.' : '',
    used,
    remaining
  };
}

export async function recordReset(userId, ip, fp) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { used: 0, remaining: CONFIG.RESET_DAILY_MAX };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  const now = Date.now();
  const history = Array.isArray(d.resetHistory) ? d.resetHistory : [];
  const kept = history.filter(x => now - Number(x.at || 0) < 7 * 86400000);
  kept.push({ at: now, ip: sanitize(ip || '', 50), fp: sanitize(fp || '', 200) });
  d.resetHistory = kept;
  d.resetCount = Number(d.resetCount || 0) + 1;
  const recent = kept.filter(x => now - Number(x.at || 0) < 86400000).length;
  await saveUser(userId, {
    ...d,
    username: row.username,
    role: row.role,
    status: row.status,
    banned: row.banned,
    accessBanned: row.accessBanned,
    forceLogout: row.forceLogout,
    registered: row.registered,
    activationStatus: row.activationStatus,
    approvedAt: row.approvedAt,
    approvedBy: row.approvedBy,
    approvedIP: row.approvedIP,
    approvedFP: row.approvedFP,
    rejectedAt: row.rejectedAt,
    rejectedBy: row.rejectedBy,
    rejectionReason: row.rejectionReason,
    createdAt: row.createdAt
  });
  return { used: recent, remaining: Math.max(0, CONFIG.RESET_DAILY_MAX - recent) };
}

export async function banUserWithIPFP(userId, reason, by, durationMs = 0) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { success: false, message: 'User tidak ditemukan' };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  const ips = Array.isArray(d.ipHistory) ? d.ipHistory : [];
  const fps = Array.isArray(d.fpHistory) ? d.fpHistory : [];
  for (const ip of ips) await blockIP(ip, reason || 'Banned user', by);
  for (const fp of fps) await blockFP(fp, reason || 'Banned user', by);
  d.bannedUntil = durationMs > 0 ? Date.now() + durationMs : 0;
  d.banReason = reason || '';
  await saveUser(userId, {
    ...d,
    username: row.username, role: row.role, status: row.status,
    registered: row.registered, activationStatus: row.activationStatus,
    approvedAt: row.approvedAt, approvedBy: row.approvedBy,
    rejectedAt: row.rejectedAt, rejectedBy: row.rejectedBy,
    createdAt: row.createdAt,
    banned: true, forceLogout: true
  });
  return { success: true, blockedIPs: ips.length, blockedFPs: fps.length };
}

export async function unbanUserWithIPFP(userId) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { success: false, message: 'User tidak ditemukan' };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  const ips = Array.isArray(d.ipHistory) ? d.ipHistory : [];
  const fps = Array.isArray(d.fpHistory) ? d.fpHistory : [];
  for (const ip of ips) await unblockIP(ip);
  for (const fp of fps) await unblockFP(fp);
  d.bannedUntil = 0;
  d.banReason = '';
  await saveUser(userId, {
    ...d,
    username: row.username, role: row.role, status: row.status,
    registered: row.registered, activationStatus: row.activationStatus,
    approvedAt: row.approvedAt, approvedBy: row.approvedBy,
    rejectedAt: row.rejectedAt, rejectedBy: row.rejectedBy,
    createdAt: row.createdAt,
    banned: false, forceLogout: false
  });
  return { success: true };
}

export async function banAksesUserWithIPFP(userId, reason, by, durationMs = 0) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { success: false, message: 'User tidak ditemukan' };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  const ips = Array.isArray(d.ipHistory) ? d.ipHistory : [];
  const fps = Array.isArray(d.fpHistory) ? d.fpHistory : [];
  for (const ip of ips) await blockIP(ip, reason || 'Ban akses', by);
  for (const fp of fps) await blockFP(fp, reason || 'Ban akses', by);
  d.banAksesUntil = durationMs > 0 ? Date.now() + durationMs : 0;
  d.banReason = reason || '';
  await saveUser(userId, {
    ...d,
    username: row.username, role: row.role, status: row.status,
    registered: row.registered, activationStatus: row.activationStatus,
    approvedAt: row.approvedAt, approvedBy: row.approvedBy,
    rejectedAt: row.rejectedAt, rejectedBy: row.rejectedBy,
    createdAt: row.createdAt,
    accessBanned: true, forceLogout: true
  });
  return { success: true };
}

export async function unbanAksesUserWithIPFP(userId) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { success: false, message: 'User tidak ditemukan' };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  const ips = Array.isArray(d.ipHistory) ? d.ipHistory : [];
  const fps = Array.isArray(d.fpHistory) ? d.fpHistory : [];
  for (const ip of ips) await unblockIP(ip);
  for (const fp of fps) await unblockFP(fp);
  d.banAksesUntil = 0;
  await saveUser(userId, {
    ...d,
    username: row.username, role: row.role, status: row.status,
    registered: row.registered, activationStatus: row.activationStatus,
    approvedAt: row.approvedAt, approvedBy: row.approvedBy,
    rejectedAt: row.rejectedAt, rejectedBy: row.rejectedBy,
    createdAt: row.createdAt,
    accessBanned: false, forceLogout: false
  });
  return { success: true };
}

export async function suspendUser(userId, reason, by, durationMs = 0) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { success: false, message: 'User tidak ditemukan' };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  d.banReason = reason || '';
  d.forceLogoutUntil = durationMs > 0 ? Date.now() + durationMs : 0;
  await saveUser(userId, {
    ...d,
    username: row.username, role: row.role, status: row.status,
    registered: row.registered, activationStatus: row.activationStatus,
    approvedAt: row.approvedAt, approvedBy: row.approvedBy,
    rejectedAt: row.rejectedAt, rejectedBy: row.rejectedBy,
    createdAt: row.createdAt,
    forceLogout: true
  });
  return { success: true };
}

export async function unsuspendUser(userId) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { success: false, message: 'User tidak ditemukan' };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  d.forceLogoutUntil = 0;
  await saveUser(userId, {
    ...d,
    username: row.username, role: row.role, status: row.status,
    registered: row.registered, activationStatus: row.activationStatus,
    approvedAt: row.approvedAt, approvedBy: row.approvedBy,
    rejectedAt: row.rejectedAt, rejectedBy: row.rejectedBy,
    createdAt: row.createdAt,
    forceLogout: false
  });
  return { success: true };
}

export async function approveUser(userId, adminUsername) {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { success: false, message: 'User tidak ditemukan' };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  const now = Date.now();
  const registeredIP = d.registeredIP || (Array.isArray(d.ipHistory) ? d.ipHistory[0] : '') || '';
  const registeredFP = d.registeredFP || (Array.isArray(d.fpHistory) ? d.fpHistory[0] : '') || '';
  await saveUser(userId, {
    ...d,
    username: row.username,
    role: row.role || 'User',
    status: 'active',
    banned: false,
    accessBanned: false,
    forceLogout: false,
    registered: true,
    activationStatus: 'approved',
    approvedAt: now,
    approvedBy: adminUsername || 'admin',
    approvedIP: registeredIP,
    approvedFP: registeredFP,
    rejectedAt: 0,
    rejectedBy: '',
    rejectionReason: '',
    createdAt: row.createdAt
  });
  return { success: true };
}

export async function rejectUser(userId, adminUsername, reason = '') {
  const snap = await db.ref(`users/${userId}`).once('value');
  if (!snap.exists()) return { success: false, message: 'User tidak ditemukan' };
  const row = snap.val();
  const d = decryptAny(row.data) || {};
  await saveUser(userId, {
    ...d,
    username: row.username,
    role: row.role || 'User',
    status: 'rejected',
    banned: false,
    accessBanned: false,
    forceLogout: false,
    registered: true,
    activationStatus: 'rejected',
    approvedAt: 0,
    approvedBy: '',
    approvedIP: '',
    approvedFP: '',
    rejectedAt: Date.now(),
    rejectedBy: adminUsername || 'admin',
    rejectionReason: sanitize(reason, 500),
    createdAt: row.createdAt
  });
  return { success: true };
}

export async function detectSuspicious(user, action, ip, fp, extra) {
  try {
    const reasons = [];
    const d = (user && user.data) || {};
    const row = (user && user.row) || {};
    if (action === 'login_success') {
      const prevIP = d.lastIP || '';
      const prevFP = d.lastFP || '';
      if (prevIP && ip && prevIP !== ip) reasons.push(`IP berubah: ${prevIP} → ${ip}`);
      if (prevFP && fp && prevFP !== fp) reasons.push(`FP berubah`);
    }
    if (/login_failed|login_wrong|login_blocked/i.test(action || '')) reasons.push('Percobaan login gagal');
    if (action === 'sharing_detected') reasons.push('Indikasi sharing akun');
    if (row.banned) reasons.push('User banned');
    if (row.accessBanned) reasons.push('User ban akses');
    if (row.forceLogout) reasons.push('User ditangguhkan');
    if (reasons.length > 0) {
      await db.ref('suspicious_logs').push({
        username: sanitize((user && user.username) || row.username || 'unknown', 100),
        action: sanitize(action, 100),
        reasons: reasons.map(r => sanitize(r, 200)),
        ip: sanitize(ip, 50),
        fingerprint: sanitize(fp, 100),
        timestamp: Date.now(),
        details: encryptAtRest({ text: extra || '' })
      });
    }
    return reasons;
  } catch (e) { return []; }
}

export async function readSuspiciousLogs(limit = 100) {
  const snap = await db.ref('suspicious_logs').limitToLast(limit).once('value');
  return Object.values(snap.val() || {})
    .map(r => ({
      username: r.username || '',
      action: r.action || '',
      reasons: Array.isArray(r.reasons) ? r.reasons : [],
      ip: r.ip || '', fingerprint: r.fingerprint || '',
      timestamp: r.timestamp || 0,
      details: decryptAny(r.details)?.text || ''
    }))
    .sort((a, b) => b.timestamp - a.timestamp);
}