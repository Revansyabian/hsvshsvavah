// rvns/session.js
import crypto from 'node:crypto';
import { CONFIG } from './config.js';

const COOKIE_SESSION_ADMIN = 'rvs_admin';
const COOKIE_SESSION_USER = 'rvs_user';
const COOKIE_CSRF_ADMIN = 'csrf_admin';
const COOKIE_CSRF_USER = 'csrf_user';
const SESSION_KEY = crypto.createHash('sha256').update(CONFIG.SESSION_SECRET || 'fallback').digest();

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  if (!raw) return out;
  raw.split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) {
      const k = p.slice(0, i).trim();
      const v = p.slice(i + 1).trim();
      try { out[k] = decodeURIComponent(v); }
      catch { out[k] = v; }
    }
  });
  return out;
}

function isAdminRole(role) {
  return ['admin', 'superadmin'].includes(String(role || '').toLowerCase());
}

export function createSessionToken(user) {
  const admin = isAdminRole(user.role);
  const maxAge = admin ? CONFIG.SESSION_ADMIN_MAX_AGE : CONFIG.SESSION_USER_MAX_AGE;

  const iat = Date.now();
  const payload = JSON.stringify({
    uid: user.id,
    username: user.username,
    role: user.role || 'User',
    iat,
    exp: iat + maxAge * 1000
  });

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_KEY, iv);
  const ct = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const token = `v2.${iv.toString('base64url')}.${tag.toString('base64url')}.${ct.toString('base64url')}`;
  const sig = crypto.createHmac('sha256', CONFIG.SESSION_SECRET || 'fallback').update(token).digest('base64url');
  return `${token}.${sig}`;
}

export function verifySession(req) {
  const cookies = parseCookies(req);
  const tAdmin = cookies[COOKIE_SESSION_ADMIN];
  const tUser = cookies[COOKIE_SESSION_USER];
  const t = tAdmin || tUser;
  if (!t) return null;

  const parts = t.split('.');
  if (parts.length !== 5) return null;
  if (parts[0] !== 'v2') return null;

  const token = parts.slice(0, 4).join('.');
  const sig = parts[4];

  const expected = crypto.createHmac('sha256', CONFIG.SESSION_SECRET || 'fallback').update(token).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    const iv = Buffer.from(parts[1], 'base64url');
    const tag = Buffer.from(parts[2], 'base64url');
    const ct = Buffer.from(parts[3], 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', SESSION_KEY, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
    const d = JSON.parse(pt);
    if (d.exp <= Date.now()) return null;
    if (tAdmin) d._from = 'admin_cookie';
    else d._from = 'user_cookie';
    return d;
  } catch {
    return null;
  }
}

export function verifyAdminSession(req) {
  const session = verifySession(req);
  if (!session) return null;
  if (session._from !== 'admin_cookie') return null;
  if (!isAdminRole(session.role)) return null;
  return session;
}

export function verifyUserSession(req) {
  const session = verifySession(req);
  if (!session) return null;
  if (session._from !== 'user_cookie') return null;
  if (isAdminRole(session.role)) return null;
  return session;
}

export function generateCSRFToken(session, kind) {
  const scope = kind || (isAdminRole(session.role) ? 'admin' : 'user');
  return crypto.createHmac('sha256', CONFIG.SESSION_SECRET || 'fallback')
    .update(`csrf:${scope}:${session.uid}:${session.exp}`)
    .digest('base64url');
}

export function verifyCSRF(req, session, kind) {
  const scope = kind || (isAdminRole(session.role) ? 'admin' : 'user');
  const headerName = scope === 'admin' ? 'x-csrf-token' : 'x-csrf-token';
  const token = req.headers[headerName];
  if (!token) return false;
  const expected = generateCSRFToken(session, scope);
  const a = Buffer.from(token);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function appendSetCookie(res, cookieStr) {
  const existing = res.getHeader('Set-Cookie');
  if (!existing) {
    res.setHeader('Set-Cookie', cookieStr);
  } else if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', [...existing, cookieStr]);
  } else {
    res.setHeader('Set-Cookie', [existing, cookieStr]);
  }
}

export function setAdminSessionCookie(res, sessionToken, csrfToken) {
  const maxAge = CONFIG.SESSION_ADMIN_MAX_AGE;
  const isProd = process.env.NODE_ENV === 'production' ||
                 process.env.VERCEL === '1' ||
                 !!process.env.VERCEL_ENV;
  const secureFlag = isProd ? '; Secure' : '';
  const baseAttrs = `Path=/; SameSite=Lax; Max-Age=${maxAge}${secureFlag}`;

  appendSetCookie(res, `${COOKIE_SESSION_ADMIN}=${encodeURIComponent(sessionToken)}; HttpOnly; ${baseAttrs}`);
  appendSetCookie(res, `${COOKIE_CSRF_ADMIN}=${encodeURIComponent(csrfToken)}; ${baseAttrs}`);
}

export function setUserSessionCookie(res, sessionToken, csrfToken) {
  const maxAge = CONFIG.SESSION_USER_MAX_AGE;
  const isProd = process.env.NODE_ENV === 'production' ||
                 process.env.VERCEL === '1' ||
                 !!process.env.VERCEL_ENV;
  const secureFlag = isProd ? '; Secure' : '';
  const baseAttrs = `Path=/; SameSite=Lax; Max-Age=${maxAge}${secureFlag}`;

  appendSetCookie(res, `${COOKIE_SESSION_USER}=${encodeURIComponent(sessionToken)}; HttpOnly; ${baseAttrs}`);
  appendSetCookie(res, `${COOKIE_CSRF_USER}=${encodeURIComponent(csrfToken)}; ${baseAttrs}`);
}

export function clearAdminSessionCookie(res) {
  const past = 'Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  appendSetCookie(res, `${COOKIE_SESSION_ADMIN}=; HttpOnly; ${past}`);
  appendSetCookie(res, `${COOKIE_CSRF_ADMIN}=; ${past}`);
}

export function clearUserSessionCookie(res) {
  const past = 'Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  appendSetCookie(res, `${COOKIE_SESSION_USER}=; HttpOnly; ${past}`);
  appendSetCookie(res, `${COOKIE_CSRF_USER}=; ${past}`);
}

export function getSessionMaxAge(user) {
  return isAdminRole(user.role) ? CONFIG.SESSION_ADMIN_MAX_AGE : CONFIG.SESSION_USER_MAX_AGE;
}

export const COOKIE_NAMES = {
  ADMIN_SESSION: COOKIE_SESSION_ADMIN,
  USER_SESSION: COOKIE_SESSION_USER,
  ADMIN_CSRF: COOKIE_CSRF_ADMIN,
  USER_CSRF: COOKIE_CSRF_USER
};