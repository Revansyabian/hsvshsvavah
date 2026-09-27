import crypto from 'node:crypto';
import { CONFIG } from './config.js';

const COOKIE_SESSION = 'rvs_session';
const COOKIE_CSRF = 'csrf_token';

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

export function createSessionToken(user) {
  const isAdmin = ['admin', 'superadmin'].includes(String(user.role || '').toLowerCase());
  const maxAge = isAdmin ? CONFIG.SESSION_ADMIN_MAX_AGE : CONFIG.SESSION_USER_MAX_AGE;
  const p = Buffer.from(JSON.stringify({
    uid: user.id,
    username: user.username,
    role: user.role || 'User',
    iat: Date.now(),
    exp: Date.now() + maxAge * 1000
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', CONFIG.SESSION_SECRET).update(p).digest('base64url');
  return `${p}.${sig}`;
}

export function getSessionMaxAge(user) {
  const isAdmin = ['admin', 'superadmin'].includes(String(user.role || '').toLowerCase());
  return isAdmin ? CONFIG.SESSION_ADMIN_MAX_AGE : CONFIG.SESSION_USER_MAX_AGE;
}

export function verifySession(req) {
  const t = parseCookies(req)[COOKIE_SESSION];
  if (!t) return null;
  const parts = t.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', CONFIG.SESSION_SECRET).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const d = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return d.exp > Date.now() ? d : null;
  } catch { return null; }
}

export function generateCSRFToken(session) {
  return crypto.createHmac('sha256', CONFIG.SESSION_SECRET)
    .update(`csrf:${session.uid}`)
    .digest('base64url');
}

export function verifyCSRF(req, session) {
  const token = req.headers['x-csrf-token'];
  if (!token) return false;
  const expected = generateCSRFToken(session);
  const a = Buffer.from(token);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function setSessionCookie(res, sessionToken, csrfToken, user) {
  const maxAge = user ? getSessionMaxAge(user) : CONFIG.SESSION_ADMIN_MAX_AGE;
  const cookies = [
    `${COOKIE_SESSION}=${encodeURIComponent(sessionToken)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAge}`,
    `${COOKIE_CSRF}=${csrfToken}; Path=/; Secure; SameSite=None; Max-Age=${maxAge}`
  ];
  res.setHeader('Set-Cookie', cookies);
}

export function clearSessionCookie(res) {
  const cookies = [
    `${COOKIE_SESSION}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`,
    `${COOKIE_CSRF}=; Path=/; Secure; SameSite=None; Max-Age=0`
  ];
  res.setHeader('Set-Cookie', cookies);
}