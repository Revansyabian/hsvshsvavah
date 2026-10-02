// rvns/session.js
import crypto from 'node:crypto';
import { CONFIG } from './config.js';

const COOKIE_SESSION = 'rvs_session';
const COOKIE_CSRF = 'csrf_token';
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

export function createSessionToken(user) {
  const isAdmin = ['admin', 'superadmin'].includes(String(user.role || '').toLowerCase());
  const maxAge = isAdmin ? CONFIG.SESSION_ADMIN_MAX_AGE : CONFIG.SESSION_USER_MAX_AGE;

  const payload = JSON.stringify({
    uid: user.id,
    username: user.username,
    role: user.role || 'User',
    iat: Date.now(),
    exp: Date.now() + maxAge * 1000
  });

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_KEY, iv);
  const ct = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const token = `v2.${iv.toString('base64url')}.${tag.toString('base64url')}.${ct.toString('base64url')}`;
  const sig = crypto.createHmac('sha256', CONFIG.SESSION_SECRET || 'fallback').update(token).digest('base64url');
  return `${token}.${sig}`;
}

export function getSessionMaxAge(user) {
  const isAdmin = ['admin', 'superadmin'].includes(String(user.role || '').toLowerCase());
  return isAdmin ? CONFIG.SESSION_ADMIN_MAX_AGE : CONFIG.SESSION_USER_MAX_AGE;
}

export function verifySession(req) {
  const t = parseCookies(req)[COOKIE_SESSION];
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
    return d.exp > Date.now() ? d : null;
  } catch {
    return null;
  }
}

export function generateCSRFToken(session) {
  return crypto.createHmac('sha256', CONFIG.SESSION_SECRET || 'fallback')
    .update(`csrf:${session.uid}:${session.iat || session.exp}`)
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

export function setSessionCookie(res, sessionToken, csrfToken, user) {
  const maxAge = user ? getSessionMaxAge(user) : CONFIG.SESSION_ADMIN_MAX_AGE;
  const isProd = process.env.NODE_ENV === 'production' ||
                 process.env.VERCEL === '1' ||
                 !!process.env.VERCEL_ENV;

  if (typeof res.cookie === 'function') {
    try {
      res.cookie(COOKIE_SESSION, sessionToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax',
        path: '/',
        maxAge: maxAge * 1000
      });
      res.cookie(COOKIE_CSRF, csrfToken, {
        httpOnly: false,
        secure: isProd,
        sameSite: 'lax',
        path: '/',
        maxAge: maxAge * 1000
      });
      return;
    } catch (e) {
      // fallback ke manual
    }
  }

  const secureFlag = isProd ? '; Secure' : '';
  const baseAttrs = `Path=/; SameSite=Lax; Max-Age=${maxAge}${secureFlag}`;
  appendSetCookie(res, `${COOKIE_SESSION}=${encodeURIComponent(sessionToken)}; HttpOnly; ${baseAttrs}`);
  appendSetCookie(res, `${COOKIE_CSRF}=${encodeURIComponent(csrfToken)}; ${baseAttrs}`);
}

export function clearSessionCookie(res) {
  if (typeof res.clearCookie === 'function') {
    try {
      res.clearCookie(COOKIE_SESSION, { path: '/' });
      res.clearCookie(COOKIE_CSRF, { path: '/' });
      return;
    } catch (e) {
      // fallback
    }
  }

  const past = 'Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  appendSetCookie(res, `${COOKIE_SESSION}=; HttpOnly; ${past}`);
  appendSetCookie(res, `${COOKIE_CSRF}=; ${past}`);
}