
function addCookie(res, value) {
  const current = res.getHeader?.('Set-Cookie');
  const list = Array.isArray(current) ? current : (current ? [current] : []);
  res.setHeader('Set-Cookie', [...list, value]);
}

function setAdminCsrfCookie(res, token = crypto.randomBytes(32).toString('base64url')) {
  addCookie(res, `${ADMIN_CSRF_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=604800; Secure; SameSite=Strict`);
  return token;
}

// API keys are server-side only. The admin panel sends the key with every
// authenticated action; the server validates it against ADMIN_API_KEYS.
// Supported env formats:
//   ADMIN_API_KEYS=key1,key2,key3
// or a JSON array:
//   ADMIN_API_KEYS=["key1","key2"]
function getConfiguredAdminApiKeys() {
  const raw = String(process.env.ADMIN_API_KEYS || "").trim();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.map(String).map(s => s.trim()).filter(Boolean);
  } catch {}
  return raw.split(",").map(s => s.trim()).filter(Boolean);
}

function extractAdminApiKey(req, body = {}) {
  return String(
    req.headers?.["x-admin-api-key"] ||
    req.headers?.["x-api-key"] ||
    body?.apiKey ||
    ""
  ).trim();
}

function isValidAdminApiKey(req, body = {}) {
  const supplied = extractAdminApiKey(req, body);
  if (!supplied) return false;
  const configured = getConfiguredAdminApiKeys();
  return configured.some(key => {
    const a = Buffer.from(supplied);
    const b = Buffer.from(key);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}

// All privileged actions must pass server-side authentication, CSRF and rate limits.
// The browser UI is never treated as an authorization boundary.

const ADMIN_SESSION_COOKIE = "__Host_admin_session";
const ADMIN_CSRF_COOKIE = "__Host_admin_csrf";
const ADMIN_RATE_WINDOW_MS = 15 * 60 * 1000;
const ADMIN_LOGIN_LIMIT = 5;
const ADMIN_ACTION_LIMIT = 60;

const adminRate = globalThis.__adminRate || new Map();
globalThis.__adminRate = adminRate;

function adminClientIp(req) {
  const xf = String(req.headers?.["x-forwarded-for"] || "").split(",")[0].trim();
  return xf || String(req.socket?.remoteAddress || "unknown");
}

function adminRateCheck(req, bucket, limit) {
  const key = `${bucket}:${adminClientIp(req)}`;
  const now = Date.now();
  let entry = adminRate.get(key);
  if (!entry || now - entry.started > ADMIN_RATE_WINDOW_MS) {
    entry = { started: now, count: 0 };
  }
  entry.count++;
  adminRate.set(key, entry);
  return entry.count <= limit;
}

function adminCookie(req, name) {
  const raw = String(req.headers?.cookie || "");
  const part = raw.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="));
  return part ? decodeURIComponent(part.slice(name.length + 1)) : "";
}

function safeTimingEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

function adminSessionIsValid(req) {
  if (typeof getSession === 'function') return !!getSession(req);
  return false;
}

function adminCsrfIsValid(req) {
  const cookieToken = adminCookie(req, ADMIN_CSRF_COOKIE);
  const headerToken = String(req.headers?.["x-csrf-token"] || "");
  return !!cookieToken && !!headerToken && safeTimingEqual(cookieToken, headerToken);
}

const ADMIN_READ_ACTIONS = new Set([
  "users", "stats", "logs", "get-users", "get-stats", "get-logs",
  "maintenance-status", "auth", "me"
]);

const ADMIN_MUTATION_ACTIONS = new Set([
  "add-user", "banned", "unbanned", "ban-akses", "unban-akses",
  "force", "unforce", "delete-user", "maintenance",
  "set-maintenance", "migrate-passwords", "migrate_users_format"
]);

function adminActionAllowed(action) {
  return ADMIN_READ_ACTIONS.has(action) || ADMIN_MUTATION_ACTIONS.has(action) ||
         action === "login" || action === "logout";
}

function adminSecurityReject(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

import crypto from 'node:crypto';
import admin from 'firebase-admin';
import bcrypt from 'bcryptjs';

const ADMIN_KEY = process.env.ADMIN_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;
const TRANSPORT_PRIVATE_KEY = process.env.TRANSPORT_PRIVATE_KEY;

if (!ADMIN_KEY || ADMIN_KEY.length < 32) throw new Error('ADMIN_KEY wajib di-set dan minimal 32 karakter');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET wajib di-set dan minimal 32 karakter');

let privateKey;
if (TRANSPORT_PRIVATE_KEY) {
  try {
    privateKey = crypto.createPrivateKey(TRANSPORT_PRIVATE_KEY.replace(/\\n/g, '\n'));
  } catch {
    throw new Error('TRANSPORT_PRIVATE_KEY tidak valid');
  }
} else {
  // Development fallback only. Set TRANSPORT_PRIVATE_KEY di Vercel agar key stabil.
  privateKey = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  }).privateKey;
}
const publicKey = crypto.createPublicKey(privateKey);
const publicJwk = publicKey.export({ format: 'jwk' });

function b64(buf) { return Buffer.from(buf).toString('base64url'); }
function fromB64(v) { return Buffer.from(String(v || ''), 'base64url'); }

function decryptTransport(envelope) {
  if (!envelope || envelope.v !== 1 || envelope.alg !== 'RSA-OAEP-256/AES-256-GCM') {
    throw new Error('Encrypted request required');
  }
  const aesKey = crypto.privateDecrypt({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, fromB64(envelope.key));
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, fromB64(envelope.iv));
  decipher.setAuthTag(fromB64(envelope.tag));
  const plain = Buffer.concat([
    decipher.update(fromB64(envelope.data)),
    decipher.final()
  ]).toString('utf8');
  return JSON.parse(plain);
}

function encryptTransport(data, clientJwk) {
  if (!clientJwk || clientJwk.kty !== 'RSA') throw new Error('Client public key required');
  const clientPublicKey = crypto.createPublicKey({ key: clientJwk, format: 'jwk' });
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(data ?? null), 'utf8')),
    cipher.final()
  ]);
  const wrappedKey = crypto.publicEncrypt({
    key: clientPublicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, aesKey);
  return {
    v: 1,
    alg: 'RSA-OAEP-256/AES-256-GCM',
    key: b64(wrappedKey),
    iv: b64(iv),
    tag: b64(cipher.getAuthTag()),
    data: b64(ciphertext)
  };
}

function keyFromSecret(secret) {
  return crypto.createHash('sha256').update(String(secret)).digest();
}
function encryptAtRest(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyFromSecret(ADMIN_KEY), iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value ?? null), 'utf8'),
    cipher.final()
  ]);
  return 'v2.' + Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
}
function decryptAtRest(raw) {
  if (typeof raw !== 'string' || !raw.startsWith('v2.')) return null;
  try {
    const b = Buffer.from(raw.slice(3), 'base64url');
    const iv = b.subarray(0, 12);
    const tag = b.subarray(12, 28);
    const ciphertext = b.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyFromSecret(ADMIN_KEY), iv);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
  } catch { return null; }
}

if (!admin.apps.length) {
  const key = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: key
    }),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
}
const db = admin.database();

function ipOf(req) {
  return String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown')
    .split(',')[0].trim();
}
function fpOf(req) { return String(req.headers['x-fingerprint'] || ''); }
function safe(v, max = 200) {
  return String(v ?? '').trim().slice(0, max);
}
function dbKey(v) { return safe(v, 300).replace(/[.#$[\]/]/g, '_') || 'unknown'; }

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function makeSession(user) {
  const payload = Buffer.from(JSON.stringify({
    uid: user.uid,
    username: user.username,
    role: user.role,
    iat: Date.now(),
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function getSession(req) {
  const token = parseCookies(req).__Host_admin_session;
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const d = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return d.exp > Date.now() ? d : null;
  } catch { return null; }
}
function setSession(res, token) {
  addCookie(res, `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`);
  setAdminCsrfCookie(res);
}
function clearSession(res) {
  addCookie(res, `${ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
  addCookie(res, `${ADMIN_CSRF_COOKIE}=; Path=/; Secure; SameSite=Strict; Max-Age=0`);
}
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
  return allowed.length ? allowed.includes(origin) : false;
}
function requireAdmin(req, res) {
  const session = getSession(req);
  if (!session || !['admin', 'superadmin'].includes(String(session.role).toLowerCase())) {
    res.status(401).json({ success: false, message: 'Sesi admin tidak valid.' });
    return null;
  }
  return session;
}

async function getUsers() {
  const snap = await db.ref('users').once('value');
  return snap.val() || {};
}
function decodeUser(row) {
  const raw = row?.data;
  if (typeof raw === 'string') return decryptAtRest(raw) || {};
  return raw && typeof raw === 'object' ? raw : {};
}
function publicUser(id, u) {
  return {
    id,
    username: u.username || '',
    email: u.email || '',
    role: u.role || 'User',
    banned: u.banned === true,
    accessBanned: u.accessBanned === true || u.banAkses === true,
    forceLogout: u.forceLogout === true,
    resetCount: Number(u.resetCount || u.reset_count || 0),
    createdAt: u.createdAt || u.created_at || null,
    lastLogin: u.lastLogin || null,
    ipHistory: Array.isArray(u.ipHistory) ? u.ipHistory.slice(-5) : [],
    fpHistory: Array.isArray(u.fpHistory) ? u.fpHistory.slice(-5) : []
  };
}
async function findUser(identifier) {
  const users = await getUsers();
  const wanted = safe(identifier, 200).toLowerCase();
  for (const [id, row] of Object.entries(users)) {
    const u = decodeUser(row);
    if (String(u.username || '').toLowerCase() === wanted ||
        String(u.email || '').toLowerCase() === wanted) {
      return { id, data: u, row };
    }
  }
  return null;
}
async function saveUser(id, data) {
  await db.ref(`users/${id}`).set({
    data: encryptAtRest(data),
    formatVersion: 2
  });
}
async function logAdmin(session, action, details, req) {
  const entry = {
    username: session?.username || 'admin',
    action: `admin:${action}`,
    details: safe(details, 1000),
    ip: ipOf(req),
    fingerprint: fpOf(req),
    timestamp: Date.now()
  };
  try {
    await db.ref('activity_logs').push({ data: encryptAtRest(entry) });
  } catch {}
}

function response(res, status, payload, clientJwk) {
  try {
    return res.status(status).json({
      encrypted: true,
      data: encryptTransport(payload, clientJwk)
    });
  } catch (e) {
    return res.status(500).json({ success: false, message: 'Gagal mengenkripsi response.' });
  }
}

async function actionLogin(req, res, body, clientJwk) {
  const identifier = safe(body.username || body.email || '');
  const password = String(body.password || '');
  if (!identifier || !password) return response(res, 400, { success: false, message: 'Username/email dan password wajib diisi.' }, clientJwk);

  let found = await findUser(identifier);
  if (!found && process.env.ADMIN_USERNAME && identifier === process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD_HASH) {
    if (await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH)) {
      found = { id: 'env-admin', data: { username: process.env.ADMIN_USERNAME, role: 'Admin' } };
    }
  }
  if (!found || !['admin', 'superadmin'].includes(String(found.data.role || '').toLowerCase())) {
    return response(res, 401, { success: false, message: 'Akun admin tidak ditemukan.' }, clientJwk);
  }
  const hash = found.data.password_hash;
  if (!hash || !(await bcrypt.compare(password, hash))) {
    return response(res, 401, { success: false, message: 'Password admin salah.' }, clientJwk);
  }
  const session = { uid: found.id, username: found.data.username, role: found.data.role };
  setSession(res, makeSession(session));
  await logAdmin(session, 'login', 'Admin berhasil login', req);
  return response(res, 200, { success: true, username: session.username, role: session.role }, clientJwk);
}

async function handle(req, res, action, body, clientJwk) {
  if (action === 'login') return actionLogin(req, res, body, clientJwk);

  if (action === 'logout') {
    const session = getSession(req);
    if (session) await logAdmin(session, 'logout', 'Admin logout', req);
    clearSession(res);
    return response(res, 200, { success: true, message: 'Logout berhasil.' }, clientJwk);
  }

  const session = requireAdmin(req, res);
  if (!session) return response(res, 401, { success: false, message: 'Sesi admin tidak valid.' }, clientJwk);

  if (action === 'me') {
    return response(res, 200, { success: true, admin: { username: session.username, role: session.role } }, clientJwk);
  }

  if (action === 'users' || action === 'list-users') {
    const users = await getUsers();
    const list = Object.entries(users).map(([id, row]) => publicUser(id, decodeUser(row)));
    return response(res, 200, { success: true, users: list }, clientJwk);
  }

  if (action === 'add-user') {
    const username = safe(body.username || req.query.username, 100);
    const email = safe(body.email || req.query.email, 200);
    const password = String(body.password || '');
    const role = safe(body.role || 'User', 30) || 'User';
    if (!username || username.length < 3 || password.length < 6) {
      return response(res, 400, { success: false, message: 'Username minimal 3 dan password minimal 6 karakter.' }, clientJwk);
    }
    if (!['User', 'Admin'].includes(role)) return response(res, 400, { success: false, message: 'Role tidak valid.' }, clientJwk);
    if (await findUser(username)) return response(res, 409, { success: false, message: 'Username sudah digunakan.' }, clientJwk);
    if (email && await findUser(email)) return response(res, 409, { success: false, message: 'Email sudah digunakan.' }, clientJwk);
    const id = db.ref('users').push().key;
    const password_hash = await bcrypt.hash(password, 12);
    const user = {
      username, email, role, password_hash,
      banned: false, accessBanned: false, forceLogout: false,
      resetCount: 0, createdAt: Date.now(),
      ipHistory: [], fpHistory: []
    };
    await saveUser(id, user);
    await logAdmin(session, 'add-user', `Menambah user ${username}`, req);
    return response(res, 200, { success: true, message: 'User berhasil ditambahkan.', user: publicUser(id, user) }, clientJwk);
  }

  const identifier = safe(body.username || body.email || req.query.username || req.query.user || '', 200);

  if (['banned', 'unbanned', 'ban-akses', 'unban-akses', 'force', 'unforce', 'delete-user', 'reset-count'].includes(action)) {
    const found = await findUser(identifier);
    if (!found) return response(res, 404, { success: false, message: 'User tidak ditemukan.' }, clientJwk);
    const u = { ...found.data };

    if (action === 'banned') u.banned = true;
    if (action === 'unbanned') u.banned = false;
    if (action === 'ban-akses') u.accessBanned = true;
    if (action === 'unban-akses') u.accessBanned = false;
    if (action === 'force') u.forceLogout = true;
    if (action === 'unforce') u.forceLogout = false;
    if (action === 'reset-count') u.resetCount = 0;

    if (action === 'delete-user') {
      await db.ref(`users/${found.id}`).remove();
      await logAdmin(session, action, `Menghapus user ${found.data.username}`, req);
      return response(res, 200, { success: true, message: 'User berhasil dihapus.' }, clientJwk);
    }

    await saveUser(found.id, u);
    await logAdmin(session, action, `Aksi ${action} pada ${u.username}`, req);
    return response(res, 200, { success: true, message: `Aksi ${action} berhasil.`, user: publicUser(found.id, u) }, clientJwk);
  }

  if (action === 'maintenance') {
    const enabled = body.enabled !== undefined ? Boolean(body.enabled) : String(req.query.enabled || '') === 'true';
    const title = safe(body.title || req.query.title || 'SEDANG PERBAIKAN SISTEM', 200);
    const message = safe(body.message || req.query.message || 'Website sedang dalam perbaikan oleh admin.', 1000);
    const until = safe(body.until || req.query.until || '', 100);
    await db.ref('maintenance_status').set({
      data: encryptAtRest({ maintenance: enabled, title, message, until, updatedAt: Date.now(), updatedBy: session.username })
    });
    await logAdmin(session, 'maintenance', enabled ? 'Maintenance ON' : 'Maintenance OFF', req);
    return response(res, 200, { success: true, maintenance: enabled, title, message, until }, clientJwk);
  }

  if (action === 'logs') {
    const limit = Math.min(Math.max(Number(body.limit || req.query.limit || 100), 1), 300);
    const snap = await db.ref('activity_logs').limitToLast(limit).once('value');
    const logs = Object.values(snap.val() || {}).map(row => decryptAtRest(row?.data)).filter(Boolean)
      .sort((a, b) => Number(b.timestamp || 0) - Number(a.timestamp || 0));
    return response(res, 200, { success: true, logs }, clientJwk);
  }

  if (action === 'stats') {
    const users = await getUsers();
    let total = 0, banned = 0, accessBanned = 0, forced = 0;
    for (const row of Object.values(users)) {
      const u = decodeUser(row);
      total++;
      if (u.banned === true) banned++;
      if (u.accessBanned === true || u.banAkses === true) accessBanned++;
      if (u.forceLogout === true) forced++;
    }
    const m = decryptAtRest((await db.ref('maintenance_status').once('value')).val()?.data) || {};
    return response(res, 200, {
      success: true,
      stats: { total, banned, accessBanned, forced, maintenance: m.maintenance === true }
    }, clientJwk);
  }

  if (['block-ip', 'unblock-ip', 'block-fp', 'unblock-fp'].includes(action)) {
    const value = safe(body.value || req.query.value || (action.includes('ip') ? req.query.ip : req.query.fp), 300);
    if (!value) return response(res, 400, { success: false, message: 'IP/FP wajib diisi.' }, clientJwk);
    const root = action.includes('ip') ? 'blocked_ips' : 'blocked_fp';
    const blocked = !action.startsWith('un');
    await db.ref(`${root}/${dbKey(value)}`).set({
      data: encryptAtRest({ blocked, value, updatedAt: Date.now(), updatedBy: session.username })
    });
    await logAdmin(session, action, `${value} => ${blocked ? 'blocked' : 'unblocked'}`, req);
    return response(res, 200, { success: true, blocked, value }, clientJwk);
  }

  return response(res, 404, { success: false, message: `Action tidak dikenal: ${action}` }, clientJwk);
}

export default async function handler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Fingerprint, X-Admin-API-Key, X-CSRF-Token');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (!sameOrigin(req)) return res.status(403).json({ success: false, message: 'Origin tidak diizinkan.' });
  if (req.method === 'OPTIONS') return res.status(204).end();

  const action = safe(req.query.action || '', 80).toLowerCase();
  if (action === 'key') {
    return res.status(200).json({ v: 1, alg: 'RSA-OAEP-256/AES-256-GCM', publicKey: publicJwk });
  }
  if (!action) return res.status(400).json({ success: false, message: 'Parameter action wajib diisi.' });

  try {
    const raw = req.body || {};
    let body = {};
    let clientJwk = null;

    if (raw && raw.envelope && raw.clientPublicKey) {
      body = decryptTransport(raw.envelope);
      clientJwk = raw.clientPublicKey;
    } else if (raw && raw.data && raw.clientPublicKey && raw.data.v === 1) {
      body = decryptTransport(raw.data);
      clientJwk = raw.clientPublicKey;
    } else {
      return res.status(400).json({ success: false, message: 'Request terenkripsi diperlukan.' });
    }

    if (!clientJwk || clientJwk.kty !== 'RSA') {
      return res.status(400).json({ success: false, message: 'Client public key tidak valid.' });
    }

    body.action = action;
    return await handle(req, res, action, body, clientJwk);
  } catch (e) {
    console.error('admin action error:', e);
    if (req.body?.clientPublicKey) {
      return response(res, 400, { success: false, message: 'Data terenkripsi tidak valid.' }, req.body.clientPublicKey);
    }
    return res.status(400).json({ success: false, message: 'Data terenkripsi tidak valid.' });
  }
}
