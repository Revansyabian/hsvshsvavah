import crypto from 'node:crypto';
import admin from 'firebase-admin';
import bcrypt from 'bcryptjs';

const ADMIN_KEY = process.env.ADMIN_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;
const TRANSPORT_PRIVATE_KEY = process.env.TRANSPORT_PRIVATE_KEY;
const RECAPTCHA_V2_SECRET_KEY = process.env.RECAPTCHA_V2_SECRET_KEY || '';
const RECAPTCHA_V2_SITE_KEY = '6LeffrotAAAAAO7SRbl-wJQ8YXzOGNG-t-DW5EGT';

if (!ADMIN_KEY || ADMIN_KEY.length < 32) throw new Error('ADMIN_KEY wajib di-set dan minimal 32 karakter');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET wajib di-set dan minimal 32 karakter');

/* =========================================
   ADMIN RATE LIMIT
========================================= */

const ADMIN_LOGIN_LIMIT = 60;
const ADMIN_ACTION_LIMIT = 120;
const ADMIN_WRONG_LOGIN_LIMIT = 4;
const ADMIN_WRONG_LOGIN_WINDOW = 60 * 60 * 1000;
const adminRateStore = new Map();

function adminRateCheck(req, type, limit) {
  const now = Date.now();
  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  const fp = String(req.headers['x-fingerprint'] || '');
  const key = `${type}:${ip}:${fp}`;
  const windowMs = 60 * 1000;
  let entry = adminRateStore.get(key);
  if (!entry || now - entry.start >= windowMs) entry = { start: now, count: 0 };
  entry.count++;
  adminRateStore.set(key, entry);
  if (adminRateStore.size > 5000) {
    for (const [k, v] of adminRateStore.entries()) {
      if (now - v.start >= windowMs) adminRateStore.delete(k);
    }
  }
  return entry.count <= limit;
}

async function verifyRecaptchaV2(token, req) {
  if (!RECAPTCHA_V2_SECRET_KEY || !token) return false;
  try {
    const params = new URLSearchParams();
    params.set('secret', RECAPTCHA_V2_SECRET_KEY);
    params.set('response', String(token));
    const ip = ipOf(req);
    if (ip && ip !== 'unknown') params.set('remoteip', ip);
    const r = await fetch('https://www.google.com/recaptcha/api/siteverify', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:params.toString() });
    const data = await r.json();
    return data.success === true;
  } catch { return false; }
}

async function getLoginAttempt(ip, fp) {
  const key = `${dbKey(ip)}_${dbKey(fp || 'nofp')}`;
  const ref = db.ref(`admin_login_attempts/${key}`);
  const snap = await ref.once('value');
  const data = decryptAtRest(snap.val()?.data) || {};
  if (data.firstAt && Date.now() - Number(data.firstAt) > ADMIN_WRONG_LOGIN_WINDOW) { await ref.remove(); return {count:0,ref,data:{}}; }
  return {count:Number(data.count||0),ref,data};
}
async function recordWrongLogin(ip, fp) {
  const state=await getLoginAttempt(ip,fp); const count=state.count+1;
  await state.ref.set({data:encryptAtRest({count,firstAt:state.data.firstAt||Date.now(),lastAt:Date.now(),ip,fingerprint:fp||''})});
  return count;
}
async function resetWrongLogin(ip, fp) {
  await db.ref(`admin_login_attempts/${dbKey(ip)}_${dbKey(fp || 'nofp')}`).remove();
}
async function isIPBlocked(ip) {
  if(!ip)return false; const snap=await db.ref(`blocked_ips/${String(ip).replace(/\./g,'_')}`).once('value'); return decryptAtRest(snap.val()?.data)?.blocked===true;
}
async function isFPBlocked(fp) {
  if(!fp)return false; const snap=await db.ref(`blocked_fp/${dbKey(fp)}`).once('value'); return decryptAtRest(snap.val()?.data)?.blocked===true;
}
async function blockIP(ip, reason) {
  if(!ip)return; await db.ref(`blocked_ips/${String(ip).replace(/\./g,'_')}`).set({data:encryptAtRest({ip,blocked:true,reason:reason||'',blockedAt:Date.now(),source:'admin-login'})});
}
async function blockFP(fp, reason) {
  if(!fp)return; await db.ref(`blocked_fp/${dbKey(fp)}`).set({data:encryptAtRest({fingerprint:fp,blocked:true,reason:reason||'',blockedAt:Date.now(),source:'admin-login'})});
}

let privateKey;

if (!TRANSPORT_PRIVATE_KEY) {
  throw new Error('TRANSPORT_PRIVATE_KEY belum diset di environment');
}

try {
  privateKey = crypto.createPrivateKey(
    TRANSPORT_PRIVATE_KEY.replace(/\\n/g, '\n')
  );
} catch (error) {
  console.error('[ADMIN TRANSPORT KEY]', error?.message || error);
  throw new Error('TRANSPORT_PRIVATE_KEY tidak valid');
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
  res.setHeader('Set-Cookie',
    `__Host_admin_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`);
}
function clearSession(res) {
  res.setHeader('Set-Cookie',
    '__Host_admin_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
}
function sameOrigin(req) {
  const origin = String(req.headers.origin || '');
  if (!origin) return true;
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
  if (allowed.length) return allowed.includes(origin);
  const host = String(req.headers.host || '');
  return origin === `https://${host}` || origin === `http://${host}` || origin === 'null';
}
function requireAdmin(req, res) {
  const session = getSession(req);
  if (!session || !['admin', 'superadmin'].includes(String(session.role).toLowerCase())) {
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
  const ip=ipOf(req), fp=fpOf(req);
  const identifier=safe(body.username||body.email||'');
  const password=String(body.password||'');
  const captchaToken=String(body.captchaToken||'');
  if(!identifier||!password) return response(res,400,{success:false,message:'Username/email dan password wajib diisi.'},clientJwk);

  if(await isIPBlocked(ip)||(fp&&await isFPBlocked(fp))){
    await logAdmin(null,'login_blocked',`Percobaan login dari IP/FP yang diblokir (${identifier})`,req);
    return response(res,403,{success:false,error:'blocked',message:'IP atau perangkat ini telah diblokir dari panel admin.'},clientJwk);
  }
  if(!RECAPTCHA_V2_SECRET_KEY){
    await logAdmin(null,'login_failed','reCAPTCHA admin belum dikonfigurasi',req);
    return response(res,503,{success:false,error:'captcha_not_configured',message:'RECAPTCHA_V2_SECRET_KEY belum diset di environment server.'},clientJwk);
  }
  if(!(await verifyRecaptchaV2(captchaToken,req))){
    await logAdmin(null,'login_failed',`reCAPTCHA admin gagal (${identifier})`,req);
    return response(res,400,{success:false,error:'captcha_failed',message:'Verifikasi reCAPTCHA gagal. Silakan coba lagi.'},clientJwk);
  }

  let found=await findUser(identifier);
  if(!found&&process.env.ADMIN_USERNAME&&identifier===process.env.ADMIN_USERNAME&&process.env.ADMIN_PASSWORD_HASH){
    if(await bcrypt.compare(password,process.env.ADMIN_PASSWORD_HASH)){
      found={id:'env-admin',data:{username:process.env.ADMIN_USERNAME,role:'Admin',password_hash:process.env.ADMIN_PASSWORD_HASH}};
    }
  }
  const validAdmin=!!found&&['admin','superadmin'].includes(String(found.data.role||'').toLowerCase());
  const validPassword=validAdmin&&found.data.password_hash?await bcrypt.compare(password,found.data.password_hash):false;
  if(!validAdmin||!validPassword){
    const count=await recordWrongLogin(ip,fp), remaining=Math.max(0,ADMIN_WRONG_LOGIN_LIMIT-count);
    await logAdmin(null,'login_failed',`Login admin gagal (${identifier}) percobaan ke-${count}${remaining?`, sisa ${remaining}`:''}`,req);
    if(count>=ADMIN_WRONG_LOGIN_LIMIT){
      await Promise.all([blockIP(ip,'Lebih dari 3 kali login admin gagal'),fp?blockFP(fp,'Lebih dari 3 kali login admin gagal'):Promise.resolve()]);
      await logAdmin(null,'suspicious_login_block',`IP dan fingerprint diblokir setelah ${count} login admin gagal (${identifier})`,req);
      return response(res,403,{success:false,error:'blocked',attempts:count,message:'Login gagal lebih dari 3 kali. IP dan perangkat ini telah diblokir.'},clientJwk);
    }
    return response(res,401,{success:false,error:'invalid_credentials',attempts:count,remaining,message:'Username/email atau password salah.'},clientJwk);
  }
  await resetWrongLogin(ip,fp);
  const session={uid:found.id,username:found.data.username,role:found.data.role};
  setSession(res,makeSession(session));
  await logAdmin(session,'login_success','Admin berhasil login',req);
  return response(res,200,{success:true,username:session.username,role:session.role},clientJwk);
}


async function findAdminSessionUser(session) {
  if (!session?.uid || session.uid === 'env-admin') return null;
  const users = await getUsers();
  const row = users[session.uid];
  if (!row) return null;
  return { id: session.uid, data: decodeUser(row) };
}

async function migrateAllPasswords(session, req) {
  const users = await getUsers();
  let migrated=0, alreadyHashed=0, skipped=0, failed=0;
  for (const [id,row] of Object.entries(users)) {
    try {
      const u=decodeUser(row);
      if (!u || !Object.keys(u).length) { skipped++; continue; }
      if (u.password_hash && String(u.password_hash).startsWith('$2')) { alreadyHashed++; continue; }
      const plain = u.password ?? u.passwordPlain ?? u.password_plaintext;
      if (!plain) { skipped++; continue; }
      u.password_hash = await bcrypt.hash(String(plain), 12);
      delete u.password;
      delete u.passwordPlain;
      delete u.password_plaintext;
      await saveUser(id,u);
      migrated++;
    } catch { failed++; }
  }
  await logAdmin(session,'migrate-passwords',`Migrasi password: ${migrated} berhasil, ${alreadyHashed} sudah hash, ${skipped} dilewati, ${failed} gagal`,req);
  return {migrated,alreadyHashed,skipped,failed};
}

async function migrateAllUsersFormat(session, req) {
  const users = await getUsers();
  let migrated=0, skipped=0, failed=0;
  for (const [id,row] of Object.entries(users)) {
    try {
      const u=decodeUser(row);
      if (!u || !Object.keys(u).length) { skipped++; continue; }
      await saveUser(id,u);
      migrated++;
    } catch { failed++; }
  }
  await logAdmin(session,'migrate_users_format',`Migrasi format user: ${migrated} berhasil, ${skipped} dilewati, ${failed} gagal`,req);
  return {migrated,skipped,failed};
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

  if (action === 'maintenance-status') {
    const m = decryptAtRest((await db.ref('maintenance_status').once('value')).val()?.data) || {};
    return response(res, 200, { success:true, maintenance:m.maintenance===true, title:m.title||'', message:m.message||'', until:m.until||0, updatedAt:m.updatedAt||0, updatedBy:m.updatedBy||'' }, clientJwk);
  }

  if (action === 'suspicious-logs') {
    const snap = await db.ref('activity_logs').limitToLast(300).once('value');
    const logs = Object.values(snap.val()||{}).map(row=>decryptAtRest(row?.data)).filter(Boolean)
      .filter(x=>/failed|blocked|ban|sharing|suspicious|force|access/i.test(`${x.action||''} ${x.details||''}`))
      .sort((a,b)=>Number(b.timestamp||0)-Number(a.timestamp||0));
    return response(res,200,{success:true,logs},clientJwk);
  }

  if (action === 'auth') {
    const found = await findAdminSessionUser(session);
    if (!found) return response(res,200,{success:true,email:session.username||'',username:session.username||'',role:session.role},clientJwk);
    return response(res,200,{success:true,email:found.data.email||'',username:found.data.username||session.username,role:found.data.role||session.role},clientJwk);
  }

  if (action === 'change-email') {
    const email=safe(body.email,200);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return response(res,400,{success:false,message:'Email tidak valid.'},clientJwk);
    const found=await findAdminSessionUser(session);
    if (!found) return response(res,400,{success:false,message:'Admin environment tidak bisa mengganti email dari panel.'},clientJwk);
    found.data.email=email;
    await saveUser(found.id,found.data);
    await logAdmin(session,'change-email',`Email admin diubah menjadi ${email}`,req);
    return response(res,200,{success:true,message:'Email admin berhasil diubah.',email},clientJwk);
  }

  if (action === 'change-password') {
    const password=String(body.password||'');
    if (password.length<8) return response(res,400,{success:false,message:'Password minimal 8 karakter.'},clientJwk);
    const found=await findAdminSessionUser(session);
    if (!found) return response(res,400,{success:false,message:'Admin environment tidak bisa mengganti password dari panel.'},clientJwk);
    found.data.password_hash=await bcrypt.hash(password,12);
    delete found.data.password;
    await saveUser(found.id,found.data);
    await logAdmin(session,'change-password','Password admin berhasil diubah',req);
    return response(res,200,{success:true,message:'Password admin berhasil diubah.'},clientJwk);
  }

  if (action === 'migrate-passwords') {
    const result=await migrateAllPasswords(session,req);
    return response(res,200,{success:true,message:'Migrasi password selesai.',...result},clientJwk);
  }

  if (action === 'migrate_users_format') {
    const result=await migrateAllUsersFormat(session,req);
    return response(res,200,{success:true,message:'Migrasi format user selesai.',...result},clientJwk);
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


  if (action === 'edit-user') {
    const found=await findUser(body.id||body.username||body.email||'');
    if(!found) return response(res,404,{success:false,message:'User tidak ditemukan.'},clientJwk);
    const u={...found.data};
    for (const k of ['username','email','phone','role','expiry_date','status','isActive','needsActivation','activationStatus']) {
      if (body[k] !== undefined) u[k] = ['isActive','needsActivation'].includes(k) ? Boolean(body[k]) : safe(body[k],300);
    }
    if (body.password) u.password_hash=await bcrypt.hash(String(body.password),12);
    delete u.password;
    await saveUser(found.id,u);
    await logAdmin(session,'edit-user',`Mengubah data user ${u.username}`,req);
    return response(res,200,{success:true,message:'User berhasil diperbarui.',user:publicUser(found.id,u)},clientJwk);
  }

  const identifier = safe(body.username || body.email || req.query.username || req.query.user || '', 200);

  if (['banned', 'unbanned', 'ban-akses', 'unban-akses', 'force', 'unforce', 'delete-user', 'reset-count'].includes(action)) {
    const found = await findUser(identifier);
    if (!found) return response(res, 404, { success: false, message: 'User tidak ditemukan.' }, clientJwk);
    const u = { ...found.data };

    if (action === 'banned') u.banned = true;
    if (action === 'unbanned') u.banned = false;
    if (action === 'ban-akses') { u.accessBanned = true; u.banAkses = true; }
    if (action === 'unban-akses') { u.accessBanned = false; u.banAkses = false; }
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

  if (action === 'clear-logs') {
    await db.ref('activity_logs').remove();
    return response(res, 200, {
      success: true,
      message: 'Semua Activity Log berhasil dihapus.'
    }, clientJwk);
  }

  if (action === 'logs') {
    const limit = Math.min(Math.max(Number(body.limit || req.query.limit || 100), 1), 100);
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

  if (['block-ip','unblock-ip','block-fp','unblock-fp'].includes(action)) {
    const value=safe(body.value||req.query.value||(action.includes('ip')?req.query.ip:req.query.fp),300);
    if(!value)return response(res,400,{success:false,message:'IP/FP wajib diisi.'},clientJwk);
    const isIP=action.includes('ip'), blocked=!action.startsWith('un'), root=isIP?'blocked_ips':'blocked_fp';
    const pathKey=isIP?value.replace(/\./g,'_'):dbKey(value);
    if(blocked) await db.ref(`${root}/${pathKey}`).set({data:encryptAtRest({blocked:true,...(isIP?{ip:value}:{fingerprint:value}),updatedAt:Date.now(),updatedBy:session.username,source:'admin-panel'})});
    else await db.ref(`${root}/${pathKey}`).remove();
    await logAdmin(session,action,`${isIP?'IP':'FP'} ${value} => ${blocked?'blocked':'unblocked'}`,req);
    return response(res,200,{success:true,blocked,value},clientJwk);
  }

  return response(res, 404, { success: false, message: `Action tidak dikenal: ${action}` }, clientJwk);
}

export default async function handler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Fingerprint');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (!sameOrigin(req)) return res.status(403).json({ success: false, message: 'Origin tidak diizinkan.' });
  if (req.method === 'OPTIONS') return res.status(204).end();

  const action = safe(req.query.action || '', 80).toLowerCase();
  if (action === 'key') {
    return res.status(200).json({ v: 1, alg: 'RSA-OAEP-256/AES-256-GCM', publicKey: publicJwk });
  }
  if (action === 'recaptcha-site-key') {
    return res.status(200).json({ siteKey: RECAPTCHA_V2_SITE_KEY });
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

    if (!adminRateCheck(req, action === 'login' ? 'login' : 'action', action === 'login' ? ADMIN_LOGIN_LIMIT : ADMIN_ACTION_LIMIT)) {
      return response(res, 429, {success:false,message:'Terlalu banyak request. Coba lagi nanti.'}, clientJwk);
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
