import crypto from 'node:crypto';
import CryptoJS from 'crypto-js';
import admin from 'firebase-admin';
import bcrypt from 'bcryptjs';


const MASTER_KEY = process.env.MASTER_KEY;
if (!MASTER_KEY || MASTER_KEY.length < 32) throw new Error('MASTER_KEY wajib di-set dan minimal 32 karakter');
const transportMasterKey = crypto.createHash('sha256').update(MASTER_KEY).digest();
const transportKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const serverPrivateKey = crypto.createPrivateKey(transportKeys.privateKey);
function b64(buf) { return Buffer.from(buf).toString('base64url'); }
function fromB64(value) { return Buffer.from(String(value || ''), 'base64url'); }
export function getTransportPublicKey() { return transportKeys.publicKey; }
export function decryptRequest(envelope) {
  if (!envelope || envelope.v !== 1 || envelope.alg !== 'RSA-OAEP-256/AES-256-GCM') throw new Error('Encrypted request required');
  const aesKey = crypto.privateDecrypt({ key: serverPrivateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, fromB64(envelope.key));
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, fromB64(envelope.iv));
  decipher.setAuthTag(fromB64(envelope.tag));
  const plain = Buffer.concat([decipher.update(fromB64(envelope.data)), decipher.final()]).toString('utf8');
  return JSON.parse(plain);
}
export function encryptResponse(data, clientPublicKeyPem) {
  if (!clientPublicKeyPem) throw new Error('Client public key required');
  let clientPublicKey;
  try {
    clientPublicKey = crypto.createPublicKey({ key: fromB64(clientPublicKeyPem), format: 'der', type: 'spki' });
  } catch {
    clientPublicKey = crypto.createPublicKey(clientPublicKeyPem);
  }
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(data ?? null), 'utf8')), cipher.final()]);
  const wrappedKey = crypto.publicEncrypt({ key: clientPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, aesKey);
  return { v: 1, alg: 'RSA-OAEP-256/AES-256-GCM', key: b64(wrappedKey), iv: b64(iv), tag: b64(cipher.getAuthTag()), data: b64(encrypted) };
}
function keyFromSecret(secret) { return crypto.createHash('sha256').update(String(secret)).digest(); }
function encryptAtRest(value, secret) {
  const key = keyFromSecret(secret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return 'v2.' + Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
}
function decryptAtRest(raw, secret) {
  if (typeof raw !== 'string' || !raw.startsWith('v2.')) return null;
  try {
    const b = Buffer.from(raw.slice(3), 'base64url');
    const iv=b.subarray(0,12), tag=b.subarray(12,28), ciphertext=b.subarray(28);
    const decipher=crypto.createDecipheriv('aes-256-gcm', keyFromSecret(secret), iv);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
  } catch { return null; }
}


const unifiedDb = (() => {
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
  return admin.database();
})();

function unifiedKey(v) { return String(v || 'unknown').replace(/[.#$\[\]\/]/g, '_'); }
function unifiedIP(req) {
  const raw=req.headers['x-forwarded-for'];
  return raw ? String(raw).split(',')[0].trim() : (req.socket.remoteAddress || 'unknown');
}
function unifiedFP(req) { return String(req.headers['x-fingerprint'] || ''); }
function unifiedDecryptStored(raw) {
  if (!raw?.data) return raw || {};
  try { return decryptAtRest(raw.data, process.env.ADMIN_KEY) || {}; } catch { return {}; }
}
async function unifiedBlocked(ip, fp) {
  const ipSnap=await unifiedDb.ref('blocked_ips/'+unifiedKey(ip)).once('value');
  if (unifiedDecryptStored(ipSnap.val()).blocked===true) return true;
  if (fp) {
    const fpSnap=await unifiedDb.ref('blocked_fp/'+unifiedKey(fp)).once('value');
    if (unifiedDecryptStored(fpSnap.val()).blocked===true) return true;
  }
  return false;
}
async function unifiedMaintenance() {
  const snap=await unifiedDb.ref('maintenance_status').once('value');
  const d=unifiedDecryptStored(snap.val());
  return { maintenance:d.maintenance===true, title:d.title||'SEDANG PERBAIKAN SISTEM', message:d.message||'Website sedang dalam perbaikan oleh admin.', until:d.until||null };
}
async function unifiedQuota(ip,fp) {
  const date=new Date().toISOString().slice(0,10), root=unifiedDb.ref('reset_usage_daily');
  const [a,b]=await Promise.all([root.child('ip_'+unifiedKey(ip)).once('value'),fp?root.child('fp_'+unifiedKey(fp)).once('value'):Promise.resolve({val:()=>null})]);
  const ad=unifiedDecryptStored(a.val()), bd=unifiedDecryptStored(b.val());
  const ac=ad.date===date?Number(ad.count||0):0, bc=bd.date===date?Number(bd.count||0):0, used=Math.max(ac,bc);
  return {used,remaining:Math.max(0,5-used),max:5,date};
}
async function unifiedLog(username,action,ip,fp,details='') {
  try {
    const message=`ip: ${ip||''} fp: ${fp||''} telah ${action}`;
    const data={username:username||'',action,details:details||message,ip:ip||'',fingerprint:fp||'',message,timestamp:Date.now()};
    await unifiedDb.ref('activity_logs').push({data:encryptAtRest(data,process.env.ADMIN_KEY)});
  } catch {}
}

async function securityAction(req,res,action) {
  const ip=unifiedIP(req), fp=unifiedFP(req);
  if (action==='key') return res.status(200).json({publicKey:getTransportPublicKey()});
  if (action==='cek-maintece' || action==='cek-maintenance') {
    const m=await unifiedMaintenance(); await unifiedLog('', 'cek maintenance', ip, fp); return res.status(200).json(m);
  }
  if (action==='cek-block') {
    const blocked=await unifiedBlocked(ip,fp); await unifiedLog('', 'cek block', ip, fp, blocked?'IP/FP terblokir':'IP/FP tidak terblokir');
    return res.status(200).json({blocked});
  }
  if (action==='cek-reset') {
    const username=String(req.body?.username||req.query.username||'').trim();
    const quota=await unifiedQuota(ip,fp); let resetCount=0;
    if (username) {
      const snap=await unifiedDb.ref('users').once('value');
      for (const id of Object.keys(snap.val()||{})) { const u=unifiedDecryptStored(snap.val()[id]); if(u.username===username){resetCount=Number(u.resetCount||u.reset_count||0);break;} }
    }
    await unifiedLog(username,'cek reset quota',ip,fp,`Reset akun: ${resetCount}, sisa kuota: ${quota.remaining}/${quota.max}`);
    return res.status(200).json({success:true,username,resetCount,quota});
  }
  return null;
}

function createRevanstoreHandler() {

const ADMIN_KEY = process.env.ADMIN_KEY;
if (!ADMIN_KEY || ADMIN_KEY.length < 32) throw new Error('ADMIN_KEY wajib di-set dan minimal 32 karakter');
const RECAPTCHA_V2_SECRET_KEY = process.env.RECAPTCHA_V2_SECRET_KEY;
const RECAPTCHA_V3_SECRET_KEY = process.env.RECAPTCHA_V3_SECRET_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET wajib di-set dan minimal 32 karakter');
const SALT_ROUNDS = 12;

if (!admin.apps.length) {
  const key = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
  admin.initializeApp({
    credential: admin.credential.cert({ projectId: process.env.FIREBASE_PROJECT_ID, clientEmail: process.env.FIREBASE_CLIENT_EMAIL, privateKey: key }),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
}

const db = admin.database();
const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW = 60000;
const TRX_MAX_AGE = 172800000;

function checkRateLimit(ip) {
  const now = Date.now();
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const requests = rateLimitMap.get(ip).filter(t => now - t < RATE_LIMIT_WINDOW);
  if (requests.length >= RATE_LIMIT_MAX) return false;
  requests.push(now);
  rateLimitMap.set(ip, requests);
  return true;
}

function encryptResponse(data) { return data || {}; }
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(part => { const i=part.indexOf('='); if(i>0) out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim()); });
  return out;
}
function createSession(user) {
  const payload=Buffer.from(JSON.stringify({uid:user.id,username:user.username,role:user.role||'Operator',iat:Date.now(),exp:Date.now()+28800000})).toString('base64url');
  const sig=crypto.createHmac('sha256',SESSION_SECRET).update(payload).digest('base64url');
  return payload+'.'+sig;
}
function verifySession(req) {
  const token=parseCookies(req).__Host_session; if(!token) return null; const parts=token.split('.'); if(parts.length!==2) return null;
  const expected=crypto.createHmac('sha256',SESSION_SECRET).update(parts[0]).digest('base64url');
  const a=Buffer.from(parts[1]), b=Buffer.from(expected); if(a.length!==b.length || !crypto.timingSafeEqual(a,b)) return null;
  try { const data=JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8')); return data.exp>Date.now()?data:null; } catch { return null; }
}
function setSessionCookie(res, token) { res.setHeader('Set-Cookie', `__Host_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`); }
function clearSessionCookie(res) { res.setHeader('Set-Cookie','__Host_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'); }
function sameOrigin(req) { const origin=req.headers.origin; if(!origin) return true; const allowed=(process.env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean); return allowed.includes(origin); }
function requireSession(req,res) { const session=verifySession(req); if(!session){res.status(401).json({error:'Sesi tidak valid atau sudah berakhir'}); return null;} return session; }

async function decryptData(raw) {
  if (!raw) return raw;
  if (raw.data) {
    try {
      const dec = JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {});
      return JSON.parse(dec);
    } catch(e) { return raw; }
  }
  return raw;
}

async function hashPassword(password) {
  try {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (e) {
    console.error('Error hashing password:', e);
    return null;
  }
}

async function verifyPassword(password, hash) {
  try {
    return await bcrypt.compare(password, hash);
  } catch (e) {
    console.error('Error verifying password:', e);
    return false;
  }
}

async function verifyRecaptchaV2(token) {
  if (!token || !RECAPTCHA_V2_SECRET_KEY) return false;
  try {
    const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${RECAPTCHA_V2_SECRET_KEY}&response=${token}`
    });
    const data = await res.json();
    return data.success === true;
  } catch (e) { return false; }
}

async function verifyRecaptchaV3(token, action) {
  if (!token || !RECAPTCHA_V3_SECRET_KEY) return false;
  try {
    const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${RECAPTCHA_V3_SECRET_KEY}&response=${token}`
    });
    const data = await res.json();
    if (data.success && data.score >= 0.5 && (!action || data.action === action)) return true;
    return false;
  } catch (e) { return false; }
}

async function isIPBlocked(ip) {
  if (!ip) return false;
  const snap = await db.ref('blocked_ips/' + ip.replace(/\./g, '_')).once('value');
  const raw = snap.val();
  if (raw?.data) {
    try {
      const dec = JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {});
      if (JSON.parse(dec)?.blocked) return true;
    } catch(e) {}
  }
  return false;
}

async function isFPBlocked(fp) {
  if (!fp) return false;
  const snap = await db.ref('blocked_fp/' + fp).once('value');
  const raw = snap.val();
  if (raw?.data) {
    try {
      const dec = JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {});
      if (JSON.parse(dec)?.blocked) return true;
    } catch(e) {}
  }
  return false;
}

async function blockIP(ip) {
  if (!ip) return;
  const enc = encryptAtRest({ ip, blocked: true, blocked_at: new Date().toISOString() }, ADMIN_KEY);
  await db.ref('blocked_ips/' + ip.replace(/\./g, '_')).set({ data: enc });
}

async function blockFP(fp) {
  if (!fp) return;
  const enc = encryptAtRest({ fingerprint: fp, blocked: true, blocked_at: new Date().toISOString() }, ADMIN_KEY);
  await db.ref('blocked_fp/' + fp).set({ data: enc });
}

async function trackLoginAttempt(ip, fp) {
  const key = ip.replace(/\./g, '_') + '_' + (fp || 'nofp');
  const ref = db.ref('login_attempts/' + key);
  const snap = await ref.once('value');
  const raw = snap.val();
  const now = Date.now();
  
  if (raw?.data) {
    try {
      const data = JSON.parse(JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {}));
      if (now - (data.last_attempt || 0) > 3600000) {
        await ref.remove();
        const enc = encryptAtRest({ count: 1, last_attempt: now, fingerprint: fp }, ADMIN_KEY);
        await ref.set({ data: enc });
        return 1;
      }
      const newCount = (data.count || 0) + 1;
      const enc = encryptAtRest({ count: newCount, last_attempt: now, fingerprint: fp }, ADMIN_KEY);
      await ref.set({ data: enc });
      return newCount;
    } catch(e) {}
  }
  
  const enc = encryptAtRest({ count: 1, last_attempt: now, fingerprint: fp }, ADMIN_KEY);
  await ref.set({ data: enc });
  return 1;
}

async function resetLoginAttempt(ip, fp) {
  await db.ref('login_attempts/' + ip.replace(/\./g, '_') + '_' + (fp || 'nofp')).remove();
}

async function logActivity(username, action, details, ip, fp) {
  try {
    const enc = encryptAtRest({ username, action, details: details || '', ip: ip || '', fingerprint: fp || '', timestamp: Date.now() }, ADMIN_KEY);
    const newRef = db.ref('activity_logs').push();
    await newRef.set({ data: enc });
  } catch(e) {}
}

function sanitizeKey(str) {
  return String(str || '').replace(/[.#$\[\]\/]/g, '_');
}

async function checkTransactionRateLimit(operator) {
  const key = 'trx_rate_' + sanitizeKey(operator || 'anon');
  const ref = db.ref('transaction_rate_limits/' + key);
  const snap = await ref.once('value');
  const raw = snap.val();
  const now = Date.now();
  let timestamps = [];
  if (raw?.data) {
    try {
      const dec = JSON.parse(JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {}));
      timestamps = dec.timestamps || [];
    } catch(e) {}
  }
  timestamps = timestamps.filter(t => now - t < 60000);
  if (timestamps.length >= 5) return false;
  timestamps.push(now);
  const enc = encryptAtRest({ timestamps }, ADMIN_KEY);
  await ref.set({ data: enc });
  return true;
}

async function cleanupOldTransactions() {
  try {
    const snap = await db.ref('transactions').once('value');
    const raw = snap.val();
    if (!raw) return;
    const now = Date.now();
    const updates = {};
    for (const key in raw) {
      const decrypted = await decryptData(raw[key]);
      if (decrypted && decrypted.timestamp && (now - decrypted.timestamp > TRX_MAX_AGE)) {
        updates[key] = null;
      }
    }
    if (Object.keys(updates).length > 0) {
      await db.ref('transactions').update(updates);
    }
  } catch(e) {}
}

async function getUserTrxCode(username) {
  const safeUsername = sanitizeKey(username);
  const codeRef = db.ref('user_trx_codes/' + safeUsername);
  const snap = await codeRef.once('value');
  const raw = snap.val();
  if (raw?.data) {
    try {
      const dec = JSON.parse(JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {}));
      if (dec && dec.code) return dec.code;
    } catch(e) {}
  }
  const allCodesSnap = await db.ref('user_trx_codes').once('value');
  const allCodes = allCodesSnap.val() || {};
  const usedCodes = new Set();
  for (const k in allCodes) {
    try {
      const dec = (decryptAtRest(allCodes[k].data, ADMIN_KEY) || JSON.parse(CryptoJS.AES.decrypt(allCodes[k].data, ADMIN_KEY).toString(CryptoJS.enc.Utf8)));
      if (dec && dec.code) usedCodes.add(dec.code);
    } catch(e) {}
  }
  let code;
  do {
    code = String(Math.floor(1000 + Math.random() * 9000));
  } while (usedCodes.has(code));
  const enc = encryptAtRest({ code, username, createdAt: Date.now() }, ADMIN_KEY);
  await codeRef.set({ data: enc });
  return code;
}

async function countUserTransactions(username, transactionsRaw) {
  let count = 0;
  if (transactionsRaw) {
    for (const key in transactionsRaw) {
      const d = await decryptData(transactionsRaw[key]);
      if (d && d.operator === username) count++;
    }
  }
  return count;
}

async function handler(req, res) {
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control','no-store');
  if (!sameOrigin(req)) return res.status(403).json({error:'Origin tidak diizinkan'});
  const allowedOrigins=(process.env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean);
  const origin=req.headers.origin;
  if(origin && allowedOrigins.includes(origin)){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Access-Control-Allow-Credentials','true');res.setHeader('Vary','Origin');}
  res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, X-Fingerprint');
  if(req.method==='OPTIONS') return res.status(204).end();
  if(req.method!=='POST') return res.status(405).json({error:'Method not allowed'});
  const ip = req.headers['x-forwarded-for'] || 'unknown';
  const fp = req.headers['x-fingerprint'] || '';
  
  let operator = '';
  try {
    const encryptedOperator = req.headers['x-operator'] || '';
    if (encryptedOperator) operator = CryptoJS.AES.decrypt(encryptedOperator, ADMIN_KEY).toString(CryptoJS.enc.Utf8);
  } catch(e) {}
  
  if (!checkRateLimit(ip)) return res.status(429).json({ error: 'Terlalu banyak request. Coba lagi nanti.' });

  try {
    let path, method, data;
    if (req.body?.path) { path=req.body.path; method=req.body.method||'GET'; data=req.body.data; }
    else return res.status(400).json({error:'Permintaan tidak valid'});

    if (!path || typeof path !== 'string' || path.length > 200) return res.status(400).json({ error: 'Path tidak valid' });
    
    const ref = db.ref(path);

    if (path === 'check_blocked' && (method === 'POST' || method === 'GET')) {
      // Status block adalah keputusan server berdasarkan Firebase.
      // Jangan gunakan reCAPTCHA/localStorage sebagai sumber status block.
      const ipBlocked = await isIPBlocked(ip);
      const fpBlocked = fp ? await isFPBlocked(fp) : false;
      return res.status(200).json(encryptResponse({
        blocked: ipBlocked || fpBlocked,
        blockType: ipBlocked ? 'ip' : (fpBlocked ? 'device' : null),
        ipBlocked,
        fpBlocked
      }));
    }

    if (path === 'maintenance_status') {
      if (method === 'GET') {
        const snap = await ref.once('value');
        const raw = snap.val();
        const result = raw ? await decryptData(raw) : {};
        return res.status(200).json(encryptResponse(result || {}));
      }
      if (method === 'PUT') {
        const enc = encryptAtRest(data, ADMIN_KEY);
        await ref.set({ data: enc });
        return res.status(200).json(encryptResponse({ success: true }));
      }
    }

    if (path === 'logout' && method === 'POST') { clearSessionCookie(res); return res.status(200).json({success:true}); }

    if (path === 'check_account_status' && method === 'POST') {
      const session = requireSession(req, res); if (!session) return;
      const captchaToken = data?.captchaToken || '';
      const captchaValid = await verifyRecaptchaV3(captchaToken, 'check_session');
      if (!captchaValid) {
        return res.status(200).json(encryptResponse({ banAkses: true, banAksesUntil: 0, message: 'Verifikasi reCAPTCHA gagal.' }));
      }
      const username = session.username;
      const user_id = session.uid;

      const ipBlocked = await isIPBlocked(ip);
      const fpBlocked = fp ? await isFPBlocked(fp) : false;
      if (ipBlocked || fpBlocked) {
        return res.status(200).json(encryptResponse({ blocked: true, message: 'IP atau fingerprint perangkat ini diblokir.' }));
      }
      const maintenance = await checkMaintenance();
      if (maintenance) {
        return res.status(200).json(encryptResponse({ maintenance: true, title: maintenance.title, message: maintenance.message, until: maintenance.until }));
      }
      
      const snap = await db.ref('users/' + user_id).once('value');
      const raw = snap.val();
      const user = await decryptData(raw);
      
      if (!user || user.username !== username) {
        return res.status(200).json(encryptResponse({ valid: false, message: 'Sesi tidak valid' }));
      }

      if (user.banned === true) {
        return res.status(200).json(encryptResponse({ banned: true, bannedUntil: user.bannedUntil || 0 }));
      }

      if (user.banAkses === true) {
        if (user.banAksesUntil && user.banAksesUntil !== 0 && user.banAksesUntil < Date.now()) {
          const updatedData = { ...user, banAkses: false, banAksesUntil: 0 };
          const enc = encryptAtRest(updatedData, ADMIN_KEY);
          await db.ref('users/' + user_id).update({ data: enc });
        } else {
          return res.status(200).json(encryptResponse({ banAkses: true, banAksesUntil: user.banAksesUntil || 0 }));
        }
      }

      if (user.forceLogout === true) {
        return res.status(200).json(encryptResponse({ forceLogout: true }));
      }

      if (user.expiry_date) {
        const expiry = new Date(user.expiry_date).getTime();
        if (Number.isFinite(expiry) && expiry <= Date.now()) {
          return res.status(200).json(encryptResponse({ expired: true, valid: false, user: { id: user_id, username: user.username, role: user.role || 'Operator', full_name: user.full_name || user.username, expiry_date: user.expiry_date } }));
        }
      }

      return res.status(200).json(encryptResponse({ valid: true, user: { id: user_id, username: user.username, role: user.role || 'Operator', full_name: user.full_name || user.username, expiry_date: user.expiry_date || '' } }));
    }

    if (path === 'access_key' && method === 'GET') {
      const snap = await ref.once('value');
      const raw = snap.val();
      let result = { key: '' };
      if (raw && raw.data) {
        try {
          const dec = JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {});
          result = JSON.parse(dec);
        } catch (e) {}
      }
      return res.status(200).json(encryptResponse(result));
    }

    if (path === 'admin/auth' && method === 'GET') {
      const ipBlocked = await isIPBlocked(ip);
      const fpBlocked = fp ? await isFPBlocked(fp) : false;
      if (ipBlocked || fpBlocked) {
        return res.status(200).json(encryptResponse({ blocked: true }));
      }
      const snap = await ref.once('value');
      const raw = snap.val();
      let result = {};
      if (raw && raw.data) {
        try {
          const dec = JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {});
          result = JSON.parse(dec);
        } catch (e) {}
      }
      return res.status(200).json(encryptResponse(result));
    }

    if (path === 'register' && method === 'POST') {
      const captchaToken = data?.captchaToken || '';
      const captchaValid = await verifyRecaptchaV2(captchaToken);
      if (!captchaValid) {
        return res.status(200).json(encryptResponse({ success: false, error: 'invalid_captcha', message: 'reCAPTCHA tidak valid!' }));
      }

      const username = data?.username || '';
      const email = data?.email || '';
      const userIP = ip;
      const userFP = fp;

      const ipKey = 'register_ip_' + userIP.replace(/\./g, '_');
      const ipRef = db.ref('register_limits/' + ipKey);
      const ipSnap = await ipRef.once('value');
      const ipRaw = ipSnap.val();
      if (ipRaw?.data) {
        try {
          const ipData = (decryptAtRest(ipRaw.data, ADMIN_KEY) || JSON.parse(CryptoJS.AES.decrypt(ipRaw.data, ADMIN_KEY).toString(CryptoJS.enc.Utf8)));
          if (Date.now() - (ipData.lastRegister || 0) < 86400000) {
            return res.status(200).json(encryptResponse({ success: false, error: 'ip_limit', message: 'IP sudah mendaftar hari ini.' }));
          }
        } catch(e) {}
      }

      if (userFP) {
        const fpKey = 'register_fp_' + userFP;
        const fpRef = db.ref('register_limits/' + fpKey);
        const fpSnap = await fpRef.once('value');
        const fpRaw = fpSnap.val();
        if (fpRaw?.data) {
          try {
            const fpData = (decryptAtRest(fpRaw.data, ADMIN_KEY) || JSON.parse(CryptoJS.AES.decrypt(fpRaw.data, ADMIN_KEY).toString(CryptoJS.enc.Utf8)));
            if (Date.now() - (fpData.lastRegister || 0) < 86400000) {
              return res.status(200).json(encryptResponse({ success: false, error: 'fp_limit', message: 'Perangkat sudah mendaftar hari ini.' }));
            }
          } catch(e) {}
        }
      }

      const usersSnap = await db.ref('users').once('value');
      const users = usersSnap.val();
      if (users) {
        for (const key in users) {
          const userData = await decryptData(users[key]);
          if (userData && userData.username === username) {
            return res.status(200).json(encryptResponse({ success: false, error: 'username_exists', message: 'Username sudah terdaftar!' }));
          }
          if (userData && email && userData.email === email) {
            return res.status(200).json(encryptResponse({ success: false, error: 'email_exists', message: 'Email sudah terdaftar!' }));
          }
        }
      }

      const hashedPassword = await hashPassword(data?.password || '');
      if (!hashedPassword) {
        return res.status(200).json(encryptResponse({ success: false, error: 'server_error', message: 'Gagal memproses password.' }));
      }

      const registerData = {
        ...data,
        password_hash: hashedPassword,
        password: undefined,
        status: 'pending',
        isActive: false,
        needsActivation: true,
        activationStatus: 'pending',
        role: 'User',
        createdAt: Date.now()
      };
      delete registerData.password;

      const enc = encryptData(registerData);
      const newRef = db.ref('users').push();
      await newRef.set({ data: enc });

      await ipRef.set({ data: encryptAtRest({ lastRegister: Date.now() }, ADMIN_KEY) });
      if (userFP) {
        await db.ref('register_limits/register_fp_' + userFP).set({ data: encryptAtRest({ lastRegister: Date.now() }, ADMIN_KEY) });
      }

      await logActivity(username, 'register', 'Pendaftaran baru - ' + (data?.paket || 'Trial'), userIP, userFP);
      return res.status(200).json(encryptResponse({ success: true, message: 'Pendaftaran berhasil! Tunggu aktivasi admin.' }));
    }

    if (path === 'login' && method === 'POST') {
      const captchaToken = data?.captchaToken || '';
      const captchaValid = await verifyRecaptchaV2(captchaToken);
      if (!captchaValid) {
        return res.status(200).json(encryptResponse({ blocked: true, message: 'Verifikasi reCAPTCHA gagal.' }));
      }

      if (await isIPBlocked(ip) || (fp && await isFPBlocked(fp))) {
        return res.status(200).json(encryptResponse({ blocked: true, message: 'IP atau Fingerprint diblokir.' }));
      }

      const snap = await db.ref('users').once('value');
      const users = snap.val();
      if (!users) return res.status(200).json(encryptResponse({ success: false }));

      const username = data.username;
      const password = data.password;
      const currentIP = ip;
      const currentFP = fp;

      for (const key in users) {
        const decryptedUser = await decryptData(users[key]);
        
        if (decryptedUser && decryptedUser.username === username) {
          const isPasswordValid = await verifyPassword(password, decryptedUser.password_hash);
          
          if (!isPasswordValid) {
            continue;
          }

          if (decryptedUser.activationStatus === 'pending') {
            return res.status(200).json(encryptResponse({ success: false, error: 'pending_activation', message: 'Akun belum diaktivasi oleh admin.' }));
          }
          if (decryptedUser.activationStatus === 'rejected') {
            return res.status(200).json(encryptResponse({ success: false, error: 'rejected', message: 'Akun ditolak oleh admin.' }));
          }

          if (decryptedUser.banned === true) {
            await logActivity(username, 'login_blocked_banned', 'Login ditolak - akun dibanned', currentIP, currentFP);
            return res.status(200).json(encryptResponse({
              success: false, banned: true, bannedUntil: decryptedUser.bannedUntil || 0,
              message: 'Akun Anda telah dibanned oleh admin.'
            }));
          }

          if (decryptedUser.banAkses === true) {
            if (decryptedUser.banAksesUntil && decryptedUser.banAksesUntil !== 0 && decryptedUser.banAksesUntil < Date.now()) {
              const updatedData = { ...decryptedUser, banAkses: false, banAksesUntil: 0 };
              const enc = encryptAtRest(updatedData, ADMIN_KEY);
              await db.ref('users/' + key).update({ data: enc });
            } else {
              await logActivity(username, 'login_blocked_banakses', 'Login ditolak - ban akses', currentIP, currentFP);
              return res.status(200).json(encryptResponse({
                success: false, banAkses: true, banAksesUntil: decryptedUser.banAksesUntil || 0,
                message: 'Akses Anda diblokir oleh admin.'
              }));
            }
          }

          if (decryptedUser.forceLogout === true) {
            await logActivity(username, 'login_blocked_force', 'Login ditolak - ditangguhkan', currentIP, currentFP);
            return res.status(200).json(encryptResponse({
              success: false, forceLogout: true,
              message: 'Akun Anda ditangguhkan karena indikasi sharing akun.'
            }));
          }

          const prevIP = decryptedUser.ip || '';
          const prevFP = decryptedUser.fingerprint || '';
          const ipChanged = prevIP && currentIP && prevIP !== currentIP;
          const fpChanged = prevFP && currentFP && prevFP !== currentFP;

          if (ipChanged && fpChanged) {
            const updatedData = { ...decryptedUser, forceLogout: true };
            const enc = encryptAtRest(updatedData, ADMIN_KEY);
            await db.ref('users/' + key).update({ data: enc });
            await logActivity(username, 'sharing_detected', 'IP & FP berbeda! Auto force logout.', currentIP, currentFP);
            return res.status(200).json(encryptResponse({
              success: false, forceLogout: true,
              message: 'Akun ditangguhkan karena terdeteksi sharing. Hubungi admin.'
            }));
          }

          const ipHistory = decryptedUser.ipHistory || [];
          if (currentIP && (!ipHistory.length || ipHistory[ipHistory.length - 1] !== currentIP)) {
            ipHistory.push(currentIP);
            if (ipHistory.length > 10) ipHistory.shift();
          }

          const fpHistory = decryptedUser.fpHistory || [];
          if (currentFP && (!fpHistory.length || fpHistory[fpHistory.length - 1] !== currentFP)) {
            fpHistory.push(currentFP);
            if (fpHistory.length > 10) fpHistory.shift();
          }

          const updatedData = {
            ...decryptedUser, ip: currentIP, fingerprint: currentFP, ipHistory, fpHistory,
            lastLogin: { ip: currentIP, fingerprint: currentFP, timestamp: Date.now() }
          };

          const enc = encryptAtRest(updatedData, ADMIN_KEY);
          await db.ref('users/' + key).update({ data: enc });
          await resetLoginAttempt(ip, fp);
          await logActivity(username, 'login_success', 'Login berhasil', currentIP, currentFP);

          setSessionCookie(res, createSession({ id: key, username: decryptedUser.username, role: decryptedUser.role || 'Operator' }));
          return res.status(200).json(encryptResponse({
            success: true,
            data: {
              id: key, username: decryptedUser.username, role: decryptedUser.role || 'Operator',
              full_name: decryptedUser.full_name || decryptedUser.username, expiry_date: decryptedUser.expiry_date || '',
              ip: currentIP, fingerprint: currentFP
            }
          }));
        }
      }

      await logActivity(username, 'login_failed', 'Password salah', currentIP, currentFP);
      return res.status(200).json(encryptResponse({ success: false }));
    }

    if (path === 'login_failed' && method === 'POST') {
      const attempts = await trackLoginAttempt(ip, fp);
      await new Promise(r => setTimeout(r, Math.min(attempts * 500, 3000)));
      if (attempts >= 5) {
        await blockIP(ip);
        if (fp) await blockFP(fp);
        return res.status(200).json(encryptResponse({ blocked: true }));
      }
      return res.status(200).json(encryptResponse({ attempts, remaining: 5 - attempts }));
    }

    if (path === 'login_success' && method === 'POST') {
      await resetLoginAttempt(ip, fp);
      return res.status(200).json(encryptResponse({ success: true }));
    }

    if (path === 'block_ip_manual' && method === 'POST') {
      await blockIP(data.ip);
      await logActivity('admin', 'block_ip', 'IP ' + data.ip + ' diblokir', ip, fp);
      return res.status(200).json(encryptResponse({ success: true }));
    }

    if (path === 'block_fp_manual' && method === 'POST') {
      await blockFP(data.fp);
      await logActivity('admin', 'block_fp', 'FP diblokir', ip, fp);
      return res.status(200).json(encryptResponse({ success: true }));
    }

    if (path === 'transactions' && method === 'POST') {
      const session = requireSession(req, res); if (!session) return;
      const trxUsername = session.username;
      const rateOk = await checkTransactionRateLimit(trxUsername || ip);
      if (!rateOk) {
        return res.status(200).json(encryptResponse({ success: false, error: 'rate_limit_trx', message: 'Terlalu banyak transaksi, tunggu sebentar sebelum transaksi lagi.' }));
      }
      await cleanupOldTransactions();
      const code = await getUserTrxCode(trxUsername || 'unknown');
      const existingSnap = await db.ref('transactions').once('value');
      const existingCount = await countUserTransactions(trxUsername || 'unknown', existingSnap.val());
      const seq = existingCount + 1;
      const trxId = code + '-' + String(seq).padStart(3, '0');
      const trxData = { ...data, trxId };
      const enc = encryptData(trxData);
      const r = db.ref('transactions').push();
      await r.set({ data: enc });
      return res.status(200).json(encryptResponse({ success: true, id: r.key, trxId }));
    }

    if (path === 'transactions' && method === 'GET') {
      const session = requireSession(req, res); if (!session) return;
      await cleanupOldTransactions();
      const trxUsername = session.username;
      const snap = await db.ref('transactions').once('value');
      const raw = snap.val();
      const result = {};
      if (raw) {
        for (const key in raw) {
          const d = await decryptData(raw[key]);
          if (d && (!trxUsername || d.operator === trxUsername)) result[key] = d;
        }
      }
      return res.status(200).json(encryptResponse(result));
    }

    if (path === 'transactions' && method === 'DELETE') {
      const session = requireSession(req, res); if (!session) return;
      const trxUsername = session.username;
      const snap = await db.ref('transactions').once('value');
      const raw = snap.val();
      if (raw) {
        const updates = {};
        for (const key in raw) {
          const d = await decryptData(raw[key]);
          if (d && d.operator === trxUsername) updates[key] = null;
        }
        if (Object.keys(updates).length > 0) await db.ref('transactions').update(updates);
      }
      return res.status(200).json(encryptResponse({ success: true }));
    }

    return res.status(404).json({ error: 'Endpoint tidak ditemukan' });
  } catch (error) {
    return res.status(500).json(encryptResponse({ error: 'Terjadi kesalahan pada server.' }));
  }
}

function encryptData(data) {
  return encryptAtRest(data, ADMIN_KEY);
}

  return handler;
}

function createRegisterHandler() {

// ==================== ENV & INIT ====================
const ADMIN_KEY = process.env.ADMIN_KEY;
if (!ADMIN_KEY || ADMIN_KEY.length < 32) throw new Error('ADMIN_KEY wajib di-set dan minimal 32 karakter');
if (!ADMIN_KEY) {
    throw new Error('ADMIN_KEY is required!');
}

const RECAPTCHA_V2_SECRET_KEY = process.env.RECAPTCHA_V2_SECRET_KEY || '';
const SALT_ROUNDS = 12;
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW = 60000;

if (!admin.apps.length) {
    const key = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
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

// ==================== CRYPTO HELPERS ====================
function encryptResponse(data) { return data || {}; }

function encryptData(data) {
    return encryptAtRest(data, ADMIN_KEY);
}

function decryptPayload(raw) {
    if (!raw) return null;
    try {
        const dec = '';
        if (!dec) return null;
        return JSON.parse(dec);
    } catch (e) {
        return null;
    }
}

function decryptData(raw) {
    if (!raw) return raw;
    try {
        if (typeof raw === 'string') {
            const dec = decryptAtRest(raw, ADMIN_KEY);
            return dec === null ? raw : dec;
        }
        if (raw.data) {
            const dec = decryptAtRest(raw.data, ADMIN_KEY);
            return dec === null ? raw : dec;
        }
        return raw;
    } catch (e) {
        return raw;
    }
}

// ==================== SANITASI & FIREBASE KEY SAFETY ====================
function sanitizeInput(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/`/g, '&#96;')
        .replace(/=/g, '&#61;')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '');
}

// Firebase Realtime Database MENOLAK key yang mengandung ".", "#", "$", "[", "]".
// Semua tempat yang butuh IP/fingerprint sebagai bagian dari path WAJIB lewat
// fungsi ini dulu, supaya gak ada lagi bug "invalid path" seperti sebelumnya.
function escapeFirebaseKey(str) {
    if (!str) return '';
    return String(str).replace(/[.#$\[\]]/g, '_');
}

// ==================== PASSWORD ====================
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    return await bcrypt.hash(password, salt);
}

// ==================== RATE LIMIT ====================
async function checkRateLimit(ip) {
    try {
        const key = escapeFirebaseKey(ip);
        const ref = db.ref('rate_limits_register/' + key);
        const snap = await ref.once('value');
        const raw = snap.val();
        const now = Date.now();

        if (raw && raw.data) {
            const data = decryptData(raw.data);
            if (data && now - (data.timestamp || 0) < RATE_LIMIT_WINDOW) {
                if ((data.count || 0) >= RATE_LIMIT_MAX) return false;
                data.count = (data.count || 0) + 1;
                await ref.set({ data: encryptData(data) });
                return true;
            }
        }

        await ref.set({ data: encryptData({ count: 1, timestamp: now }) });
        return true;
    } catch (e) {
        // Kalau Firebase lagi bermasalah, jangan sampai orang gak bisa daftar
        // gara-gara rate limiter error - biarkan lewat, lebih aman daripada
        // seluruh sistem down.
        console.error('checkRateLimit error:', e.message);
        return true;
    }
}

// ==================== RECAPTCHA ====================
async function verifyRecaptcha(token) {
    if (!token) return false;
    // Kalau secret key belum dikonfigurasi di server, verifikasi di-skip
    // (dianggap valid) - bukan langsung gagal.
    if (!RECAPTCHA_V2_SECRET_KEY) return true;

    try {
        const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${RECAPTCHA_V2_SECRET_KEY}&response=${token}`
        });
        const data = await res.json();
        return data.success === true;
    } catch (e) {
        console.error('verifyRecaptcha error:', e.message);
        return false;
    }
}

// ==================== CLIENT IP ====================
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        const ips = forwarded.split(',');
        return ips[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
}

// ==================== CEK MAINTENANCE & BLOCK ====================
// Semua fungsi di bawah ini SELALU resolve dengan aman (gak pernah throw),
// supaya kalau ada masalah baca Firebase, register tetap bisa lanjut jalan
// bukannya langsung 500.
async function isIPBlocked(ip) {
    if (!ip || ip === 'unknown' || ip === '::1' || ip === '127.0.0.1') return false;
    try {
        const key = escapeFirebaseKey(ip);
        const snap = await db.ref('blocked_ips/' + key).once('value');
        const raw = snap.val();
        if (raw) {
            const data = decryptData(raw);
            if (data && data.blocked === true) return true;
        }
        return false;
    } catch (e) {
        console.error('isIPBlocked error:', e.message);
        return false;
    }
}

async function isFPBlocked(fp) {
    if (!fp) return false;
    try {
        const key = escapeFirebaseKey(fp);
        const snap = await db.ref('blocked_fp/' + key).once('value');
        const raw = snap.val();
        if (raw) {
            const data = decryptData(raw);
            if (data && data.blocked === true) return true;
        }
        return false;
    } catch (e) {
        console.error('isFPBlocked error:', e.message);
        return false;
    }
}

async function checkMaintenance() {
    try {
        const snap = await db.ref('maintenance_status').once('value');
        const raw = snap.val();
        if (raw) {
            const data = decryptData(raw);
            if (data && data.maintenance === true) {
                return {
                    maintenance: true,
                    title: data.title || 'SEDANG PERBAIKAN SISTEM',
                    message: data.message || 'Website sedang dalam perbaikan oleh admin. Silakan kembali beberapa saat lagi.',
                    until: data.until || null
                };
            }
        }
        return null;
    } catch (e) {
        console.error('checkMaintenance error:', e.message);
        return null;
    }
}

// ==================== LOG AKTIVITAS UNTUK PANEL ADMIN ====================
async function logActivity(username, action, details, ip, fp) {
    try {
        const enc = encryptData({
            username: username,
            action: action,
            details: details || '',
            ip: ip || '',
            fingerprint: fp || '',
            timestamp: Date.now()
        });
        const newRef = db.ref('activity_logs').push();
        await newRef.set({ data: enc });
    } catch (e) {
        // Log gagal bukan alasan buat gagalin registrasi
        console.error('logActivity error:', e.message);
    }
}

// ==================== VALIDASI USERNAME ====================
function isValidUsername(username) {
    if (!username || typeof username !== 'string') {
        return { valid: false, message: 'Username tidak valid!' };
    }

    const trimmed = username.trim();
    if (trimmed.length < 3) {
        return { valid: false, message: 'Username minimal 3 karakter!' };
    }

    if (trimmed.length > 30) {
        return { valid: false, message: 'Username maksimal 30 karakter!' };
    }

    const usernameRegex = /^[a-zA-Z0-9_.]+$/;
    if (!usernameRegex.test(trimmed)) {
        return { valid: false, message: 'Username hanya boleh huruf, angka, underscore (_), dan titik (.)!' };
    }

    return { valid: true, username: trimmed };
}

// ==================== HANDLER UTAMA ====================
function sameOrigin(req) { const origin=req.headers.origin; if(!origin) return true; const allowed=(process.env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean); return allowed.includes(origin); }

async function handler(req, res) {
    if (!sameOrigin(req)) return res.status(403).json({ error: 'Origin tidak diizinkan' });
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Fingerprint');
    if (!sameOrigin(req)) return res.status(403).json({ error: 'Origin tidak diizinkan' });
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const ip = getClientIP(req);
    const fp = req.headers['x-fingerprint'] || '';

    if (!await checkRateLimit(ip)) {
        return res.status(429).json({ data: encryptResponse({ success: false, error: 'rate_limit', message: 'Terlalu banyak percobaan.' }) });
    }

    try {
        const body = req.body || {};
        if (!body || typeof body !== 'object') {
            return res.status(400).json({ data: encryptResponse({ success: false, error: 'no_data', message: 'Data tidak ditemukan!' }) });
        }

        const decrypted = body;
        if (!decrypted || !decrypted.action) {
            return res.status(403).json({ data: encryptResponse({ success: false, error: 'access_denied', message: 'Akses ditolak!' }) });
        }

        const action = decrypted.action;

        // ---------- CHECK STATUS (maintenance + ban akses) ----------
        if (action === 'check_status') {
            const ipBlocked = await isIPBlocked(ip);
            const fpBlocked = fp ? await isFPBlocked(fp) : false;

            if (ipBlocked || fpBlocked) {
                return res.status(200).json({
                    data: encryptResponse({
                        blocked: true,
                        maintenance: false,
                        message: 'Akses ditolak, jika ingin dibuka silakan hubungi admin.'
                    })
                });
            }

            const maintenance = await checkMaintenance();
            if (maintenance) {
                return res.status(200).json({
                    data: encryptResponse({
                        blocked: false,
                        maintenance: true,
                        title: maintenance.title,
                        message: maintenance.message,
                        until: maintenance.until
                    })
                });
            }

            return res.status(200).json({
                data: encryptResponse({ blocked: false, maintenance: false })
            });
        }

        // ---------- REGISTER ----------
        if (action === 'register') {
            // Ban akses & maintenance dicek DULU sebelum apapun lain,
            // ban akses menang kalau dua-duanya aktif bersamaan.
            const ipBlockedRegister = await isIPBlocked(ip);
            const fpBlockedRegister = fp ? await isFPBlocked(fp) : false;

            if (ipBlockedRegister || fpBlockedRegister) {
                return res.status(200).json({
                    data: encryptResponse({
                        success: false,
                        error: 'access_denied',
                        message: 'Akses ditolak, jika ingin dibuka silakan hubungi admin.'
                    })
                });
            }

            const maintenanceRegister = await checkMaintenance();
            if (maintenanceRegister) {
                return res.status(200).json({
                    data: encryptResponse({
                        success: false,
                        error: 'maintenance',
                        message: maintenanceRegister.message
                    })
                });
            }

            // ---- Validasi username ----
            const rawUsername = decrypted.username || '';
            const usernameValidation = isValidUsername(rawUsername);
            if (!usernameValidation.valid) {
                return res.status(200).json({
                    data: encryptResponse({ success: false, error: 'invalid_username', message: usernameValidation.message })
                });
            }
            const username = usernameValidation.username;

            const password = decrypted.password || '';
            const confirmPassword = decrypted.confirmPassword || '';
            const phone = sanitizeInput(decrypted.phone || '');
            const email = sanitizeInput(decrypted.email || '');
            const paket = sanitizeInput(decrypted.paket || '');
            const harga = decrypted.harga || 0;
            const captchaToken = decrypted.captchaToken || '';
            const userIP = decrypted.ip || ip;
            const userFP = decrypted.fingerprint || fp;
            const sessionFingerprint = decrypted.sessionFingerprint || '';

            // ---- Validasi field lain ----
            if (!password || password.length < 6) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'weak_password', message: 'Password minimal 6 karakter!' }) });
            }
            if (password !== confirmPassword) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'password_mismatch', message: 'Password tidak cocok!' }) });
            }
            if (!phone || phone.length < 10) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'invalid_phone', message: 'Nomor telepon tidak valid!' }) });
            }
            if (!email || !email.includes('@')) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'invalid_email', message: 'Email tidak valid!' }) });
            }
            if (!paket) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'paket_not_selected', message: 'Pilih paket terlebih dahulu!' }) });
            }

            // ---- Captcha ----
            const captchaValid = await verifyRecaptcha(captchaToken);
            if (!captchaValid) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'invalid_captcha', message: 'reCAPTCHA tidak valid!' }) });
            }

            // ---- Limit 1x/hari per IP ----
            try {
                const ipKey = 'register_ip_' + escapeFirebaseKey(userIP);
                const ipRef = db.ref('register_limits/' + ipKey);
                const ipSnap = await ipRef.once('value');
                const ipRaw = ipSnap.val();
                if (ipRaw && ipRaw.data) {
                    const ipData = decryptData(ipRaw.data);
                    if (ipData && Date.now() - (ipData.lastRegister || 0) < 86400000) {
                        return res.status(200).json({ data: encryptResponse({ success: false, error: 'ip_limit', message: 'IP sudah mendaftar hari ini.' }) });
                    }
                }
            } catch (e) {
                console.error('IP limit check error:', e.message);
            }

            // ---- Limit 1x/hari per fingerprint ----
            if (userFP) {
                try {
                    const fpKey = 'register_fp_' + escapeFirebaseKey(userFP);
                    const fpRef = db.ref('register_limits/' + fpKey);
                    const fpSnap = await fpRef.once('value');
                    const fpRaw = fpSnap.val();
                    if (fpRaw && fpRaw.data) {
                        const fpData = decryptData(fpRaw.data);
                        if (fpData && Date.now() - (fpData.lastRegister || 0) < 86400000) {
                            return res.status(200).json({ data: encryptResponse({ success: false, error: 'fp_limit', message: 'Perangkat sudah mendaftar hari ini.' }) });
                        }
                    }
                } catch (e) {
                    console.error('FP limit check error:', e.message);
                }
            }

            // ---- Cek username/email sudah dipakai ----
            const usersSnap = await db.ref('users').once('value');
            const users = usersSnap.val();
            if (users) {
                for (const key in users) {
                    const userData = decryptData(users[key].data);
                    if (userData && userData.username === username) {
                        return res.status(200).json({ data: encryptResponse({ success: false, error: 'username_exists', message: 'Username sudah terdaftar!' }) });
                    }
                    if (userData && email && userData.email === email) {
                        return res.status(200).json({ data: encryptResponse({ success: false, error: 'email_exists', message: 'Email sudah terdaftar!' }) });
                    }
                }
            }

            // ---- Hash password ----
            const hashedPassword = await hashPassword(password);
            if (!hashedPassword) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'server_error', message: 'Gagal memproses password.' }) });
            }

            // ---- Simpan user baru ----
            const registerData = {
                username: username,
                password_hash: hashedPassword,
                phone: phone,
                email: email,
                paket: paket,
                harga: harga,
                ip: userIP,
                fingerprint: userFP,
                sessionFingerprint: sessionFingerprint,
                status: 'pending',
                isActive: false,
                needsActivation: true,
                activationStatus: 'pending',
                role: 'User',
                banned: false,
                banAkses: false,
                forceLogout: false,
                expiry_date: '',
                createdAt: Date.now()
            };

            const enc = encryptData(registerData);
            const newRef = db.ref('users').push();
            await newRef.set({ data: enc });

            // ---- Catat limit harian (gak fatal kalau gagal) ----
            try {
                await db.ref('register_limits/register_ip_' + escapeFirebaseKey(userIP)).set({ data: encryptData({ lastRegister: Date.now() }) });
                if (userFP) {
                    await db.ref('register_limits/register_fp_' + escapeFirebaseKey(userFP)).set({ data: encryptData({ lastRegister: Date.now() }) });
                }
            } catch (e) {
                console.error('Set register limit error:', e.message);
            }

            // ---- Log ke panel admin (gak fatal kalau gagal) ----
            await logActivity(username, 'register', 'Pendaftaran baru - ' + (paket || 'Trial'), userIP, userFP);

            return res.status(200).json({ data: encryptResponse({ success: true, message: 'Pendaftaran berhasil! Tunggu aktivasi admin.' }) });
        }

        return res.status(400).json({ data: encryptResponse({ success: false, error: 'invalid_action', message: 'Aksi tidak valid!' }) });
    } catch (error) {
        console.error('Register error:', error);
        return res.status(500).json({ data: encryptResponse({ success: false, error: 'server_error', message: 'Terjadi kesalahan pada server.' }) });
    }
}

  return handler;
}

function createResetHandler() {

const ADMIN_KEY = process.env.ADMIN_KEY;
if (!ADMIN_KEY || ADMIN_KEY.length < 32) throw new Error('ADMIN_KEY wajib di-set dan minimal 32 karakter');
if (!ADMIN_KEY) {
    throw new Error('ADMIN_KEY is required!');
}

const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RECAPTCHA_V2_SECRET_KEY = process.env.RECAPTCHA_V2_SECRET_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'Web Top Up Bussid <noreply@webtopupbussid.web.id>';
const BASE_URL = process.env.BASE_URL || 'https://tesweb-kohl.vercel.app';

const RESET_TOKEN_EXPIRY = 15 * 60 * 1000;
const SALT_ROUNDS = 12;
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW = 60000;

if (!admin.apps.length) {
    const key = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
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
const RESET_DAILY_MAX = 5;

function safeKey(value) { return String(value || 'unknown').replace(/[.#$\[\]\/]/g, '_'); }
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    return forwarded ? String(forwarded).split(',')[0].trim() : (req.socket.remoteAddress || 'unknown');
}
function todayKey() { return new Date().toISOString().slice(0, 10); }

async function consumeResetQuota(ip, fp) {
    const date = todayKey();
    const root = db.ref('reset_usage_daily');
    let allowed = true;
    await root.transaction(current => {
        current = current && typeof current === 'object' ? current : {};
        const ipKey = 'ip_' + safeKey(ip);
        const fpKey = fp ? 'fp_' + safeKey(fp) : '';
        const ipData = current[ipKey] && current[ipKey].data ? decryptData(current[ipKey].data) : {};
        const fpData = fpKey && current[fpKey] && current[fpKey].data ? decryptData(current[fpKey].data) : {};
        const ipCount = ipData.date === date ? Number(ipData.count || 0) : 0;
        const fpCount = fpData.date === date ? Number(fpData.count || 0) : 0;
        if (ipCount >= RESET_DAILY_MAX || (fp && fpCount >= RESET_DAILY_MAX)) {
            allowed = false;
            return current;
        }
        current[ipKey] = { data: encryptData({ date, count: ipCount + 1 }) };
        if (fpKey) current[fpKey] = { data: encryptData({ date, count: fpCount + 1 }) };
        return current;
    });
    return allowed;
}

async function getResetQuota(ip, fp) {
    const date = todayKey();
    const root = db.ref('reset_usage_daily');
    const [ipSnap, fpSnap] = await Promise.all([
        root.child('ip_' + safeKey(ip)).once('value'),
        fp ? root.child('fp_' + safeKey(fp)).once('value') : Promise.resolve({ val: () => null })
    ]);
    const ipData = ipSnap.val()?.data ? decryptData(ipSnap.val().data) : {};
    const fpRaw = fpSnap.val();
    const fpData = fpRaw?.data ? decryptData(fpRaw.data) : {};
    const ipCount = ipData.date === date ? Number(ipData.count || 0) : 0;
    const fpCount = fpData.date === date ? Number(fpData.count || 0) : 0;
    const used = Math.max(ipCount, fpCount);
    return { used, remaining: Math.max(0, RESET_DAILY_MAX - used), max: RESET_DAILY_MAX, date };
}

async function logActivity(username, action, details, ip, fp) {
    try {
        const message = `ip: ${ip || ''} fp: ${fp || ''} telah ${action}`;
        const enc = encryptData({ username: username || '', action, details: details || message, ip: ip || '', fingerprint: fp || '', message, timestamp: Date.now() });
        await db.ref('activity_logs').push({ data: enc });
    } catch (e) {}
}

function encryptResponse(data) { return data || {}; }

function encryptData(data) {
    return encryptAtRest(data, ADMIN_KEY);
}

function decryptPayload(raw) {
    if (!raw) return null;
    try {
        const dec = '';
        return JSON.parse(dec);
    } catch (e) {
        return null;
    }
}

function decryptData(raw) {
    if (!raw) return raw;
    try {
        const dec = JSON.stringify(decryptAtRest(raw, ADMIN_KEY) || {});
        return JSON.parse(dec);
    } catch (e) { return raw; }
}

function sanitizeInput(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/`/g, '&#96;')
        .replace(/=/g, '&#61;')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .replace(/<script/gi, '')
        .replace(/<\/script/gi, '')
        .replace(/<img/gi, '')
        .replace(/<svg/gi, '')
        .replace(/<iframe/gi, '')
        .replace(/<object/gi, '')
        .replace(/<embed/gi, '')
        .replace(/<link/gi, '')
        .replace(/<meta/gi, '')
        .replace(/<style/gi, '')
        .replace(/expression/gi, '')
        .replace(/eval/gi, '')
        .replace(/alert/gi, '');
}

async function hashPassword(password) {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    return await bcrypt.hash(password, salt);
}

async function checkRateLimit(ip) {
    const key = ip.replace(/\./g, '_');
    const ref = db.ref('rate_limits_reset_pw/' + key);
    const snap = await ref.once('value');
    const raw = snap.val();
    const now = Date.now();
    
    if (raw && raw.data) {
        try {
            const data = decryptData(raw.data);
            if (now - (data.timestamp || 0) < RATE_LIMIT_WINDOW) {
                if ((data.count || 0) >= RATE_LIMIT_MAX) return false;
                data.count = (data.count || 0) + 1;
                await ref.set({ data: encryptData(data) });
                return true;
            }
        } catch (e) {}
    }
    
    await ref.set({ data: encryptData({ count: 1, timestamp: now }) });
    return true;
}

async function verifyRecaptcha(token) {
    if (!token || !RECAPTCHA_V2_SECRET_KEY) return false;
    
    try {
        const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${RECAPTCHA_V2_SECRET_KEY}&response=${token}`
        });
        const data = await res.json();
        return data.success === true;
    } catch (e) {
        return false;
    }
}

function generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
}

async function sendResetEmail(toEmail, username, resetLink) {
    if (!RESEND_API_KEY) {
        console.error('RESEND_API_KEY is not set!');
        return false;
    }
    
    const safeUsername = sanitizeInput(username);
    const safeResetLink = sanitizeInput(resetLink);
    const safeEmail = sanitizeInput(toEmail);
    
    try {
        const response = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + RESEND_API_KEY
            },
            body: JSON.stringify({
                from: EMAIL_FROM,
                to: [safeEmail],
                subject: 'Reset Password Akun Anda',
                html: `
                    <!DOCTYPE html>
                    <html>
                    <head><meta charset="UTF-8"></head>
                    <body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f8fafc;">
                        <div style="max-width:600px;margin:0 auto;padding:20px;">
                            <div style="text-align:center;padding:20px 0;background:#00BFFF;border-radius:16px 16px 0 0;">
                                <h1 style="color:#ffffff;margin:0;font-size:28px;">Web Top Up Bussid</h1>
                                <p style="color:#E6F9FF;font-size:14px;margin:8px 0 0;">Reset Password</p>
                            </div>
                            <div style="background:#ffffff;padding:32px;text-align:center;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;">
                                <p style="color:#475569;font-size:15px;margin-bottom:8px;">Halo <b>${safeUsername}</b>,</p>
                                <p style="color:#475569;font-size:14px;margin-bottom:24px;">Klik tombol di bawah ini untuk mereset password Anda.</p>
                                <a href="${safeResetLink}" style="display:inline-block;background:#00BFFF;color:#ffffff;padding:14px 40px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px;">Reset Password</a>
                                <p style="color:#94a3b8;font-size:12px;margin-top:24px;">Link expired dalam <b>15 menit</b>.<br>Jika Anda tidak meminta reset password, abaikan email ini.</p>
                            </div>
                            <div style="text-align:center;margin-top:20px;color:#94a3b8;font-size:12px;">
                                <p>Email ini dikirim otomatis.</p>
                            </div>
                        </div>
                    </body>
                    </html>
                `
            })
        });
        
        return response.ok;
    } catch (e) {
        console.error('Email error:', e);
        return false;
    }
}

function sameOrigin(req) { const origin=req.headers.origin; if(!origin) return true; const allowed=(process.env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean); return allowed.includes(origin); }

async function handler(req, res) {
    if (!sameOrigin(req)) return res.status(403).json({ error: 'Origin tidak diizinkan' });
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Fingerprint');
    if (!sameOrigin(req)) return res.status(403).json({ error: 'Origin tidak diizinkan' });
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const fp = req.headers['x-fingerprint'] || '';

    if (!await checkRateLimit(ip)) {
        return res.status(429).json({ data: encryptResponse({ success: false, error: 'rate_limit', message: 'Terlalu banyak percobaan. Coba lagi nanti.' }) });
    }

    try {
        const body = req.body || {};
        if (!body || typeof body !== 'object') {
            return res.status(400).json({ data: encryptResponse({ success: false, error: 'no_data', message: 'Data tidak ditemukan!' }) });
        }

        const decrypted = body;
        if (!decrypted || !decrypted.action) {
            return res.status(403).json({ data: encryptResponse({ success: false, error: 'access_denied', message: 'Akses ditolak!' }) });
        }

        const action = decrypted.action;

        // ==================== REQUEST RESET ====================
        if (action === 'request_reset') {
            const username = sanitizeInput(decrypted.username || '');
            const captchaToken = decrypted.captchaToken || '';

            if (!username || username.length < 3) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'invalid_username', message: 'Username minimal 3 karakter!' }) });
            }

            const captchaValid = await verifyRecaptcha(captchaToken);
            if (!captchaValid) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'invalid_captcha', message: 'reCAPTCHA tidak valid! Silakan coba lagi.' }) });
            }

            const usersSnap = await db.ref('users').once('value');
            const users = usersSnap.val();

            if (!users) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'user_not_found', message: 'Username tidak terdaftar!' }) });
            }

            let foundUser = null;
            let userKey = null;

            for (const key in users) {
                const userData = decryptData(users[key].data);
                if (userData && userData.username === username) {
                    foundUser = userData;
                    userKey = key;
                    break;
                }
            }

            if (!foundUser) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'user_not_found', message: 'Username tidak terdaftar! Periksa kembali username Anda.' }) });
            }

            if (!foundUser.email || foundUser.email.trim() === '') {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'email_not_found', message: 'Akun ini tidak memiliki email terdaftar! Hubungi admin.' }) });
            }

            if (foundUser.banned === true) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'account_banned', message: 'Akun Anda dibanned! Hubungi admin.' }) });
            }

            if (foundUser.forceLogout === true) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'account_suspended', message: 'Akun Anda ditangguhkan! Hubungi admin.' }) });
            }

            const quota = await getResetQuota(ip, fp);
            if (quota.remaining <= 0) {
                await logActivity(username, 'reset ditolak', 'Kuota reset harian habis', ip, fp);
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'reset_quota_exhausted', message: 'Kuota reset password hari ini sudah habis (maksimal 5 kali per hari).' }) });
            }

            const resetToken = generateResetToken();
            const resetTokenExpiry = Date.now() + RESET_TOKEN_EXPIRY;

            const updatedData = { ...foundUser, resetToken: resetToken, resetTokenExpiry: resetTokenExpiry };
            await db.ref('users/' + userKey).update({ data: encryptData(updatedData) });

            const resetLink = BASE_URL + '/pages/confirm-password?token=' + resetToken;

            const emailSent = await sendResetEmail(foundUser.email, foundUser.username, resetLink);

            if (!emailSent) {
                await logActivity(username, 'request reset gagal', 'Gagal mengirim email reset', ip, fp);
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'email_error', message: 'Gagal mengirim email! Coba lagi nanti.' }) });
            }
            await logActivity(username, 'request reset', 'Link reset password dikirim', ip, fp);

            const emailParts = foundUser.email.split('@');
            const maskedEmail = emailParts[0].substring(0, 1) + '***@' + emailParts[1];

            return res.status(200).json({ data: encryptResponse({ success: true, maskedEmail: maskedEmail, message: 'Link reset telah dikirim ke email Anda!' }) });
        }

        // ==================== VERIFY TOKEN ====================
        if (action === 'verify_token') {
            const token = sanitizeInput(decrypted.token || '');

            if (!token || token.length < 10) {
                return res.status(200).json({ data: encryptResponse({ valid: false, error: 'token_invalid', message: 'Link tidak valid!' }) });
            }

            const usersSnap = await db.ref('users').once('value');
            const users = usersSnap.val();

            if (!users) {
                return res.status(200).json({ data: encryptResponse({ valid: false, error: 'token_not_found', message: 'Link tidak valid!' }) });
            }

            let foundUser = null;

            for (const key in users) {
                const userData = decryptData(users[key].data);
                if (userData && userData.resetToken === token) {
                    foundUser = userData;
                    break;
                }
            }

            if (!foundUser) {
                return res.status(200).json({ data: encryptResponse({ valid: false, error: 'token_not_found', message: 'Link tidak valid atau sudah digunakan!' }) });
            }

            if (Date.now() > foundUser.resetTokenExpiry) {
                return res.status(200).json({ data: encryptResponse({ valid: false, expired: true, error: 'token_expired', message: 'Link expired!' }) });
            }

            return res.status(200).json({ data: encryptResponse({ valid: true }) });
        }

        // ==================== CONFIRM RESET ====================
        if (action === 'confirm_reset') {
            const token = sanitizeInput(decrypted.token || '');
            const newPassword = decrypted.newPassword || '';
            const captchaToken = decrypted.captchaToken || '';

            if (!token || token.length < 10) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'token_invalid', message: 'Link tidak valid!' }) });
            }

            if (!newPassword || newPassword.length < 6) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'weak_password', message: 'Password minimal 6 karakter!' }) });
            }

            const captchaValid = await verifyRecaptcha(captchaToken);
            if (!captchaValid) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'invalid_captcha', message: 'reCAPTCHA tidak valid!' }) });
            }

            const usersSnap = await db.ref('users').once('value');
            const users = usersSnap.val();

            if (!users) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'token_not_found', message: 'Link tidak valid!' }) });
            }

            let foundUser = null;
            let userKey = null;

            for (const key in users) {
                const userData = decryptData(users[key].data);
                if (userData && userData.resetToken === token) {
                    foundUser = userData;
                    userKey = key;
                    break;
                }
            }

            if (!foundUser) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'token_not_found', message: 'Link tidak valid atau sudah digunakan!' }) });
            }

            if (Date.now() > foundUser.resetTokenExpiry) {
                const cleanedData = { ...foundUser };
                delete cleanedData.resetToken;
                delete cleanedData.resetTokenExpiry;
                await db.ref('users/' + userKey).update({ data: encryptData(cleanedData) });
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'token_expired', message: 'Link expired! Minta link baru.' }) });
            }

            const quotaAllowed = await consumeResetQuota(ip, fp);
            if (!quotaAllowed) {
                await logActivity(foundUser.username, 'reset ditolak', 'Kuota reset harian habis', ip, fp);
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'reset_quota_exhausted', message: 'Kuota reset password hari ini sudah habis (maksimal 5 kali per hari).' }) });
            }

            const hashedPassword = await hashPassword(newPassword);

            const updatedData = { ...foundUser, password_hash: hashedPassword, resetCount: Number(foundUser.resetCount || foundUser.reset_count || 0) + 1, lastReset: { ip, fingerprint: fp, timestamp: Date.now() } };
            delete updatedData.password;
            delete updatedData.resetToken;
            delete updatedData.resetTokenExpiry;

            await db.ref('users/' + userKey).update({ data: encryptData(updatedData) });
            await logActivity(foundUser.username, 'reset password', 'Password berhasil diubah', ip, fp);

            return res.status(200).json({ data: encryptResponse({ success: true, message: 'Password berhasil diubah! Silakan login dengan password baru.' }) });
        }

        return res.status(400).json({ data: encryptResponse({ success: false, error: 'invalid_action', message: 'Aksi tidak valid!' }) });
    } catch (error) {
        console.error('Reset password error:', error);
        return res.status(500).json({ data: encryptResponse({ success: false, error: 'server_error', message: 'Terjadi kesalahan pada server. Coba lagi nanti.' }) });
    }
}
  return handler;
}


const revanstoreHandler=createRevanstoreHandler();
const registerHandler=createRegisterHandler();
const resetHandler=createResetHandler();

function looksLikeReset(action) { return new Set(['request_reset','verify_token','confirm_reset']).has(String(action||'')); }

export default async function webtopupbussid(req,res) {
  const queryAction=String(req.query.action||'').toLowerCase();
  if (queryAction) {
    const result=await securityAction(req,res,queryAction);
    if (result) return result;
  }

  const body=req.body||{};
  const ip=unifiedIP(req), fp=unifiedFP(req);
  // Catat setiap aksi endpoint webtopup tanpa pernah menyimpan password/token
  // atau isi payload sensitif. Aksi spesifik yang sudah punya log tetap boleh
  // menghasilkan log detail tambahan.
  if (body.path) {
    const actionName=`web:${String(body.path).slice(0,120)}`;
    try {
      const result=await revanstoreHandler(req,res);
      await unifiedLog(String(body.username||body.email||body.operator||''), actionName, ip, fp,
        `method=${String(body.method||'GET').slice(0,12)}`);
      return result;
    } catch (e) {
      await unifiedLog(String(body.username||body.email||body.operator||''), `${actionName}:error`, ip, fp, 'Request gagal di server');
      throw e;
    }
  }
  if (body.action && looksLikeReset(body.action)) {
    const actionName=`web:${String(body.action).slice(0,80)}`;
    try {
      const result=await resetHandler(req,res);
      await unifiedLog(String(body.username||body.email||''), actionName, ip, fp, 'Aksi reset password');
      return result;
    } catch (e) {
      await unifiedLog(String(body.username||body.email||''), `${actionName}:error`, ip, fp, 'Request gagal di server');
      throw e;
    }
  }
  if (body.action) {
    const actionName=`web:${String(body.action).slice(0,80)}`;
    try {
      const result=await registerHandler(req,res);
      await unifiedLog(String(body.username||body.email||''), actionName, ip, fp, 'Aksi webtopup');
      return result;
    } catch (e) {
      await unifiedLog(String(body.username||body.email||''), `${actionName}:error`, ip, fp, 'Request gagal di server');
      throw e;
    }
  }
  await unifiedLog('', 'web:invalid_request', ip, fp, 'Permintaan tidak valid');
  return res.status(400).json({error:'Permintaan tidak valid'});
}
