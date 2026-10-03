// api/user.js
import { db } from './rvns/db.js';
import {
  saveUser,
  logActivity,
  decryptAny,
  encryptAtRest,
  sanitize,
  getIP,
  fpOf,
  getMaintenance,
  trackUserIPFP,
  detectSuspicious
} from './rvns/helper.js';
import {
  requireAuth,
  setSecurityHeaders,
  setCorsHeaders,
  enforceOrigin,
  methodGuard,
  bodyGuard
} from './rvns/middleware.js';

async function handleCheckStatus(req, res, auth, ip, fp) {
  const row = auth.user.row;
  const data = auth.user.data;

  const m = await getMaintenance();
  if (m.maintenance) {
    return res.status(200).json({ valid: false, maintenance: true, title: m.title, message: m.message, until: m.until });
  }

  if (row.banned === true) {
    if (data.bannedUntil && data.bannedUntil > 0 && data.bannedUntil < Date.now()) {
      data.bannedUntil = 0;
      await saveUser(auth.user.id, {
        ...data,
        username: row.username,
        role: row.role,
        status: row.status,
        banned: false
      });
    } else {
      return res.status(200).json({ banned: true, bannedUntil: data.bannedUntil || 0 });
    }
  }

  if (row.accessBanned === true) {
    if (data.banAksesUntil && data.banAksesUntil > 0 && data.banAksesUntil < Date.now()) {
      data.banAksesUntil = 0;
      await saveUser(auth.user.id, {
        ...data,
        username: row.username,
        role: row.role,
        status: row.status,
        accessBanned: false
      });
    } else {
      return res.status(200).json({ banAkses: true, banAksesUntil: data.banAksesUntil || 0 });
    }
  }

  if (row.forceLogout === true) {
    if (data.forceLogoutUntil && data.forceLogoutUntil > 0 && data.forceLogoutUntil < Date.now()) {
      data.forceLogoutUntil = 0;
      await saveUser(auth.user.id, {
        ...data,
        username: row.username,
        role: row.role,
        status: row.status,
        forceLogout: false
      });
    } else {
      return res.status(200).json({ forceLogout: true });
    }
  }

  const expiry = data.expiry_date || '';
  if (!expiry) {
    return res.status(200).json({
      valid: false,
      expired: true,
      reason: 'no_expiry',
      message: 'Masa aktif tidak valid. Coba login lagi.'
    });
  }
  if (!String(expiry).includes('9999')) {
    const expiryDate = new Date(expiry);
    if (isNaN(expiryDate.getTime())) {
      return res.status(200).json({
        valid: false,
        expired: true,
        reason: 'bad_expiry',
        message: 'Masa aktif tidak valid. Coba login lagi.'
      });
    }
    expiryDate.setHours(23, 59, 59, 999);
    if (Date.now() > expiryDate.getTime()) {
      return res.status(200).json({
        valid: false,
        expired: true,
        reason: 'expired',
        message: 'Masa aktif habis. Hubungi admin.'
      });
    }
  }

  const lockedFP = data.lockedFP || '';
  const lockedIP = data.lockedIP || '';
  const currentFP = fp || '';
  const currentIP = ip || '';

  if (!lockedFP && currentFP) {
    data.lockedFP = currentFP;
    data.lockedIP = currentIP;
    data.lockedAt = Date.now();
    await saveUser(auth.user.id, { ...data, username: row.username, role: row.role, status: row.status });
  } else if (lockedFP && currentFP) {
    const fpSame = lockedFP === currentFP;
    const ipSame = !lockedIP || !currentIP || lockedIP === currentIP;

    if (fpSame) {
      if (currentIP && lockedIP !== currentIP) {
        data.lockedIP = currentIP;
        data.ipChangeAt = Date.now();
        await saveUser(auth.user.id, { ...data, username: row.username, role: row.role, status: row.status });
      }
    } else if (ipSame) {
      data.lockedFP = currentFP;
      data.fpChangedAt = Date.now();
      data.fpChangedFrom = lockedFP;
      await saveUser(auth.user.id, { ...data, username: row.username, role: row.role, status: row.status });
      await logActivity(row.username, 'fp_rotated', 'FP berubah tapi IP sama', ip, fp);
    } else {
      data.forceLogout = true;
      data.forceLogoutUntil = 0;
      data.shareDetected = { at: Date.now(), type: 'fp_and_ip_mismatch' };
      await saveUser(auth.user.id, {
        ...data,
        username: row.username,
        role: row.role,
        status: row.status,
        forceLogout: true
      });
      await logActivity(row.username, 'sharing_detected', 'FP & IP beda', ip, fp);
      await detectSuspicious(auth.user, 'sharing_detected', ip, fp,
        'User login dari device + jaringan lain.');
      return res.status(200).json({
        valid: false,
        forceLogout: true,
        share: true,
        message: 'Akun terdeteksi login dari perangkat lain. Hubungi admin.'
      });
    }
  }

  try { await trackUserIPFP(auth.user.id, ip, fp); } catch (e) {}

  return res.status(200).json({
    valid: true,
    user: {
      id: auth.user.id,
      username: row.username,
      role: row.role || 'User',
      email: data.email || '',
      expiry_date: data.expiry_date || ''
    }
  });
}

async function handleGetTransactions(req, res, auth) {
  const snap = await db.ref('transactions').orderByChild('owner').equalTo(auth.session.username).once('value');
  const raw = snap.val() || {};
  const now = Date.now();
  const result = {};
  for (const [k, v] of Object.entries(raw)) {
    if (now - (v.createdAt || 0) > 172800000) { db.ref(`transactions/${k}`).remove(); continue; }
    const d = decryptAny(v.data) || {};
    delete d.deviceId;
    delete d.authToken;
    delete d.xAuth;
    result[k] = d;
  }
  return res.status(200).json({ success: true, transactions: result });
}

async function handleSaveTransaction(req, res, auth, ip, fp) {
  const data = req.body || {};

  const maskedDeviceId = (() => {
    const raw = String(data.deviceId || '').trim();
    if (!raw) return '';
    if (raw.length <= 8) return raw.slice(0, 2) + '***';
    return raw.slice(0, 4) + '***' + raw.slice(-4);
  })();

  const sanitizedData = {
    type: sanitize(data.type, 20),
    accountName: sanitize(data.accountName, 100),
    amount: Number(data.amount) || 0,
    oldBalance: Number(data.oldBalance) || 0,
    newBalance: Number(data.newBalance) || 0,
    oldName: sanitize(data.oldName, 100),
    newName: sanitize(data.newName, 100),
    maskedDeviceId: maskedDeviceId,
    status: sanitize(data.status, 20),
    operator: auth.session.username
  };

  const id = db.ref('transactions').push().key;
  await db.ref(`transactions/${id}`).set({
    owner: auth.session.username,
    type: sanitizedData.type,
    accountName: sanitizedData.accountName,
    amount: sanitizedData.amount,
    operator: auth.session.username,
    createdAt: Date.now(),
    data: encryptAtRest(sanitizedData)
  });

  await logActivity(auth.session.username, 'transaction', `${sanitizedData.type} ${sanitizedData.amount}`, ip, fp);
  await trackUserIPFP(auth.user.id, ip, fp);

  return res.status(200).json({ success: true, id });
}

async function handleDeleteTransactions(req, res, auth) {
  const snap = await db.ref('transactions').orderByChild('owner').equalTo(auth.session.username).once('value');
  const updates = {};
  for (const k of Object.keys(snap.val() || {})) updates[k] = null;
  if (Object.keys(updates).length) await db.ref('transactions').update(updates);
  return res.status(200).json({ success: true });
}

export default async function handler(req, res) {
  setSecurityHeaders(res);
  setCorsHeaders(req, res);
  if (!methodGuard(req, res, ['GET', 'POST', 'DELETE'])) return;
  if (!enforceOrigin(req, res)) return;
  if (!bodyGuard(req, res)) return;

  const action = String(req.query.action || '').toLowerCase();
  const ip = getIP(req);
  const fp = fpOf(req);

  try {
    const auth = await requireAuth(req, res, { csrf: true });
    if (!auth) return;

    if (action === 'check-status') return handleCheckStatus(req, res, auth, ip, fp);
    if (action === 'transactions') {
      if (req.method === 'GET') return handleGetTransactions(req, res, auth);
      if (req.method === 'POST') return handleSaveTransaction(req, res, auth, ip, fp);
      if (req.method === 'DELETE') return handleDeleteTransactions(req, res, auth);
    }
    return res.status(404).json({ success: false, message: `Action tidak dikenal: ${action}` });
  } catch (e) {
    console.error('[user]', e?.stack || e?.message || e);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
}