import { db } from './rvns/db.js';
import {
  hashPassword,
  verifyPassword,
  verifyRecaptchaV2,
  findUserByUsername,
  saveUser,
  toPublicUser,
  isValidUsername,
  logActivity,
  readLogs,
  readSuspiciousLogs,
  decryptAny,
  encryptAtRest,
  sanitize,
  blockIP,
  unblockIP,
  blockFP,
  unblockFP,
  listBlockedIPs,
  listBlockedFPs,
  isIPBlocked,
  isFPBlocked,
  getMaintenance,
  setMaintenance,
  banUserWithIPFP,
  unbanUserWithIPFP,
  banAksesUserWithIPFP,
  unbanAksesUserWithIPFP,
  suspendUser,
  unsuspendUser,
  approveUser,
  rejectUser,
  getIP,
  fpOf
} from './rvns/helper.js';
import {
  requireAdmin,
  setSecurityHeaders,
  setCorsHeaders,
  enforceOrigin,
  methodGuard,
  bodyGuard
} from './rvns/middleware.js';
import {
  createSessionToken,
  setSessionCookie,
  clearSessionCookie,
  generateCSRFToken,
  verifySession
} from './rvns/session.js';
import crypto from 'node:crypto';

function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

async function handleLogin(req, res, ip, fp) {
  const { accessKey, username, password, captchaToken } = req.body || {};

  if (!accessKey || !timingSafeEqualStr(accessKey, process.env.ADMIN_KEY || '')) {
    await logActivity(username || 'unknown', 'admin_login_bad_key', 'Kode akses salah', ip, fp);
    return res.status(403).json({ success: false, error: 'bad_key', message: 'Kode akses salah' });
  }
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });
  }
  if (!(await verifyRecaptchaV2(captchaToken))) {
    return res.status(400).json({ success: false, message: 'Verifikasi reCAPTCHA gagal' });
  }
  if (await isIPBlocked(ip)) {
    return res.status(403).json({ success: false, error: 'ip_blocked', message: 'IP Anda diblokir' });
  }
  if (fp && await isFPBlocked(fp)) {
    return res.status(403).json({ success: false, error: 'fp_blocked', message: 'Perangkat Anda diblokir' });
  }

  const attemptKey = `${String(ip).replace(/\./g, '_')}_${String(fp || 'nofp').replace(/[.#$\[\]\/]/g, '_')}`;
  const attemptRef = db.ref(`admin_login_attempts/${attemptKey}`);
  const attemptSnap = await attemptRef.once('value');
  const attemptData = attemptSnap.val() || {};
  let wrongCount = Number(attemptData.count || 0);
  const firstAt = Number(attemptData.firstAt || 0);
  if (firstAt && Date.now() - firstAt > 3600000) {
    await attemptRef.remove();
    wrongCount = 0;
  }

  const adminSnap = await db.ref('admin').once('value');
  const admins = adminSnap.val() || {};
  let found = null;
  let foundId = null;
  const input = String(username).toLowerCase().trim();

  for (const [id, row] of Object.entries(admins)) {
    if (id === 'auth') continue;
    const rowUsername = String(row.username || '').toLowerCase();
    let rowEmail = '';
    const d = decryptAny(row.data);
    if (d && d.email) rowEmail = String(d.email).toLowerCase();
    if (rowUsername === input || rowEmail === input) {
      found = row;
      foundId = id;
      break;
    }
  }

  if (!found) {
    wrongCount++;
    await attemptRef.set({
      count: wrongCount, firstAt: firstAt || Date.now(), lastAt: Date.now(),
      ip: sanitize(ip, 50), fingerprint: sanitize(fp, 100)
    });
    await logActivity(username, 'admin_login_failed', `Admin tidak ditemukan (attempt ${wrongCount}/3)`, ip, fp);
    if (wrongCount >= 3) {
      await blockIP(ip, 'Admin login gagal 3x', 'system');
      if (fp) await blockFP(fp, 'Admin login gagal 3x', 'system');
      await logActivity(username, 'admin_login_auto_blocked', `IP & FP diblokir setelah ${wrongCount} login gagal`, ip, fp);
      await attemptRef.remove();
      return res.status(403).json({ success: false, error: 'auto_blocked', message: 'Login gagal 3 kali. IP dan perangkat diblokir.' });
    }
    return res.status(401).json({ success: false, message: `Username atau password salah. Sisa ${3 - wrongCount} percobaan.` });
  }

  const lockedIP = found.lockedIP || '';
  const lockedFP = found.lockedFP || '';
  if (lockedIP && lockedIP !== ip) {
    return res.status(403).json({ success: false, error: 'ip_locked', message: 'Login cuma bisa dari jaringan yang terdaftar.' });
  }
  if (lockedFP && lockedFP !== fp) {
    return res.status(403).json({ success: false, error: 'fp_locked', message: 'Login cuma bisa dari perangkat yang terdaftar.' });
  }

  const adminData = decryptAny(found.data) || {};
  const hash = adminData.password_hash || adminData.passwordHash || '';
  let passwordOk = false;
  if (hash && hash.startsWith('$2')) passwordOk = await verifyPassword(password, hash);
  else if (adminData.password) passwordOk = String(adminData.password) === String(password);

  if (!passwordOk) {
    wrongCount++;
    await attemptRef.set({
      count: wrongCount, firstAt: firstAt || Date.now(), lastAt: Date.now(),
      ip: sanitize(ip, 50), fingerprint: sanitize(fp, 100)
    });
    await logActivity(username, 'admin_login_failed', `Password salah (attempt ${wrongCount}/3)`, ip, fp);
    if (wrongCount >= 3) {
      await blockIP(ip, 'Admin login gagal 3x', 'system');
      if (fp) await blockFP(fp, 'Admin login gagal 3x', 'system');
      await logActivity(username, 'admin_login_auto_blocked', `IP & FP diblokir setelah ${wrongCount} login gagal`, ip, fp);
      await attemptRef.remove();
      return res.status(403).json({ success: false, error: 'auto_blocked', message: 'Login gagal 3 kali. IP dan perangkat diblokir.' });
    }
    return res.status(401).json({ success: false, message: `Username atau password salah. Sisa ${3 - wrongCount} percobaan.` });
  }

  await attemptRef.remove();

  adminData.lastLoginIP = ip;
  adminData.lastLoginFP = fp;
  adminData.lastLoginAt = Date.now();
  adminData.lockedIP = ip;
  adminData.lockedFP = fp;
  const ips = Array.isArray(adminData.ipHistory) ? adminData.ipHistory : [];
  if (ip && (ips.length === 0 || ips[ips.length - 1] !== ip)) { ips.push(ip); if (ips.length > 10) ips.shift(); }
  adminData.ipHistory = ips;
  const fps = Array.isArray(adminData.fpHistory) ? adminData.fpHistory : [];
  if (fp && (fps.length === 0 || fps[fps.length - 1] !== fp)) { fps.push(fp); if (fps.length > 10) fps.shift(); }
  adminData.fpHistory = fps;

  await db.ref(`admin/${foundId}`).update({
    lockedIP: ip, lockedFP: fp, data: encryptAtRest(adminData)
  });

  const sessionToken = createSessionToken({ id: foundId, username: found.username, role: 'admin' });
  const csrfToken = generateCSRFToken({ uid: foundId });
  setSessionCookie(res, sessionToken, csrfToken, { role: 'admin' });
  await logActivity(found.username, 'admin_login_success', 'Login admin berhasil', ip, fp);

  return res.status(200).json({
    success: true,
    username: found.username,
    role: 'admin',
    csrfToken,
    sessionMaxAge: 3 * 24 * 60 * 60
  });
}

async function handleLogout(req, res, ip, fp) {
  const s = verifySession(req);
  if (s) await logActivity(s.username, 'admin_logout', 'Logout admin', ip, fp);
  clearSessionCookie(res);
  return res.status(200).json({ success: true, message: 'Logout berhasil' });
}

async function handleMe(req, res, session) {
  return res.status(200).json({ success: true, admin: { username: session.username, role: session.role } });
}

async function handleAuthInfo(req, res, session) {
  const snap = await db.ref(`admin/${session.uid}`).once('value');
  const row = snap.val();
  const d = row ? (decryptAny(row.data) || {}) : {};
  return res.status(200).json({ success: true, email: d.email || '', username: session.username, role: session.role });
}

async function handleStorageKey(req, res, session) {
  const fp = fpOf(req);
  const storageKey = crypto
    .createHmac('sha256', process.env.ADMIN_KEY)
    .update(`storage:${session.uid}:${session.username}:${fp}`)
    .digest('base64url');
  return res.status(200).json({ success: true, storageKey });
}

async function handleCheckShare(req, res, session, ip, fp) {
  const snap = await db.ref(`admin/${session.uid}`).once('value');
  const row = snap.val();
  if (!row) return res.status(200).json({ success: true, kick: false });
  const lockedFP = row.lockedFP || '';
  const lockedIP = row.lockedIP || '';
  if (lockedFP && fp && lockedFP !== fp) {
    return res.status(200).json({ success: true, kick: true, reason: 'fp_mismatch', message: 'Akun login di perangkat lain. Sesi ditutup.' });
  }
  if (lockedIP && ip && lockedIP !== ip) {
    return res.status(200).json({ success: true, kick: true, reason: 'ip_mismatch', message: 'Akun login di jaringan lain. Sesi ditutup.' });
  }
  return res.status(200).json({ success: true, kick: false });
}

async function handleGetUsers(req, res) {
  const snap = await db.ref('users').once('value');
  const users = Object.entries(snap.val() || {}).map(([id, row]) => toPublicUser(id, row))
    .sort((a, b) => b.createdAt - a.createdAt);
  return res.status(200).json({ success: true, users });
}

async function handleGetPendingUsers(req, res) {
  const snap = await db.ref('users').once('value');
  const users = Object.entries(snap.val() || {})
    .map(([id, row]) => toPublicUser(id, row))
    .filter(u => u.registered === true && u.activationStatus === 'pending')
    .sort((a, b) => b.createdAt - a.createdAt);
  return res.status(200).json({ success: true, users });
}

async function handleGetActiveUsers(req, res) {
  const snap = await db.ref('users').once('value');
  const users = Object.entries(snap.val() || {})
    .map(([id, row]) => toPublicUser(id, row))
    .filter(u => u.activationStatus === 'approved')
    .sort((a, b) => b.createdAt - a.createdAt);
  return res.status(200).json({ success: true, users });
}

async function handleGetRejectedUsers(req, res) {
  const snap = await db.ref('users').once('value');
  const users = Object.entries(snap.val() || {})
    .map(([id, row]) => toPublicUser(id, row))
    .filter(u => u.activationStatus === 'rejected')
    .sort((a, b) => b.rejectedAt - a.rejectedAt);
  return res.status(200).json({ success: true, users });
}

async function handleGetUserDetail(req, res) {
  const { id, username } = req.body || {};
  let found = null;
  if (id) {
    const snap = await db.ref(`users/${id}`).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    found = { id, row: snap.val(), data: decryptAny(snap.val().data) || {} };
  } else if (username) {
    found = await findUserByUsername(username);
  }
  if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });

  const user = toPublicUser(found.id, found.row);
  const trxSnap = await db.ref('transactions').once('value');
  const trxRaw = trxSnap.val() || {};
  const trxList = [];
  for (const [k, v] of Object.entries(trxRaw)) {
    const d = decryptAny(v.data) || {};
    if (d.operator === user.username || v.owner === user.username) trxList.push({ id: k, ...d });
  }
  trxList.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  user.recentTopups = trxList.filter(t => t.type === 'topup').slice(0, 5);
  user.recentTransactions = trxList.slice(0, 10);

  const logs = await readLogs(500);
  user.recentLogs = logs.filter(l => l.username === user.username).slice(0, 20);

  const resetHistory = Array.isArray(found.data.resetHistory) ? found.data.resetHistory : [];
  user.resetHistory = resetHistory.slice(-10).reverse();

  return res.status(200).json({ success: true, user });
}

async function handleApproveUser(req, res, session, ip, fp) {
  const { username } = req.body || {};
  const found = await findUserByUsername(username);
  if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
  if (found.row.activationStatus !== 'pending' && found.row.status !== 'pending') return res.status(409).json({ success: false, message: 'User tidak sedang menunggu aktivasi' });
  await approveUser(found.id, session.username);
  await logActivity(session.username, 'admin_approve_user', `Setujui aktivasi ${username}`, ip, fp);
  await logActivity(username, 'account_approved', `Akun disetujui oleh ${session.username}`, ip, fp);
  return res.status(200).json({ success: true, message: 'User disetujui & diaktivasi' });
}

async function handleRejectUser(req, res, session, ip, fp) {
  const { username, reason } = req.body || {};
  const found = await findUserByUsername(username);
  if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
  if (found.row.activationStatus !== 'pending' && found.row.status !== 'pending') return res.status(409).json({ success: false, message: 'User tidak sedang menunggu aktivasi' });
  await rejectUser(found.id, session.username, reason || '');
  await logActivity(session.username, 'admin_reject_user', `Tolak aktivasi ${username}${reason ? ' - ' + reason : ''}`, ip, fp);
  await logActivity(username, 'account_rejected', `Akun ditolak oleh ${session.username}${reason ? `: ${reason}` : ''}`, ip, fp);
  return res.status(200).json({ success: true, message: 'User ditolak' });
}

async function handleAddUser(req, res, session, ip, fp) {
  const { username, email, password, phone, expiry_date, role = 'User' } = req.body || {};
  const vu = isValidUsername(username);
  if (!vu.valid) return res.status(400).json({ success: false, message: vu.message });
  if (!password || password.length < 6) return res.status(400).json({ success: false, message: 'Password minimal 6 karakter' });
  if (!['User', 'Admin'].includes(role)) return res.status(400).json({ success: false, message: 'Role tidak valid' });
  if (await findUserByUsername(vu.username)) return res.status(409).json({ success: false, message: 'Username sudah dipakai' });

  const id = db.ref('users').push().key;
  const password_hash = await hashPassword(password);
  await saveUser(id, {
    username: vu.username,
    role,
    status: 'active',
    banned: false, accessBanned: false, forceLogout: false,
    registered: false,
    activationStatus: 'approved',
    approvedAt: Date.now(),
    approvedBy: session.username,
    createdAt: Date.now(),
    email: sanitize(email || '', 200),
    phone: sanitize(phone || '', 30),
    expiry_date: sanitize(expiry_date || '', 50),
    password_hash,
    ipHistory: [], fpHistory: [], resetCount: 0
  });
  await logActivity(session.username, 'admin_add_user', `Tambah user ${vu.username}`, ip, fp);
  return res.status(200).json({ success: true, message: 'User ditambahkan', id });
}

async function handleEditUser(req, res, session, ip, fp) {
  const { id, username, email, phone, role, password, status, expiry_date } = req.body || {};
  let found;
  if (id) {
    const snap = await db.ref(`users/${id}`).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    found = { id, row: snap.val(), data: decryptAny(snap.val().data) || {} };
  } else {
    found = await findUserByUsername(username);
  }
  if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
  const u = { ...found.data };
  if (email !== undefined) u.email = sanitize(email, 200);
  if (phone !== undefined) u.phone = sanitize(phone, 30);
  if (expiry_date !== undefined) u.expiry_date = sanitize(expiry_date, 50);
  if (password) u.password_hash = await hashPassword(password);
  await saveUser(found.id, {
    ...u,
    username: found.row.username,
    role: role || found.row.role,
    status: status || found.row.status,
    banned: found.row.banned,
    accessBanned: found.row.accessBanned,
    forceLogout: found.row.forceLogout,
    registered: found.row.registered,
    activationStatus: found.row.activationStatus,
    approvedAt: found.row.approvedAt,
    approvedBy: found.row.approvedBy,
    rejectedAt: found.row.rejectedAt,
    rejectedBy: found.row.rejectedBy,
    createdAt: found.row.createdAt
  });
  await logActivity(session.username, 'admin_edit_user', `Edit ${found.row.username}`, ip, fp);
  return res.status(200).json({ success: true, message: 'User diperbarui' });
}

async function handleUserRegistrations(req, res) {
  return handleGetPendingUsers(req, res);
}

async function handleUserActivity(req, res) {
  const limit = Math.min(Math.max(Number(req.body?.limit || req.query.limit || 200), 1), 500);
  return res.status(200).json({ success: true, logs: await readLogs(limit) });
}

async function handleStats(req, res) {
  const snap = await db.ref('users').once('value');
  const raw = snap.val() || {};
  const users = Object.entries(raw).map(([id, row]) => toPublicUser(id, row));
  const m = await getMaintenance();
  return res.status(200).json({
    success: true,
    stats: {
      total: users.length,
      pending: users.filter(u => u.activationStatus === 'pending').length,
      active: users.filter(u => u.activationStatus === 'approved').length,
      rejected: users.filter(u => u.activationStatus === 'rejected').length,
      banned: users.filter(u => u.banned === true).length,
      accessBanned: users.filter(u => u.accessBanned === true).length,
      forced: users.filter(u => u.forceLogout === true).length,
      maintenance: m.maintenance
    }
  });
}

async function handleLogsRich(req, res) {
  const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
  const logs = await readLogs(limit);
  const userSnap = await db.ref('users').once('value');
  const users = userSnap.val() || {};
  const ipFpMap = new Map();
  for (const [id, row] of Object.entries(users)) {
    const d = decryptAny(row.data) || {};
    const ips = Array.isArray(d.ipHistory) ? d.ipHistory : [];
    const fps = Array.isArray(d.fpHistory) ? d.fpHistory : [];
    const username = row.username || '';
    for (const ip of ips) ipFpMap.set('ip:' + ip, username);
    for (const fp of fps) ipFpMap.set('fp:' + fp, username);
  }
  const enriched = logs.map(l => {
    let displayName = '';
    if (l.ip && ipFpMap.has('ip:' + l.ip)) displayName = ipFpMap.get('ip:' + l.ip);
    else if (l.fingerprint && ipFpMap.has('fp:' + l.fingerprint)) displayName = ipFpMap.get('fp:' + l.fingerprint);
    return { ...l, displayName: displayName || (l.username || 'Anonymous'), knownUser: !!displayName };
  });
  return res.status(200).json({ success: true, logs: enriched });
}

async function handleSuspiciousRich(req, res) {
  const logs = await readSuspiciousLogs(300);
  return res.status(200).json({ success: true, logs });
}

export default async function handler(req, res) {
  setSecurityHeaders(res);
  setCorsHeaders(req, res);
  if (!methodGuard(req, res, ['GET', 'POST', 'PATCH', 'DELETE'])) return;
  if (!enforceOrigin(req, res)) return;
  if (!bodyGuard(req, res)) return;

  const action = String(req.query.action || '').toLowerCase();
  const ip = getIP(req);
  const fp = fpOf(req);

  try {
    if (action === 'login') return handleLogin(req, res, ip, fp);
    if (action === 'logout') return handleLogout(req, res, ip, fp);

    const skipCsrf = action === 'storage-key';
    const auth = await requireAdmin(req, res, { csrf: !skipCsrf });
    if (!auth) return;
    const session = auth.session;

    if (action === 'me') return handleMe(req, res, session);
    if (action === 'auth') return handleAuthInfo(req, res, session);
    if (action === 'storage-key') return handleStorageKey(req, res, session);
    if (action === 'check-share') return handleCheckShare(req, res, session, ip, fp);

    if (action === 'users') return handleGetUsers(req, res);
    if (action === 'pending-users') return handleGetPendingUsers(req, res);
    if (action === 'approved-users' || action === 'active-users') return handleGetActiveUsers(req, res);
    if (action === 'rejected-users') return handleGetRejectedUsers(req, res);
    if (action === 'user-registrations') return handleUserRegistrations(req, res);
    if (action === 'user-activity') return handleUserActivity(req, res);
    if (action === 'get-user-detail') return handleGetUserDetail(req, res);
    if (action === 'add-user') return handleAddUser(req, res, session, ip, fp);
    if (action === 'edit-user') return handleEditUser(req, res, session, ip, fp);
    if (action === 'stats') return handleStats(req, res);

    if (action === 'approve-user') return handleApproveUser(req, res, session, ip, fp);
    if (action === 'reject-user') return handleRejectUser(req, res, session, ip, fp);

    if (action === 'ban-user') {
      const { username, reason, days } = req.body || {};
      const found = await findUserByUsername(username);
      if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
      const durationMs = days ? Number(days) * 86400000 : 0;
      const result = await banUserWithIPFP(found.id, reason, session.username, durationMs);
      await logActivity(session.username, 'admin_ban_user', `Ban ${username} + block IP/FP`, ip, fp);
      return res.status(200).json({ success: true, message: `User dibanned + ${result.blockedIPs} IP + ${result.blockedFPs} FP diblokir`, ...result });
    }

    if (action === 'unban-user' || action === 'unbanned') {
      const { username } = req.body || {};
      const found = await findUserByUsername(username);
      if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
      await unbanUserWithIPFP(found.id);
      await logActivity(session.username, 'admin_unban_user', `Unban ${username}`, ip, fp);
      return res.status(200).json({ success: true, message: 'User diunban + IP/FP diunblock' });
    }

    if (action === 'ban-akses') {
      const { username, reason, days } = req.body || {};
      const found = await findUserByUsername(username);
      if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
      const durationMs = days ? Number(days) * 86400000 : 0;
      await banAksesUserWithIPFP(found.id, reason, session.username, durationMs);
      await logActivity(session.username, 'admin_ban_akses', `Ban akses ${username} + block IP/FP`, ip, fp);
      return res.status(200).json({ success: true, message: 'Ban akses + IP/FP diblokir' });
    }

    if (action === 'unban-akses') {
      const { username } = req.body || {};
      const found = await findUserByUsername(username);
      if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
      await unbanAksesUserWithIPFP(found.id);
      await logActivity(session.username, 'admin_unban_akses', `Unban akses ${username}`, ip, fp);
      return res.status(200).json({ success: true, message: 'Ban akses dicabut' });
    }

    if (action === 'force-logout') {
      const { username, reason, days } = req.body || {};
      const found = await findUserByUsername(username);
      if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
      const durationMs = days ? Number(days) * 86400000 : 0;
      await suspendUser(found.id, reason, session.username, durationMs);
      await logActivity(session.username, 'admin_force_logout', `Tangguhkan ${username}`, ip, fp);
      return res.status(200).json({ success: true, message: 'User ditangguhkan' });
    }

    if (action === 'unforce-logout' || action === 'unforce') {
      const { username } = req.body || {};
      const found = await findUserByUsername(username);
      if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
      await unsuspendUser(found.id);
      await logActivity(session.username, 'admin_unforce_logout', `Pulihkan ${username}`, ip, fp);
      return res.status(200).json({ success: true, message: 'Penangguhan dicabut' });
    }

    if (action === 'delete-user') {
      const found = await findUserByUsername(req.body.username);
      if (!found) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
      await db.ref(`users/${found.id}`).remove();
      await logActivity(session.username, 'admin_delete_user', `Hapus ${found.row.username}`, ip, fp);
      return res.status(200).json({ success: true, message: 'User dihapus' });
    }

    if (action === 'block-ip') {
      if (!req.body.ip) return res.status(400).json({ success: false, message: 'IP wajib' });
      await blockIP(req.body.ip, req.body.reason, session.username);
      return res.status(200).json({ success: true, message: 'IP diblokir' });
    }
    if (action === 'unblock-ip') {
      await unblockIP(req.body.ip);
      return res.status(200).json({ success: true, message: 'IP diunblock' });
    }
    if (action === 'block-fp') {
      if (!req.body.fingerprint) return res.status(400).json({ success: false, message: 'Fingerprint wajib' });
      await blockFP(req.body.fingerprint, req.body.reason, session.username);
      return res.status(200).json({ success: true, message: 'FP diblokir' });
    }
    if (action === 'unblock-fp') {
      await unblockFP(req.body.fingerprint);
      return res.status(200).json({ success: true, message: 'FP diunblock' });
    }
    if (action === 'list-blocked-ips') return res.status(200).json({ success: true, items: await listBlockedIPs() });
    if (action === 'list-blocked-fps') return res.status(200).json({ success: true, items: await listBlockedFPs() });

    if (action === 'maintenance-status') {
      const m = await getMaintenance();
      return res.status(200).json({ success: true, ...m });
    }
    if (action === 'set-maintenance') {
      const result = await setMaintenance(req.body, session.username);
      await logActivity(session.username, 'admin_maintenance', `Maintenance ${result.maintenance ? 'ON' : 'OFF'}`, ip, fp);
      return res.status(200).json({ success: true, data: result });
    }

    if (action === 'logs') return handleLogsRich(req, res);
    if (action === 'suspicious-logs') return handleSuspiciousRich(req, res);
    if (action === 'clear-logs') {
      await db.ref('activity_logs').remove();
      return res.status(200).json({ success: true, message: 'Log dihapus' });
    }
    if (action === 'clear-suspicious') {
      await db.ref('suspicious_logs').remove();
      return res.status(200).json({ success: true, message: 'Log mencurigakan dihapus' });
    }

    return res.status(404).json({ success: false, message: `Action tidak dikenal: ${action}` });
  } catch (e) {
    console.error('[admin]', e?.stack || e?.message || e);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
}