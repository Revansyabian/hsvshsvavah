import CryptoJS from 'crypto-js';
import admin from 'firebase-admin';
import { encryptAtRest, decryptAtRest } from './secure-store.js';
import bcrypt from 'bcryptjs';

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
            const dec = JSON.stringify(decryptAtRest(raw, ADMIN_KEY) || {});
            if (!dec) return raw;
            return JSON.parse(dec);
        }
        if (raw.data) {
            const dec = JSON.stringify(decryptAtRest(raw.data, ADMIN_KEY) || {});
            if (!dec) return raw;
            return JSON.parse(dec);
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
        if (raw && raw.data) {
            const data = decryptData(raw.data);
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
        if (raw && raw.data) {
            const data = decryptData(raw.data);
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
        if (raw && raw.data) {
            const data = decryptData(raw.data);
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

export default async function handler(req, res) {
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
