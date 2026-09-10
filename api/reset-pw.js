import CryptoJS from 'crypto-js';
import admin from 'firebase-admin';
import { encryptAtRest, decryptAtRest } from './secure-store.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

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

            const resetToken = generateResetToken();
            const resetTokenExpiry = Date.now() + RESET_TOKEN_EXPIRY;

            const updatedData = { ...foundUser, resetToken: resetToken, resetTokenExpiry: resetTokenExpiry };
            await db.ref('users/' + userKey).update({ data: encryptData(updatedData) });

            const resetLink = BASE_URL + '/pages/confirm-password?token=' + resetToken;

            const emailSent = await sendResetEmail(foundUser.email, foundUser.username, resetLink);

            if (!emailSent) {
                return res.status(200).json({ data: encryptResponse({ success: false, error: 'email_error', message: 'Gagal mengirim email! Coba lagi nanti.' }) });
            }

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

            const hashedPassword = await hashPassword(newPassword);

            const updatedData = { ...foundUser, password_hash: hashedPassword };
            delete updatedData.password;
            delete updatedData.resetToken;
            delete updatedData.resetTokenExpiry;

            await db.ref('users/' + userKey).update({ data: encryptData(updatedData) });

            return res.status(200).json({ data: encryptResponse({ success: true, message: 'Password berhasil diubah! Silakan login dengan password baru.' }) });
        }

        return res.status(400).json({ data: encryptResponse({ success: false, error: 'invalid_action', message: 'Aksi tidak valid!' }) });
    } catch (error) {
        console.error('Reset password error:', error);
        return res.status(500).json({ data: encryptResponse({ success: false, error: 'server_error', message: 'Terjadi kesalahan pada server. Coba lagi nanti.' }) });
    }
}