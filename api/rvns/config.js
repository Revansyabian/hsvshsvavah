const required = { ADMIN_KEY: 32, SESSION_SECRET: 32 };
for (const [key, min] of Object.entries(required)) {
  const v = process.env[key];
  if (!v || v.length < min) throw new Error(`[CONFIG] ${key} wajib minimal ${min} karakter`);
}

export const CONFIG = {
  ADMIN_KEY: process.env.ADMIN_KEY,
  SESSION_SECRET: process.env.SESSION_SECRET,
  RECAPTCHA_V2_SECRET: process.env.RECAPTCHA_V2_SECRET_KEY || '',
  RECAPTCHA_V3_SECRET: process.env.RECAPTCHA_V3_SECRET_KEY || '',
  RECAPTCHA_V2_SITE_KEY: '6LeffrotAAAAAO7SRbl-wJQ8YXzOGNG-t-DW5EGT',
  RECAPTCHA_V3_SITE_KEY: '6LcVBn4tAAAAAINTTIleUbUZr1ZykvyB6WA-oOfT',
  RESEND_API_KEY: process.env.RESEND_API_KEY || '',
  EMAIL_FROM: process.env.EMAIL_FROM || 'Web Top Up <noreply@example.com>',
  BASE_URL: process.env.BASE_URL || '',
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean),
  SALT_ROUNDS: 12,
  SESSION_ADMIN_MAX_AGE: 3 * 24 * 60 * 60,
  SESSION_USER_MAX_AGE: 3 * 24 * 60 * 60,
  SESSION_MAX_AGE: 3 * 24 * 60 * 60,
  RESET_TOKEN_EXPIRY: 15 * 60 * 1000,
  RESET_DAILY_MAX: 3,
  REGISTER_COOLDOWN: 3 * 24 * 60 * 60 * 1000,
  MAX_TOPUP_AMOUNT: 2147483647,
  BAN_DURATIONS: {
    '1h': 3600000,
    '2h': 7200000,
    '3h': 10800000,
    'permanent': 0
  }
};