import crypto from 'crypto';

function keyFromSecret(secret) {
  return crypto.createHash('sha256').update(String(secret)).digest();
}

export function encryptAtRest(value, secret) {
  const key = keyFromSecret(secret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return 'v2.' + Buffer.concat([iv, tag, ciphertext]).toString('base64url');
}

export function decryptAtRest(raw, secret) {
  if (typeof raw !== 'string') return null;
  if (raw.startsWith('v2.')) {
    try {
      const b = Buffer.from(raw.slice(3), 'base64url');
      const iv = b.subarray(0, 12), tag = b.subarray(12, 28), ciphertext = b.subarray(28);
      const decipher = crypto.createDecipheriv('aes-256-gcm', keyFromSecret(secret), iv);
      decipher.setAuthTag(tag);
      return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
    } catch { return null; }
  }
  return null;
}
