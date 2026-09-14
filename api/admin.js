import crypto from 'node:crypto';
import admin from 'firebase-admin';
import bcrypt from 'bcryptjs';

const ADMIN_KEY = process.env.ADMIN_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;
const TRANSPORT_PRIVATE_KEY = process.env.TRANSPORT_PRIVATE_KEY;

if (!ADMIN_KEY || ADMIN_KEY.length < 32) {
  throw new Error('ADMIN_KEY wajib di-set dan minimal 32 karakter');
}

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET wajib di-set dan minimal 32 karakter');
}

/* =========================================
   TRANSPORT RSA KEY
========================================= */

let privateKey;

if (!TRANSPORT_PRIVATE_KEY) {
  throw new Error(
    'TRANSPORT_PRIVATE_KEY wajib di-set di environment Vercel'
  );
}

try {
  privateKey = crypto.createPrivateKey(
    TRANSPORT_PRIVATE_KEY.replace(/\\n/g, '\n')
  );
} catch (error) {
  console.error('[TRANSPORT KEY]', error?.message || error);

  throw new Error(
    'TRANSPORT_PRIVATE_KEY tidak valid'
  );
}

const publicKey = crypto.createPublicKey(
  privateKey
);

const publicJwk = publicKey.export({
  format: 'jwk'
});

/* =========================================
   BASE64URL
========================================= */

function b64(buffer) {
  return Buffer
    .from(buffer)
    .toString('base64url');
}

function fromB64(value) {
  return Buffer.from(
    String(value || ''),
    'base64url'
  );
}

/* =========================================
   DECRYPT REQUEST
========================================= */

function decryptTransport(envelope) {

  if (
    !envelope ||
    envelope.v !== 1 ||
    envelope.alg !==
      'RSA-OAEP-256/AES-256-GCM'
  ) {
    throw new Error(
      'Encrypted request required'
    );
  }

  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding:
        crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    fromB64(envelope.key)
  );

  if (aesKey.length !== 32) {
    throw new Error(
      'AES key tidak valid'
    );
  }

  const iv = fromB64(envelope.iv);

  if (iv.length !== 12) {
    throw new Error(
      'IV tidak valid'
    );
  }

  const authTag = fromB64(
    envelope.tag
  );

  if (authTag.length !== 16) {
    throw new Error(
      'Auth tag tidak valid'
    );
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    aesKey,
    iv
  );

  decipher.setAuthTag(
    authTag
  );

  const plaintext = Buffer.concat([
    decipher.update(
      fromB64(envelope.data)
    ),
    decipher.final()
  ]).toString('utf8');

  return JSON.parse(
    plaintext
  );
}

/* =========================================
   ENCRYPT RESPONSE
========================================= */

function encryptTransport(
  data,
  clientJwk
) {

  if (
    !clientJwk ||
    clientJwk.kty !== 'RSA'
  ) {
    throw new Error(
      'Client public key required'
    );
  }

  const clientPublicKey =
    crypto.createPublicKey({
      key: clientJwk,
      format: 'jwk'
    });

  const aesKey =
    crypto.randomBytes(32);

  const iv =
    crypto.randomBytes(12);

  const cipher =
    crypto.createCipheriv(
      'aes-256-gcm',
      aesKey,
      iv
    );

  const plaintext =
    Buffer.from(
      JSON.stringify(data ?? null),
      'utf8'
    );

  const ciphertext =
    Buffer.concat([
      cipher.update(plaintext),
      cipher.final()
    ]);

  const wrappedKey =
    crypto.publicEncrypt(
      {
        key: clientPublicKey,
        padding:
          crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      aesKey
    );

  return {
    v: 1,

    alg:
      'RSA-OAEP-256/AES-256-GCM',

    key:
      b64(wrappedKey),

    iv:
      b64(iv),

    tag:
      b64(cipher.getAuthTag()),

    data:
      b64(ciphertext)
  };
}