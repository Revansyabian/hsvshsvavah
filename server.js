import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import webtopupbussid, {
  decryptRequest,
  encryptResponse
} from './api/webtopupbussid.js';

import rvnstore from './api/rvnstore.js';
import adminHandler from './api/admin.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const server = express();

const PAGES_DIR = path.join(__dirname, 'pages');

/* =========================================
   BASIC CONFIG
========================================= */

server.disable('x-powered-by');
server.set('trust proxy', 1);

/* =========================================
   BODY PARSER
========================================= */

server.use(express.json({
  limit: '200kb',
  strict: false
}));

server.use(express.urlencoded({
  extended: false,
  limit: '20kb'
}));

/* =========================================
   CORS
========================================= */

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);

server.use((req, res, next) => {
  const origin = req.headers.origin;

  if (
    origin &&
    allowedOrigins.length > 0 &&
    !allowedOrigins.includes(origin)
  ) {
    return res.status(403).json({
      success: false,
      error: 'Origin tidak diizinkan'
    });
  }

  if (origin) {
    res.setHeader(
      'Access-Control-Allow-Origin',
      origin
    );

    res.setHeader(
      'Access-Control-Allow-Credentials',
      'true'
    );

    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, X-Requested-With, X-Fingerprint, X-Client-Key'
    );

    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,POST,PUT,PATCH,DELETE,OPTIONS'
    );

    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  next();
});

/* =========================================
   ORIGINAL PATH
========================================= */

function getOriginalPath(req) {
  const value = String(
    req.originalUrl ||
    req.url ||
    ''
  );

  const q = value.indexOf('?');

  return q >= 0
    ? value.slice(0, q)
    : value;
}

/* =========================================
   ENCRYPTION EXEMPTION
========================================= */

function isExempt(req) {
  const originalPath = getOriginalPath(req);

  /*
   * RVNStore tetap terpisah
   */
  if (originalPath === '/api/rvnstore') {
    return true;
  }

  /*
   * ADMIN MENGURUS ENCRYPTION SENDIRI
   */
  if (originalPath === '/api/admin') {
    return true;
  }

  /*
   * PUBLIC KEY WEBTOPUP
   *
   * Request pertama belum memiliki
   * X-Client-Key.
   */
  if (
    (
      originalPath === '/api/webtopup' ||
      originalPath === '/api/webtopupbussid'
    ) &&
    String(req.query.action || '').toLowerCase() === 'key'
  ) {
    return true;
  }

  return false;
}

/* =========================================
   WEBTOPUP ENCRYPTED TRANSPORT
========================================= */

function encryptedTransport(req, res, next) {

  if (isExempt(req)) {
    return next();
  }

  const clientKey =
    req.headers['x-client-key'];

  /*
   * Request harus encrypted
   */
  if (
    req.body &&
    typeof req.body === 'object' &&
    Object.keys(req.body).length > 0
  ) {
    try {

      req.body = decryptRequest(
        req.body
      );

    } catch (error) {

      console.error(
        '[WEBTOPUP DECRYPT]',
        error?.message || error
      );

      return res.status(400).json({
        success: false,
        error: 'Encrypted request tidak valid'
      });
    }
  }

  if (!clientKey) {
    return res.status(400).json({
      success: false,
      error: 'Client public key diperlukan'
    });
  }

  /*
   * Simpan res.json asli
   */
  const originalJson =
    res.json.bind(res);

  /*
   * Encrypt response
   */
  res.json = (body) => {

    try {

      /*
       * Handler lama mungkin sudah
       * menghasilkan encrypted envelope.
       *
       * Jangan encrypt dua kali.
       */
      if (
        body &&
        typeof body === 'object' &&
        body.data &&
        typeof body.data === 'object' &&
        body.data.v === 1 &&
        body.data.alg ===
          'RSA-OAEP-256/AES-256-GCM'
      ) {

        return originalJson(
          body.data
        );
      }

      return originalJson(
        encryptResponse(
          body,
          clientKey
        )
      );

    } catch (error) {

      console.error(
        '[WEBTOPUP ENCRYPT]',
        error?.message || error
      );

      if (!res.headersSent) {
        return originalJson({
          success: false,
          error: 'Gagal mengenkripsi response'
        });
      }

      return res;
    }
  };

  next();
}

/* =========================================
   IMPORTANT
   API MIDDLEWARE
========================================= */

server.use(
  '/api',
  encryptedTransport
);

/* =========================================
   WEBTOPUP
========================================= */

server.all(
  '/api/webtopup',
  async (req, res) => {

    try {

      return await webtopupbussid(
        req,
        res
      );

    } catch (error) {

      console.error(
        '[WEBTOPUP]',
        error?.stack ||
        error?.message ||
        error
      );

      if (!res.headersSent) {
        return res.status(500).json({
          success: false,
          error: 'Internal server error'
        });
      }
    }
  }
);

server.all(
  '/api/webtopupbussid',
  async (req, res) => {

    try {

      return await webtopupbussid(
        req,
        res
      );

    } catch (error) {

      console.error(
        '[WEBTOPUP BUSSID]',
        error?.stack ||
        error?.message ||
        error
      );

      if (!res.headersSent) {
        return res.status(500).json({
          success: false,
          error: 'Internal server error'
        });
      }
    }
  }
);

/* =========================================
   RVNSTORE
========================================= */

server.all(
  '/api/rvnstore',
  async (req, res) => {

    try {

      return await rvnstore(
        req,
        res
      );

    } catch (error) {

      console.error(
        '[RVNSTORE]',
        error?.stack ||
        error?.message ||
        error
      );

      if (!res.headersSent) {
        return res.status(500).json({
          success: false,
          error: 'Internal server error'
        });
      }
    }
  }
);

/* =========================================
   ADMIN API
========================================= */

server.all(
  '/api/admin',
  async (req, res) => {

    try {

      return await adminHandler(
        req,
        res
      );

    } catch (error) {

      console.error(
        '[ADMIN API]',
        error?.stack ||
        error?.message ||
        error
      );

      if (!res.headersSent) {
        return res.status(500).json({
          success: false,
          error: 'Internal server error'
        });
      }
    }
  }
);

/* =========================================
   MAIN WEBSITE
========================================= */

server.get(
  '/',
  (_req, res) => {

    return res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );
  }
);

/* =========================================
   ADMIN PANEL
========================================= */

server.get(
  ['/admin', '/admin/'],
  (_req, res) => {

    return res.sendFile(
      path.join(
        __dirname,
        'admin.html'
      )
    );
  }
);

/* =========================================
   ADMIN REGISTER
========================================= */

server.get(
  ['/admin/register', '/admin/register/'],
  (_req, res) => {

    return res.sendFile(
      path.join(
        __dirname,
        'admin-register.html'
      )
    );
  }
);

/* =========================================
   FRONTEND PAGES
========================================= */

const pageNames = [
  'login',
  'dashboard',
  'register',
  'reset-password',
  'confirm-password'
];

for (const name of pageNames) {

  server.get(
    `/pages/${name}`,
    (_req, res) => {

      return res.sendFile(
        path.join(
          PAGES_DIR,
          `${name}.html`
        )
      );
    }
  );

}

/* =========================================
   STATIC /PAGES
========================================= */

server.use(
  '/pages',
  express.static(
    PAGES_DIR,
    {
      index: false
    }
  )
);

/* =========================================
   STATIC ROOT
========================================= */

server.use(
  express.static(
    __dirname,
    {
      index: false
    }
  )
);

/* =========================================
   404
========================================= */

server.use(
  (req, res) => {

    console.log(
      '[404]',
      req.method,
      req.originalUrl
    );

    return res.status(404).send(
      'Not Found'
    );
  }
);

/* =========================================
   EXPORT
========================================= */

export default server;