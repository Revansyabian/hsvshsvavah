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

server.disable('x-powered-by');
server.set('trust proxy', 1);

/* =========================================
   BODY PARSER
========================================= */

server.use(express.json({
  limit: '200kb',
  strict: true
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
      'Vary',
      'Origin'
    );
  }

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, X-Requested-With, X-Fingerprint, X-Client-Key'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,DELETE,OPTIONS'
  );

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  next();
});

/* =========================================
   GET ORIGINAL API PATH
========================================= */

function getOriginalPath(req) {
  const url = String(req.originalUrl || '');

  const questionIndex = url.indexOf('?');

  if (questionIndex >= 0) {
    return url.slice(0, questionIndex);
  }

  return url;
}

/* =========================================
   ENCRYPTION EXEMPTIONS
========================================= */

function isExempt(req) {
  const originalPath = getOriginalPath(req);

  /*
   * RVNStore tetap terpisah.
   */
  if (originalPath === '/api/rvnstore') {
    return true;
  }

  /*
   * Admin API mengurus transport encryption
   * sendiri di api/admin.js.
   *
   * Karena middleware dipasang pada /api,
   * jangan mengecek req.path === /api/admin.
   */
  if (originalPath === '/api/admin') {
    return true;
  }

  /*
   * WebTopup public key.
   *
   * Request pertama memang belum mempunyai
   * X-Client-Key, karena browser sedang meminta
   * public key server.
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
   ENCRYPTED WEBTOPUP TRANSPORT
========================================= */

function encryptedTransport(req, res, next) {
  if (isExempt(req)) {
    return next();
  }

  const clientKey = req.headers['x-client-key'];

  /*
   * Request WebTopup harus encrypted.
   */
  if (
    req.body &&
    typeof req.body === 'object' &&
    Object.keys(req.body).length > 0
  ) {
    try {
      req.body = decryptRequest(req.body);
    } catch (error) {
      console.error(
        'Decrypt request error:',
        error?.message || error
      );

      return res.status(400).json({
        error: 'Encrypted request tidak valid'
      });
    }
  }

  if (!clientKey) {
    return res.status(400).json({
      error: 'Client public key diperlukan'
    });
  }

  /*
   * Simpan res.json asli.
   */
  const originalJson = res.json.bind(res);

  /*
   * Encrypt setiap response WebTopup.
   */
  res.json = (body) => {
    try {
      /*
       * Kalau handler lama sudah menghasilkan
       * envelope encrypted, jangan encrypt dua kali.
       */
      if (
        body &&
        typeof body === 'object' &&
        body.data &&
        typeof body.data === 'object' &&
        body.data.v === 1 &&
        body.data.alg === 'RSA-OAEP-256/AES-256-GCM'
      ) {
        return originalJson(body.data);
      }

      return originalJson(
        encryptResponse(body, clientKey)
      );
    } catch (error) {
      console.error(
        'Encrypt response error:',
        error?.message || error
      );

      if (!res.headersSent) {
        return originalJson({
          error: 'Gagal mengenkripsi response'
        });
      }

      return res;
    }
  };

  next();
}

/*
 * Hanya WebTopup yang menggunakan middleware
 * encrypted transport ini.
 *
 * Admin dan RVNStore tidak dilewatkan ke sini.
 */
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
      return await webtopupbussid(req, res);
    } catch (error) {
      console.error(
        'WEBTOPUP ERROR:',
        error?.stack || error?.message || error
      );

      if (!res.headersSent) {
        return res.status(500).json({
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
      return await webtopupbussid(req, res);
    } catch (error) {
      console.error(
        'WEBTOPUP BUSSID ERROR:',
        error?.stack || error?.message || error
      );

      if (!res.headersSent) {
        return res.status(500).json({
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
      return await rvnstore(req, res);
    } catch (error) {
      console.error(
        'RVNSTORE ERROR:',
        error?.stack || error?.message || error
      );

      if (!res.headersSent) {
        return res.status(500).json({
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
      return await adminHandler(req, res);
    } catch (error) {
      console.error(
        'ADMIN API ERROR:',
        error?.stack || error?.message || error
      );

      if (!res.headersSent) {
        return res.status(500).json({
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
    res.sendFile(
      path.join(__dirname, 'index.html')
    );
  }
);

/* =========================================
   ADMIN PANEL
========================================= */

server.get(
  '/admin',
  (_req, res) => {
    res.sendFile(
      path.join(__dirname, 'admin.html')
    );
  }
);

server.get(
  '/admin/',
  (_req, res) => {
    res.sendFile(
      path.join(__dirname, 'admin.html')
    );
  }
);

/* =========================================
   ADMIN REGISTER
========================================= */

server.get(
  '/admin/register',
  (_req, res) => {
    res.sendFile(
      path.join(__dirname, 'admin-register.html')
    );
  }
);

server.get(
  '/admin/register/',
  (_req, res) => {
    res.sendFile(
      path.join(__dirname, 'admin-register.html')
    );
  }
);

/* =========================================
   PAGES
========================================= */

for (
  const name of [
    'login',
    'dashboard',
    'register',
    'reset-password',
    'confirm-password'
  ]
) {
  server.get(
    `/pages/${name}`,
    (_req, res) => {
      res.sendFile(
        path.join(
          PAGES_DIR,
          `${name}.html`
        )
      );
    }
  );
}

/* =========================================
   STATIC PAGES
========================================= */

server.use(
  '/pages',
  express.static(PAGES_DIR, {
    index: false
  })
);

/*
 * Static file harus setelah route khusus
 * supaya /admin tidak tertabrak.
 */
server.use(
  express.static(__dirname, {
    index: false
  })
);

/* =========================================
   404
========================================= */

server.use(
  (_req, res) => {
    res.status(404).send('Not Found');
  }
);

/* =========================================
   EXPORT
========================================= */

export default server;