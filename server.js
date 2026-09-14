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

server.use(express.json({
  limit: '200kb',
  strict: true
}));

server.use(express.urlencoded({
  extended: false,
  limit: '20kb'
}));

/* =========================
   CORS
========================= */

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);

server.use((req, res, next) => {
  const origin = req.headers.origin;

  if (
    origin &&
    allowedOrigins.length &&
    !allowedOrigins.includes(origin)
  ) {
    return res.status(403).json({
      error: 'Origin tidak diizinkan'
    });
  }

  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader(
      'Access-Control-Allow-Credentials',
      'true'
    );
    res.setHeader('Vary', 'Origin');
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

/* =========================
   ENCRYPTED TRANSPORT
========================= */

function isExempt(req) {
  const p = req.path;

  // RVNStore tetap tidak menggunakan
  // encrypted transport dari middleware ini.
  if (p === '/api/rvnstore') {
    return true;
  }

  // Admin mempunyai transport encryption sendiri
  // di api/admin.js.
  if (p === '/api/admin') {
    return true;
  }

  // Endpoint public untuk mengambil public key.
  if (
    (p === '/api/webtopup' ||
      p === '/api/webtopupbussid') &&
    req.query.action === 'key'
  ) {
    return true;
  }

  return false;
}

function encryptedTransport(req, res, next) {
  if (isExempt(req)) {
    return next();
  }

  const clientKey = req.headers['x-client-key'];

  if (req.body && Object.keys(req.body).length) {
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

  const originalJson = res.json.bind(res);

  res.json = (body) => {
    try {
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
    }
  };

  next();
}

server.use('/api', encryptedTransport);

/* =========================
   WEB TOP UP
========================= */

server.all(
  '/api/webtopupbussid',
  async (req, res) => {
    try {
      return await webtopupbussid(req, res);
    } catch (error) {
      console.error(
        'WEBTOPUP ERROR:',
        error?.stack || error
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
  '/api/webtopup',
  async (req, res) => {
    try {
      return await webtopupbussid(req, res);
    } catch (error) {
      console.error(
        'WEBTOPUP ERROR:',
        error?.stack || error
      );

      if (!res.headersSent) {
        return res.status(500).json({
          error: 'Internal server error'
        });
      }
    }
  }
);

/* =========================
   RVNSTORE
========================= */

server.all(
  '/api/rvnstore',
  async (req, res) => {
    try {
      return await rvnstore(req, res);
    } catch (error) {
      console.error(
        'RVNSTORE ERROR:',
        error?.stack || error
      );

      if (!res.headersSent) {
        return res.status(500).json({
          error: 'Internal server error'
        });
      }
    }
  }
);

/* =========================
   ADMIN API
========================= */

server.all(
  '/api/admin',
  async (req, res) => {
    try {
      return await adminHandler(req, res);
    } catch (error) {
      console.error(
        'ADMIN API ERROR:',
        error?.stack || error
      );

      if (!res.headersSent) {
        return res.status(500).json({
          error: 'Internal server error'
        });
      }
    }
  }
);

/* =========================
   MAIN WEBSITE
========================= */

server.get(
  '/',
  (_req, res) => {
    res.sendFile(
      path.join(__dirname, 'index.html')
    );
  }
);

/* =========================
   ADMIN PANEL
========================= */

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

/* =========================
   PAGES
========================= */

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

/* =========================
   STATIC FILES
========================= */

server.use(
  '/pages',
  express.static(PAGES_DIR, {
    index: false
  })
);

server.use(
  express.static(__dirname, {
    index: false
  })
);

/* =========================
   404
========================= */

server.use(
  (_req, res) => {
    res.status(404).send('Not Found');
  }
);

export default server;