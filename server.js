import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import helmet from 'helmet';
import cors from 'cors';
import webtopupbussidHandler from './api/webtopupbussid.js';
import authHandler from './api/auth.js';
import userHandler from './api/user.js';
import adminHandler from './api/admin.js';
import adminRegisterHandler from './api/admin-register.js';
import rvnstoreHandler from './api/rvnstore.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const server = express();
const PAGES_DIR = path.join(__dirname, 'pages');

server.disable('x-powered-by');
server.set('trust proxy', 1);

server.use(helmet({ contentSecurityPolicy: false }));
server.use(cors({
  origin: (origin, cb) => {
    const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
    if (!origin || !allowed.length || allowed.includes(origin)) cb(null, true);
    else cb(new Error('Not allowed'));
  },
  credentials: true
}));

server.use(express.json({ limit: '10kb', strict: true }));
server.use(express.urlencoded({ extended: false, limit: '10kb' }));

function wrap(handler) {
  return async (req, res) => {
    try { return await handler(req, res); }
    catch (e) {
      console.error('[ERR]', req.method, req.originalUrl, e?.stack || e?.message || e);
      if (!res.headersSent) return res.status(500).json({ success: false, message: 'Internal server error' });
    }
  };
}

server.all('/api/webtopupbussid', wrap(webtopupbussidHandler));
server.all('/api/webtopup', wrap(webtopupbussidHandler));
server.all('/api/auth', wrap(authHandler));
server.all('/api/user', wrap(userHandler));
server.all('/api/admin', wrap(adminHandler));
server.all('/api/admin-register', wrap(adminRegisterHandler));
server.all('/api/rvnstore', wrap(rvnstoreHandler));

server.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
server.get(['/admin', '/admin/'], (_req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
server.get(['/admin/register', '/admin/register/'], (_req, res) => res.sendFile(path.join(__dirname, 'admin-register.html')));

server.get('/pages/login', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
for (const name of ['dashboard', 'register', 'reset-password', 'confirm-password']) {
  server.get('/pages/' + name, (_req, res) => res.sendFile(path.join(PAGES_DIR, name + '.html')));
}

server.use('/pages', express.static(PAGES_DIR, { index: false }));
server.use(express.static(__dirname, { index: false }));
server.use((req, res) => res.status(404).send('Not Found'));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server ready on http://localhost:${PORT}`));

export default server;