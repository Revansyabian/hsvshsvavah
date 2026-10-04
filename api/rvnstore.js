const TARGET = process.env.PLAYFAB_API_URL || '';

const ALLOWED_ENDPOINTS = new Set([
  '/Client/LoginWithAndroidDeviceID',
  '/Client/GetPlayerCombinedInfo',
  '/Client/ExecuteCloudScript',
  '/Client/UpdateUserTitleDisplayName'
]);

const rateMap = new Map();
function allowedRate(ip) {
  const now = Date.now();
  const row = rateMap.get(ip) || [];
  const fresh = row.filter(t => now - t < 60000);
  if (fresh.length >= 60) { rateMap.set(ip, fresh); return false; }
  fresh.push(now);
  rateMap.set(ip, fresh);
  return true;
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
  if (!allowed.length) return true;
  return allowed.includes(origin);
}

export default async function handler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!sameOrigin(req)) return res.status(403).json({ error: 'Origin tidak diizinkan' });

  if (!TARGET) {
    console.error('[rvnstore] PLAYFAB_API_URL tidak di-set');
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  const origin = req.headers.origin;
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }

  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  if (!allowedRate(ip)) return res.status(429).json({ error: 'Too many requests' });

  try {
    const { endpoint, method, body, authToken } = req.body || {};
    if (!ALLOWED_ENDPOINTS.has(endpoint)) return res.status(403).json({ error: 'Endpoint tidak diizinkan' });
    if ((method || 'POST') !== 'POST') return res.status(405).json({ error: 'Only POST is allowed' });

    const isLoginEndpoint = endpoint === '/Client/LoginWithAndroidDeviceID';

    if (!isLoginEndpoint) {
      if (typeof authToken !== 'string' || authToken.length < 10 || authToken.length > 4096) {
        return res.status(401).json({ error: 'PlayFab session tidak valid' });
      }
    }

    const upstreamHeaders = { 'Content-Type': 'application/json' };
    if (!isLoginEndpoint && authToken) {
      upstreamHeaders['X-Authorization'] = authToken;
    }

    const response = await fetch(TARGET + endpoint, {
      method: 'POST',
      headers: upstreamHeaders,
      body: JSON.stringify(body || {})
    });
    const text = await response.text();
    let result;
    try { result = JSON.parse(text); } catch { result = { error: 'Invalid upstream response' }; }
    return res.status(response.status).json(result);
  } catch (error) {
    console.error('rvnstore error:', error.message);
    return res.status(502).json({ error: 'Upstream service unavailable' });
  }
}