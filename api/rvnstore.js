const TARGET = process.env.PLAYFAB_API_URL;
if (!TARGET) throw new Error('url is not configured');
const ALLOWED_ENDPOINTS = new Set([
  '/Client/LoginWithAndroidDeviceID',
  '/Client/GetPlayerCombinedInfo',
  '/Client/ExecuteCloudScript',
  '/Client/UpdateUserTitleDisplayName'
]);

const rateMap = new Map();
function allowedRate(ip) {
  const now=Date.now(); const row=rateMap.get(ip)||[]; const fresh=row.filter(t=>now-t<60000);
  if(fresh.length>=30){rateMap.set(ip,fresh);return false;} fresh.push(now); rateMap.set(ip,fresh); return true;
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
  return allowed.includes(origin);
}

export default async function handler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');
  if (!sameOrigin(req)) return res.status(403).json({ error: 'Origin tidak diizinkan' });
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

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
    if (typeof authToken !== 'string' || authToken.length < 10 || authToken.length > 4096) {
      return res.status(401).json({ error: 'PlayFab session tidak valid' });
    }

    const response = await fetch(TARGET + endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Authorization': authToken },
      body: JSON.stringify(body || {})
    });
    const text = await response.text();
    let result;
    try { result = JSON.parse(text); } catch { result = { error: 'Invalid upstream response' }; }
    return res.status(response.status).json(result);
  } catch (error) {
    console.error('topupbussid error:', error.message);
    return res.status(502).json({ error: 'Upstream service unavailable' });
  }
}
