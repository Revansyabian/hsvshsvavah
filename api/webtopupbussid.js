import { setSecurityHeaders, setCorsHeaders, enforceOrigin, methodGuard } from './rvns/middleware.js';
import { CONFIG } from './rvns/config.js';
import { isIPBlocked, isFPBlocked, getMaintenance, logActivity, getIP, fpOf } from './rvns/helper.js';

export default async function handler(req, res) {
  setSecurityHeaders(res);
  setCorsHeaders(req, res);
  if (!methodGuard(req, res, ['GET', 'POST'])) return;
  if (!enforceOrigin(req, res)) return;

  const action = String(req.query.action || '').toLowerCase();
  const ip = getIP(req);
  const fp = fpOf(req);

  try {
    if (action === 'check-blocked' || action === 'cek-block') {
      const [ipB, fpB] = await Promise.all([isIPBlocked(ip), isFPBlocked(fp)]);
      await logActivity('', 'check_blocked', ipB || fpB ? 'blocked' : 'clean', ip, fp);
      return res.status(200).json({
        blocked: ipB || fpB,
        ipBlocked: ipB,
        fpBlocked: fpB,
        blockType: ipB ? 'ip' : (fpB ? 'device' : null)
      });
    }

    if (action === 'maintenance-status' || action === 'cek-maintenance' || action === 'cek-maintece') {
      const m = await getMaintenance();
      await logActivity('', 'check_maintenance', m.maintenance ? 'ON' : 'OFF', ip, fp);
      return res.status(200).json(m);
    }

    if (action === 'config') {
      return res.status(200).json({
        recaptchaV2SiteKey: CONFIG.RECAPTCHA_V2_SITE_KEY,
        recaptchaV3SiteKey: CONFIG.RECAPTCHA_V3_SITE_KEY
      });
    }

    return res.status(404).json({ success: false, message: `Action tidak dikenal: ${action}` });
  } catch (e) {
    console.error('[webtopupbussid]', e?.stack || e?.message || e);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
}