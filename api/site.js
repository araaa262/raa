const crypto = require('crypto');
const path = require('path');
const app = require('../app');

function isAdmin(req) {
  const secret = process.env.ADMIN_PASSWORD;
  if (!secret) return false;
  const token = (req.headers.cookie || '').split(';').map(v => v.trim())
    .find(v => v.startsWith('xra_maintenance_admin='))
    ?.split('=').slice(1).join('=');
  if (!token) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  const a = Buffer.from(expected), b = Buffer.from(signature);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now(); }
  catch { return false; }
}

async function getMaintenanceState() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return false;
  const response = await fetch(`${url.replace(/\/+$/, '')}/get/xra%3Amaintenance`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store'
  });
  if (!response.ok) throw new Error('Upstash Redis request failed');
  const data = await response.json();
  return data.result === 'true';
}

module.exports = async (req, res) => {
  const rawPath = req.query.path;
  const requestedPath = `/${Array.isArray(rawPath) ? rawPath.join('/') : (rawPath || '')}`;
  const pathname = requestedPath.split('?')[0];

  if (pathname === '/admin.html' || pathname === '/maintenance.html' ||
      pathname === '/api/maintenance' || pathname.startsWith('/api/')) {
    req.url = requestedPath;
    return app(req, res);
  }

  try {
    if (!isAdmin(req) && await getMaintenanceState()) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.setHeader('Retry-After', '300');
      return res.status(503).sendFile(path.join(__dirname, '..', 'public', 'maintenance.html'));
    }
  } catch (error) {
    // Redis outage: keep the site reachable.
  }

  req.url = requestedPath;
  return app(req, res);
};
