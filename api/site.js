const crypto = require('crypto');
const path = require('path');
const app = require('../app');

function isAdmin(req) {
  const secret = process.env.ADMIN_PASSWORD;
  if (!secret) return false;
  const token = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('xra_maintenance_admin='))?.split('=').slice(1).join('=');
  if (!token) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  const a = Buffer.from(expected), b = Buffer.from(signature);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}

async function maintenanceEnabled() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return false;
  const r = await fetch(`${url.replace(/\/+$/, '')}/get/xra%3Amaintenance`, {
    headers: { Authorization: `Bearer ${token}` }, cache: 'no-store'
  });
  if (!r.ok) throw new Error('Redis unavailable');
  const data = await r.json();
  return data.result === 'true';
}

module.exports = async (req, res) => {
  const raw = req.query.path;
  let pathname = '/' + (Array.isArray(raw) ? raw.join('/') : (raw || ''));
  pathname = pathname.split('?')[0];
  if (pathname === '//') pathname = '/';
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');

  // Jangan pernah menutup dashboard, halaman maintenance, atau API status.
  if (pathname === '/admin.html' || pathname === '/maintenance.html' || pathname === '/api/maintenance' || pathname.startsWith('/api/')) {
    req.url = pathname;
    return app(req, res);
  }

  try {
    if (!isAdmin(req) && await maintenanceEnabled()) {
      res.setHeader('Retry-After', '300');
      return res.status(503).sendFile(path.join(__dirname, '..', 'public', 'maintenance.html'));
    }
  } catch (e) {
    // Redis gagal: website tetap dapat dibuka, tidak membuat seluruh situs down.
  }
  req.url = pathname;
  return app(req, res);
};
