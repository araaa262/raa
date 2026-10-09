const crypto = require('crypto');

const redis = async (command, key, value) => {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error('Upstash Redis belum dikonfigurasi di Vercel.');
  const path = value === undefined ? `${command}/${encodeURIComponent(key)}` : `${command}/${encodeURIComponent(key)}/${encodeURIComponent(value)}`;
  const response = await fetch(`${url}/${path}`, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' });
  if (!response.ok) throw new Error('Gagal mengakses penyimpanan maintenance.');
  return response.json();
};

function sign(payload) {
  return crypto.createHmac('sha256', process.env.ADMIN_PASSWORD).update(payload).digest('base64url');
}
function cookieToken() {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + 1000 * 60 * 60 * 12 })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}
function isAdmin(req) {
  const token = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('xra_maintenance_admin='))?.split('=').slice(1).join('=');
  if (!token || !process.env.ADMIN_PASSWORD) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature || sign(payload) !== signature) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method === 'GET' && req.query.public === '1') {
    try {
      const result = await redis('get', 'xra:maintenance');
      return res.status(200).json({ maintenance: result.result === 'true' });
    } catch (e) { return res.status(503).json({ error: e.message }); }
  }
  if (req.method === 'POST') {
    const { action, password, enabled } = req.body || {};
    if (action === 'login') {
      if (!process.env.ADMIN_PASSWORD) return res.status(500).json({ error: 'ADMIN_PASSWORD belum diatur di Vercel.' });
      if (typeof password !== 'string' || password.length < 1 || password !== process.env.ADMIN_PASSWORD) return res.status(401).json({ error: 'Password admin salah.' });
      res.setHeader('Set-Cookie', `xra_maintenance_admin=${cookieToken()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`);
      return res.status(200).json({ success: true });
    }
    if (action === 'logout') {
      res.setHeader('Set-Cookie', 'xra_maintenance_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
      return res.status(200).json({ success: true });
    }
    if (!isAdmin(req)) return res.status(401).json({ error: 'Silakan login sebagai admin terlebih dahulu.' });
    if (action === 'status') {
      try { const result = await redis('get', 'xra:maintenance'); return res.status(200).json({ success: true, maintenance: result.result === 'true' }); }
      catch (e) { return res.status(503).json({ error: e.message }); }
    }
    if (action === 'toggle' && typeof enabled === 'boolean') {
      try { await redis('set', 'xra:maintenance', String(enabled)); return res.status(200).json({ success: true, maintenance: enabled }); }
      catch (e) { return res.status(503).json({ error: e.message }); }
    }
  }
  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method tidak diizinkan.' });
};
