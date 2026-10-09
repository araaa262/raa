/**
 * app.js
 * Creator: xDonzCode
 * Type: CommonJs
 * Mode: AM Send & Verify (Direct from Core)
 *
 * Usage:
 *   node app.js              → normal mode
 *   node app.js mc true      → maintenance ON
 *   node app.js mc false     → maintenance OFF
 */

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '20kb' }));

// Google Search Console HTML file verification (must be reachable at the domain root).
app.get('/google53ad5cb1fed4e5e3.html', (req, res) => {
  res.status(200).type('text/plain').send('google-site-verification: google53ad5cb1fed4e5e3.html');
});

// Basic API abuse protection backed by Upstash (per IP and endpoint).
// This slows automated bulk requests; it cannot hide code already sent to a browser.
const apiLimits = new Map();
async function rateLimit(req, res, next) {
  if (!['/api/send-link', '/api/verify-link'].includes(req.path)) return next();
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').toString().split(',')[0].trim().slice(0, 80);
  const route = req.path.replace(/[^a-z0-9]/gi, '_');
  const key = `xra:ratelimit:${route}:${crypto.createHash('sha256').update(ip).digest('hex').slice(0, 24)}`;
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  try {
    if (url && token) {
      const base = url.replace(/\/+$/, '');
      const headers = { Authorization: `Bearer ${token}` };
      const r = await fetch(`${base}/incr/${encodeURIComponent(key)}`, { headers, cache: 'no-store' });
      if (!r.ok) throw new Error('rate-limit store unavailable');
      const data = await r.json();
      const count = Number(data.result || 0);
      if (count === 1) await fetch(`${base}/expire/${encodeURIComponent(key)}/60`, { headers, cache: 'no-store' });
      const limit = req.path === '/api/send-link' ? 5 : 10;
      if (count > limit) return res.status(429).json({ success: false, error: 'Terlalu banyak permintaan. Coba lagi dalam satu menit.' });
    } else {
      const now = Date.now();
      const old = apiLimits.get(key);
      const count = !old || now - old.start > 60000 ? 1 : old.count + 1;
      apiLimits.set(key, { start: !old || now - old.start > 60000 ? now : old.start, count });
      if (count > (req.path === '/api/send-link' ? 5 : 10)) return res.status(429).json({ success: false, error: 'Terlalu banyak permintaan. Coba lagi dalam satu menit.' });
    }
  } catch (e) {
    // If the limiter is down, use the local fallback above instead of blocking all users.
    const now = Date.now(), old = apiLimits.get(key);
    const count = !old || now - old.start > 60000 ? 1 : old.count + 1;
    apiLimits.set(key, { start: !old || now - old.start > 60000 ? now : old.start, count });
    if (count > 5) return res.status(429).json({ success: false, error: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  }
  next();
}
app.use(rateLimit);

function verifyAdminCookie(req) {
  const secret = process.env.ADMIN_PASSWORD;
  const token = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('xra_maintenance_admin='))?.split('=').slice(1).join('=');
  if (!secret || !token) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  if (expected.length !== signature.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}

app.use(async (req, res, next) => {
  if (req.path === '/api/maintenance' || req.path === '/admin.html' || req.path === '/maintenance.html' || req.path.startsWith('/api/')) return next();
  if (verifyAdminCookie(req)) return next();
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return next();
  try {
    const response = await fetch(`${url}/get/xra%3Amaintenance`, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' });
    const data = await response.json();
    if (data.result === 'true') return res.status(503).sendFile(path.join(__dirname, 'public', 'maintenance.html'));
  } catch (error) { /* fail open jika penyimpanan sementara tidak tersedia */ }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

const cfg = {
  key: 'AIzaSyDtG1AU22ErnQD60AzBAcaknySiz9_CEq0',
  idt: 'https://www.googleapis.com/identitytoolkit/v3/relyingparty',
  vfy: 'https://us-central1-alight-creative.cloudfunctions.net/verifyPurchase'
};

const dip = () => [
  crypto.randomInt(1, 255),
  crypto.randomInt(0, 255),
  crypto.randomInt(0, 255),
  crypto.randomInt(1, 255)
].join('.');

const sp = h => ({
  ...h,
  'x-forwarded-for': dip(),
  'x-real-ip': dip(),
  'client-ip': dip(),
  'x-client-ip': dip(),
  'x-originating-ip': dip(),
  'x-cluster-client-ip': dip()
});

const h1 = {
  'content-type': 'application/json',
  'x-android-package': 'com.alightcreative.motion',
  'x-android-cert': 'ECA6BF91B8715A6F810ED0BBFC65B6CD578F52A8',
  'user-agent': 'dalvik/2.1.0 (linux; u; android 15; 23127pn0cc build/bp1a.250505.005)'
};

const h2 = {
  'content-type': 'application/json; charset=utf-8',
  'user-agent': 'okhttp/3.12.1',
  'accept-encoding': 'gzip'
};

const bad = e => {
  const d = e.response?.data;
  return d ? (typeof d === 'object' ? JSON.stringify(d) : String(d)) : e.message;
};

const genOrderId = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let r = '';
  for (let i = 0; i < 10; i++) r += chars[crypto.randomInt(0, chars.length)];
  return `XDONZCODE-APIS-${r}`;
};

function extractCode(raw) {
  if (!raw) return null;
  let s = String(raw).replace(/&/g, '&');
  try { s = decodeURIComponent(s); } catch {}

  try {
    const u = new URL(s);
    let c = u.searchParams.get('oobCode');
    if (!c) {
      const n = u.searchParams.get('link') || u.searchParams.get('q') || u.searchParams.get('url');
      if (n) {
        try { c = new URL(n).searchParams.get('oobCode'); } catch {}
      }
    }
    if (c) return c.replace(/[^a-zA-Z0-9_-]/g, '');
  } catch {}

  const m = s.match(/oobCode=([a-zA-Z0-9_-]+)/i);
  if (m) return m[1];

  const t = raw.trim();
  if (/^[a-zA-Z0-9_-]{10,}$/.test(t) && !t.includes('://')) return t;
  return null;
}

async function sendMagicLink(email) {
  const c1 = { identifier: email, continueUri: 'http://localhost' };
  const c2 = {
    requestType: 6,
    email: email,
    androidInstallApp: true,
    canHandleCodeInApp: true,
    continueUrl: 'https://alightcreative.com?ui_sid=0366624874&ui_sd=0',
    iosBundleId: 'com.alightcreative.motion',
    androidPackageName: 'com.alightcreative.motion',
    androidMinimumVersion: '585',
    clientType: 'CLIENT_TYPE_ANDROID'
  };
  try {
    await axios.post(`${cfg.idt}/createAuthUri?key=${cfg.key}`, c1, { headers: sp(h1) });
    const r = await axios.post(`${cfg.idt}/getOobConfirmationCode?key=${cfg.key}`, c2, { headers: sp(h1) });
    return { ok: true, r: r.data };
  } catch (e) {
    return { ok: false, why: bad(e) };
  }
}

async function auth(email, raw) {
  const c = extractCode(raw);
  if (!c) return { ok: false, why: 'Code tidak ditemukan' };
  try {
    const a = await axios.post(`${cfg.idt}/emailLinkSignin?key=${cfg.key}`, {
      email: email,
      oobCode: c,
      clientType: 'CLIENT_TYPE_ANDROID'
    }, { headers: sp(h1) });
    return {
      ok: true,
      email,
      id: a.data.idToken,
      ref: a.data.refreshToken,
      uid: a.data.localId,
      baru: !!a.data.isNewUser
    };
  } catch (e) {
    return { ok: false, why: bad(e) };
  }
}

async function pro(id) {
  const orderId = genOrderId();
  const b = {
    data: {
      productId: 'am.full.sub.annual.19q4',
      token: 'mmgaobamlahbbeccfplmbkbb.AO-J1OzqG0or_GJJIx-ms8GrTm-jaglCRfhQSRPUZKpl2YspYS-oN7_94uv8RC5vQbvd_Ios2pPDStZ2n7F0hLE3FiOU7HS3R6Fquulv5xLXFECSv4ctElw',
      skuType: 'subs',
      orderId
    }
  };
  const h = {
    ...h2,
    authorization: 'Bearer ' + id,
    'firebase-instance-id-token': 'cSDnCyp3T-uwp07z3tL86T:APA91bFkmvvsHw5nnqa1SBFci-99DRsKClLiETdRrVcJjS5yBx1v_FbCb1d8WhBuea_zmwnYBktyTIzcRhN4b6uNOUur9wPc0gKXmJDoZic0LhNq5V2s0xI'
  };
  try {
    const r = await axios.post(cfg.vfy, b, { headers: sp(h) });
    return { ok: true, order: orderId, r: r.data };
  } catch (e) {
    return { ok: false, why: bad(e) };
  }
}

// ==========================================
// ENDPOINT: /api/send-link
// ==========================================
app.post('/api/send-link', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'Email wajib diisi' });
  }
  if (!email.includes('@') || !email.includes('.')) {
    return res.status(400).json({ success: false, error: 'Format email tidak valid' });
  }

  try {
    const r = await sendMagicLink(email);
    if (!r.ok) {
      return res.status(500).json({ success: false, error: 'Gagal mengirim link', message: r.why });
    }

    return res.json({
      success: true,
      message: 'Magic link berhasil dikirim, silahkan cek inbox',
      email
    });
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/verify-link', async (req, res) => {
  const { email, magicLink } = req.body;

  if (!email || !magicLink) {
    return res.status(400).json({
      success: false,
      error: 'Email dan magic link wajib diisi'
    });
  }

  try {
    const v = await auth(email, magicLink);
    if (!v.ok) {
      return res.status(500).json({
        success: false,
        error: 'Verifikasi gagal',
        message: v.why
      });
    }

    const q = await pro(v.id);
    if (!q.ok) {
      return res.status(500).json({
        success: false,
        error: 'Promote premium gagal',
        message: q.why,
        uid: v.uid
      });
    }

    return res.json({
      success: true,
      message: 'Verifikasi berhasil & premium aktif',
      email,
      uid: v.uid,
      orderId: q.order,
      tier: 'Premium',
      validUntil: '1 Tahun',
      isNewUser: v.baru
    });

  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    service: 'xDonzAm Send & Verify',
    creator: 'xDonzCode',
    maintenance: undefined,
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`Server berjalan di http://localhost:${PORT}`));
}

module.exports = app;