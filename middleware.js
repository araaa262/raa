const COOKIE_NAME = "xra_browser_check";
const COOKIE_TTL = 60 * 60 * 4;

const BLOCKED_UA =
  /(httrack|wget|curl|python-requests|scrapy|aiohttp|webcopier|site.?sucker|teleport|webzip|phantomjs)/i;

const TRUSTED_BOTS =
  /(googlebot|bingbot|duckduckbot|facebookexternalhit|twitterbot|telegrambot|discordbot|whatsapp)/i;

export const config = {
  matcher: [
    "/((?!_vercel|favicon.ico|robots.txt).*)",
};

function denyBot() {
  const html = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Akses Tidak Tersedia</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font:16px system-ui;background:linear-gradient(135deg,#edf6ff,#d9eaff);color:#243b5a}
main{max-width:420px;padding:36px 28px;text-align:center;background:#ffffffb8;border:1px solid white;border-radius:28px;box-shadow:0 24px 70px #528bd526;backdrop-filter:blur(20px)}
.icon{width:68px;height:68px;margin:0 auto 22px;display:grid;place-items:center;background:#e3efff;color:#3478ec;border-radius:22px;font-size:30px}
h1{font-size:26px;letter-spacing:-.8px}
p{color:#7487a3;line-height:1.8;font-size:14px}
small{color:#8b9db5}
</style>
</head>
<body>
<main>
<div class="icon">🔒</div>
<h1>Akses tidak tersedia</h1>
<p>Permintaan ini tidak dapat diproses. Silakan gunakan browser biasa untuk mengakses website.</p>
<small>Browser Security</small>
</main>
</body>
</html>`;

  return new Response(html, {
    status: 403,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

function makeChallenge() {
  const html = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#eaf4ff">
<title>Memeriksa Browser</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--blue:#438cff;--text:#243b5a;--muted:#7487a3}
body{min-height:100vh;overflow:hidden;display:grid;place-items:center;padding:24px;color:var(--text);font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 15% 15%,#fff 0%,transparent 38%),radial-gradient(ellipse at 90% 85%,#b9d9ff 0%,transparent 40%),linear-gradient(135deg,#edf6ff,#d9eaff 55%,#eff8ff)}
.orb{position:fixed;width:280px;height:280px;border-radius:50%;background:linear-gradient(135deg,#ffffff99,#78b5ff30);filter:blur(2px);animation:float 9s ease-in-out infinite;pointer-events:none}
.one{top:-110px;left:-80px}
.two{width:220px;height:220px;right:-60px;bottom:-60px;animation-delay:-4s}
.card{position:relative;width:min(100%,430px);padding:38px 30px 28px;text-align:center;border:1px solid #ffffffd9;border-radius:30px;background:#ffffffa8;box-shadow:0 24px 80px #528bd51c,inset 0 1px 0 #fff;backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);animation:appear .7s cubic-bezier(.2,.8,.2,1) both}
.icon-box{display:grid;place-items:center;width:78px;height:78px;margin:0 auto 25px;border:1px solid #fff;border-radius:25px;color:#fff;background:linear-gradient(145deg,#71b5ff,#377af5);box-shadow:0 12px 28px #438cff40;animation:bob 3s ease-in-out infinite}
.icon-box svg{width:38px;height:38px}
.eyebrow{display:inline-flex;align-items:center;gap:8px;padding:7px 12px;margin-bottom:17px;border:1px solid #d8e9ff;border-radius:999px;color:#3976d8;background:#edf6ff;font-size:11px;font-weight:800;letter-spacing:1.4px;text-transform:uppercase}
.pulse{width:7px;height:7px;border-radius:50%;background:#438cff;box-shadow:0 0 0 4px #438cff20;animation:pulse 1.6s infinite}
h1{margin-bottom:13px;font-size:clamp(25px,6vw,32px);font-weight:800;letter-spacing:-1.2px}
.description{max-width:320px;margin:0 auto;color:var(--muted);font-size:14px;line-height:1.8}
.progress{height:6px;overflow:hidden;margin:29px 0 13px;border-radius:99px;background:#dceaff}
.progress span{display:block;width:38%;height:100%;border-radius:inherit;background:linear-gradient(90deg,#8dc6ff,#367af5);animation:loading 2.1s ease-in-out infinite}
.status{display:flex;align-items:center;justify-content:center;gap:8px;color:#6380a4;font-size:12px;font-weight:600}
.status svg{width:15px;height:15px}
.footer{margin-top:28px;padding-top:18px;border-top:1px solid #dce9f7;color:#8b9db5;font-size:11px}
@keyframes appear{from{opacity:0;transform:translateY(18px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-24px)}}
@keyframes bob{0%,100%{transform:translateY(0) rotate(0)}50%{transform:translateY(-5px) rotate(2deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
@keyframes loading{0%{transform:translateX(-110%)}100%{transform:translateX(290%)}}
@media(max-width:420px){.card{padding:32px 22px 24px;border-radius:25px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important}}
</style>
</head>
<body>
<div class="orb one"></div>
<div class="orb two"></div>
<main class="card">
<div class="icon-box">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<path d="M12 3 19 6v5c0 4.7-3 8-7 10-4-2-7-5.3-7-10V6l7-3Z"/>
<path d="m9 12 2 2 4-4"/>
</svg>
</div>
<div class="eyebrow"><span class="pulse"></span>Browser Security</div>
<h1>Halo, sebentar ya!</h1>
<p class="description">Kami sedang memeriksa browser kamu untuk memastikan koneksi aman sebelum melanjutkan ke website.</p>
<div class="progress"><span></span></div>
<div class="status">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
Pemeriksaan otomatis sedang berjalan
</div>
<div class="footer">Secure connection · Browser verification</div>
</main>
<script>
(() => {
  const name = ${JSON.stringify(COOKIE_NAME)};
  const value = document.cookie.split("; ").find(v => v.startsWith(name + "="));
  if (!value) {
    document.cookie = name + "=1; Path=/; Max-Age=${COOKIE_TTL}; SameSite=Lax" +
      (location.protocol === "https:" ? "; Secure" : "");
    location.reload();
  } else {
    location.reload();
  }
})();
</script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

export default function middleware(request) {
  const ua = request.headers.get("user-agent") || "";
  const url = new URL(request.url);
  const cookie = request.headers.get("cookie") || "";
  const accept = request.headers.get("accept") || "";

  if (!ua || BLOCKED_UA.test(ua)) {
    return denyBot();
  }

  if (TRUSTED_BOTS.test(ua)) {
    return denyBot();
  }

  if (cookie.includes(COOKIE_NAME + "=1")) {
    return;
  }

  if (request.method === "GET" && accept.includes("text/html")) {
    return makeChallenge();
  }

  return denyBot();
}