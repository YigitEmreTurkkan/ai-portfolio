// Private owner dashboard: yigitemreturkkan.com/dashboard
// Password-protected (HMAC compare + signed cookie). All secrets live in Cloudflare env vars:
//   DASH_SALT, DASH_PASS_HASH, DASH_SECRET          (login)
//   CF_API_TOKEN, CF_ACCOUNT_ID                     (Web Analytics, read-only)
//   SUPABASE_URL, SUPABASE_SERVICE_KEY              (calls dashboard_stats(), numbers only)
// Nothing here is ever sent to the browser except computed results.

const SITES = [
  { name: 'Produstra', url: 'https://produstra.com', host: 'produstra.com' },
  { name: 'Hızlı Sözleşme', url: 'https://hizlisozlesme.com', host: 'hizlisozlesme.com' },
  { name: 'Poliçem AI', url: 'https://policemai.groupt4.com', host: 'policemai.groupt4.com' },
  { name: 'T4 Group', url: 'https://groupt4.com', host: 'groupt4.com' },
  { name: 'T4 Academy', url: 'https://academy.groupt4.com', host: 'academy.groupt4.com' },
  { name: 'Portfolyo', url: 'https://yigitemreturkkan.com', host: 'yigitemreturkkan.com' },
];

const COOKIE = 'dash';
const MAX_AGE = 60 * 60 * 24 * 90; // log in once; this browser stays signed in for 90 days (HttpOnly, Secure, SameSite=Strict)
const fails = new Map(); // ip -> {n, until}  (per isolate; a soft brake, not the only defence)

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
// Slow password hash (PBKDF2-SHA256, 100k rounds = Workers maximum). Salt is the DASH_SALT string itself.
async function pbkdf2(password, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function cookieOf(request) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|; )' + COOKIE + '=([^;]+)'));
  return m ? m[1] : '';
}
async function authed(request, env) {
  if (!env.DASH_SECRET) return false;
  const [exp, sig] = cookieOf(request).split('.');
  if (!exp || !sig || Number(exp) < Date.now() / 1000) return false;
  return same(sig, await hmac(env.DASH_SECRET, exp));
}

const baseHeaders = {
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Strict-Transport-Security': 'max-age=31536000',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};
const html = (body, status = 200) =>
  new Response(body, { status, headers: { ...baseHeaders, 'Content-Type': 'text/html; charset=utf-8' } });
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...baseHeaders, 'Content-Type': 'application/json' } });

// ---------- data sources (each fails on its own, never the whole page) ----------

async function health() {
  return Promise.all(
    SITES.map(async (s) => {
      const t0 = Date.now();
      try {
        const r = await fetch(s.url, { method: 'GET', redirect: 'follow', headers: { 'User-Agent': 'owner-dashboard-healthcheck' }, signal: AbortSignal.timeout(8000) });
        return { name: s.name, url: s.url, host: s.host, ok: r.ok, status: r.status, ms: Date.now() - t0 };
      } catch (e) {
        return { name: s.name, url: s.url, host: s.host, ok: false, status: 0, ms: Date.now() - t0, error: String(e.message || e) };
      }
    }),
  );
}

async function traffic(env) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { error: 'CF_API_TOKEN / CF_ACCOUNT_ID tanımlı değil' };
  const end = new Date();
  const start = new Date(end.getTime() - 7 * 86400000);
  const query = `query($acc:String!,$s:Time!,$e:Time!){viewer{accounts(filter:{accountTag:$acc}){
    rumPageloadEventsAdaptiveGroups(limit:100,filter:{datetime_geq:$s,datetime_leq:$e}){count sum{visits} dimensions{requestHost}}}}}`;
  const r = await fetch('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + env.CF_API_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables: { acc: env.CF_ACCOUNT_ID, s: start.toISOString(), e: end.toISOString() } }),
  });
  const d = await r.json();
  if (d.errors && d.errors.length) return { error: d.errors[0].message };
  const rows = d?.data?.viewer?.accounts?.[0]?.rumPageloadEventsAdaptiveGroups || [];
  const byHost = {};
  for (const x of rows) {
    const h = x.dimensions.requestHost;
    byHost[h] = byHost[h] || { views: 0, visits: 0 };
    byHost[h].views += x.count;
    byHost[h].visits += x.sum?.visits || 0;
  }
  return { days: 7, byHost };
}

async function policemai(env) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_KEY) return { error: 'SUPABASE_URL / SUPABASE_SERVICE_KEY tanımlı değil' };
  const r = await fetch(env.SUPABASE_URL.replace(/\/$/, '') + '/rest/v1/rpc/dashboard_stats', {
    method: 'POST',
    headers: { apikey: env.SUPABASE_SERVICE_KEY, Authorization: 'Bearer ' + env.SUPABASE_SERVICE_KEY, 'Content-Type': 'application/json' },
    body: '{}',
  });
  if (!r.ok) return { error: 'Supabase ' + r.status + ' (0021_dashboard_stats.sql uygulandı mı?)' };
  return r.json();
}

// ---- ChainBud: Google Analytics 4 Data API (read-only service account) ----
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
async function googleToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const body = b64u(enc.encode(JSON.stringify({ iss: env.GA4_SA_EMAIL, scope: 'https://www.googleapis.com/auth/analytics.readonly', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 })));
  const pem = env.GA4_SA_PRIVATE_KEY.replaceAll('\\n', '\n').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = b64u(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + body)));
  const { d, r } = await gjson('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + head + '.' + body + '.' + sig,
  });
  if (!d.access_token) throw new Error('Google token: ' + (d.error_description || d.error || r.status));
  gTok = { t: d.access_token, exp: Date.now() + 50 * 60 * 1000 };
  return d.access_token;
}
// Google's edge sometimes answers with an HTML error page: retry a few times before giving up.
let gTok = { t: '', exp: 0 };
async function gjson(url, init) {
  let last = '';
  for (let i = 0; i < 4; i++) {
    const r = await fetch(url, init);
    const txt = await r.text();
    try { return { d: JSON.parse(txt), r }; } catch { last = 'HTTP ' + r.status; }
    await sleep(500 * (i + 1));
  }
  throw new Error('Google yanıtı okunamadı (' + last + ')');
}
async function chainbud(env) {
  if (!env.GA4_PROPERTY_ID || !env.GA4_SA_EMAIL || !env.GA4_SA_PRIVATE_KEY) return { error: 'GA4_* tanımlı değil' };
  const token = gTok.t && gTok.exp > Date.now() ? gTok.t : await googleToken(env);
  const run = async (b) => {
    const { d, r } = await gjson('https://analyticsdata.googleapis.com/v1beta/properties/' + env.GA4_PROPERTY_ID + ':runReport', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify(b),
    });
    if (!r.ok) throw new Error('GA4 ' + r.status + ': ' + (d.error?.message || '').slice(0, 160));
    return d.rows || [];
  };
  const [users, events, countries] = await Promise.all([
    run({ dateRanges: [{ startDate: '7daysAgo', endDate: 'today' }, { startDate: '30daysAgo', endDate: 'today' }], metrics: [{ name: 'activeUsers' }, { name: 'newUsers' }, { name: 'sessions' }] }),
    run({ dateRanges: [{ startDate: '30daysAgo', endDate: 'today' }], dimensions: [{ name: 'eventName' }], metrics: [{ name: 'eventCount' }], orderBys: [{ metric: { metricName: 'eventCount' }, desc: true }], limit: 25 }),
    run({ dateRanges: [{ startDate: '30daysAgo', endDate: 'today' }], dimensions: [{ name: 'country' }], metrics: [{ name: 'activeUsers' }], orderBys: [{ metric: { metricName: 'activeUsers' }, desc: true }], limit: 5 }),
  ]);
  const u7 = users.find((x) => x.dimensionValues?.[0]?.value === 'date_range_0');
  const u30 = users.find((x) => x.dimensionValues?.[0]?.value === 'date_range_1');
  const mv = (x, i) => Number(x?.metricValues?.[i]?.value || 0);
  return {
    active7: mv(u7, 0), new7: mv(u7, 1), sessions7: mv(u7, 2),
    active30: mv(u30, 0), new30: mv(u30, 1), sessions30: mv(u30, 2),
    events: events.map((x) => ({ name: x.dimensionValues[0].value, n: Number(x.metricValues[0].value) })),
    countries: countries.map((x) => ({ name: x.dimensionValues[0].value, n: Number(x.metricValues[0].value) })),
  };
}

async function hq(env) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_KEY) return { error: 'Supabase tanımlı değil' };
  const r = await fetch(env.SUPABASE_URL.replace(/\/$/, '') + '/rest/v1/hq_snapshot?id=eq.1&select=data', {
    headers: { apikey: env.SUPABASE_SERVICE_KEY, Authorization: 'Bearer ' + env.SUPABASE_SERVICE_KEY },
  });
  if (!r.ok) return { error: 'hq_snapshot ' + r.status };
  const rows = await r.json();
  return rows[0] ? rows[0].data : {};
}

async function safe(fn) {
  try {
    return await fn();
  } catch (e) {
    return { error: String(e.message || e) };
  }
}

// ---------- routes ----------

// Password required (26 Nov 2026). Never set to true again: the panel shows revenue.
const OPEN = false;

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const ip = request.headers.get('CF-Connecting-IP') || 'x';

  if (path === '/dashboard/login' && request.method === 'POST') {
    // CSRF / cross-site posts: the login form is only ever submitted from our own origin.
    const origin = request.headers.get('Origin');
    if (origin && origin !== url.origin) return html(loginPage('Geçersiz istek.'), 403);
    const f = fails.get(ip) || { n: 0, until: 0 };
    if (f.until > Date.now()) return html(loginPage('Çok fazla deneme. Biraz bekleyin.'), 429);
    if (!env.DASH_SALT || !env.DASH_PASS_HASH || !env.DASH_SECRET) return html(loginPage('Şifre henüz tanımlanmamış.'), 503);
    const form = await request.formData();
    const given = await pbkdf2(String(form.get('p') || '').slice(0, 200), env.DASH_SALT);
    if (same(given, env.DASH_PASS_HASH)) {
      fails.delete(ip);
      const exp = String(Math.floor(Date.now() / 1000) + MAX_AGE);
      const token = exp + '.' + (await hmac(env.DASH_SECRET, exp));
      return new Response(null, {
        status: 303,
        headers: { ...baseHeaders, Location: '/dashboard', 'Set-Cookie': `${COOKIE}=${token}; Path=/dashboard; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Strict` },
      });
    }
    f.n += 1;
    if (f.n >= 5) { f.until = Date.now() + 15 * 60 * 1000; f.n = 0; }
    fails.set(ip, f);
    await sleep(1500);
    return html(loginPage('Şifre yanlış.'), 401);
  }

  if (path === '/dashboard/logout') {
    return new Response(null, { status: 303, headers: { ...baseHeaders, Location: '/dashboard', 'Set-Cookie': `${COOKIE}=; Path=/dashboard; Max-Age=0; HttpOnly; Secure; SameSite=Strict` } });
  }

  if (!OPEN && !(await authed(request, env))) {
    return path === '/dashboard/api/data' ? json({ error: 'unauthorized' }, 401) : html(loginPage(''));
  }

  if (path === '/dashboard/api/data') {
    const [sites, tr, pol, cb, hqd] = await Promise.all([safe(health), safe(() => traffic(env)), safe(() => policemai(env)), safe(() => chainbud(env)), safe(() => hq(env))]);
    return json({ at: new Date().toISOString(), sites, traffic: tr, policemai: pol, chainbud: cb, hq: hqd });
  }

  if (path === '/dashboard') return html(dashboardPage());
  return html('<h1>404</h1>', 404);
}

function loginPage(msg) {
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Giriş</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#e8e8ea;display:grid;place-items:center;min-height:100vh;margin:0}
form{background:#181b22;padding:28px;border-radius:16px;width:min(320px,90vw);display:grid;gap:12px}
input,button{padding:12px;border-radius:10px;border:1px solid #333;background:#0f1115;color:#fff;font-size:16px}
button{background:#6366f1;border:0;font-weight:700;cursor:pointer}.m{color:#f87171;font-size:14px;min-height:18px}</style></head>
<body><form method="post" action="/dashboard/login"><div style="font-weight:800;font-size:18px">Kontrol paneli</div>
<input type="password" name="p" placeholder="Şifre" autocomplete="current-password" autofocus required>
<div class="m">${msg}</div><button>Giriş</button></form></body></html>`;
}

function dashboardPage() {
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta name="theme-color" content="#07080c"><title>T4 HQ · Kontrol paneli</title>
<link rel="icon" href="/t4-logo.png">
<style>
:root{--bg:#07080c;--card:rgba(255,255,255,.045);--line:rgba(255,255,255,.09);--tx:#eef0f6;--mu:#8e93a6;--ok:#34d399;--bad:#f87171;--warn:#fbbf24;--ac:#818cf8;--ac2:#c084fc}
*{box-sizing:border-box}
body{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;color:var(--tx);margin:0;padding:22px 18px 60px;min-height:100vh;
background:radial-gradient(900px 500px at 8% -10%,rgba(129,140,248,.22),transparent 60%),radial-gradient(800px 480px at 100% 0%,rgba(192,132,252,.16),transparent 55%),var(--bg)}
.wrap{max-width:1180px;margin:0 auto}
header{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.brand{display:flex;align-items:center;gap:14px}
.brand img{height:54px;width:54px;object-fit:contain;filter:invert(1);mix-blend-mode:screen}.brand{position:relative}.brand:before{content:"";position:absolute;left:-14px;top:-14px;width:82px;height:82px;background:radial-gradient(circle,rgba(129,140,248,.45),transparent 68%);z-index:-1}
.brand b{font-size:22px;letter-spacing:.04em;display:block}
.brand span{color:var(--mu);font-size:13px}
.tools{display:flex;gap:8px;align-items:center;color:var(--mu);font-size:12px;flex-wrap:wrap}
button,.btn{background:var(--card);color:var(--tx);border:1px solid var(--line);padding:8px 14px;border-radius:10px;cursor:pointer;font-size:13px;backdrop-filter:blur(8px)}
button:hover{border-color:var(--ac)}
h2{font-size:12px;color:var(--mu);text-transform:uppercase;letter-spacing:.14em;margin:30px 0 12px;display:flex;align-items:center;gap:10px}
h2:after{content:"";height:1px;flex:1;background:linear-gradient(90deg,var(--line),transparent)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;backdrop-filter:blur(10px)}
.kpi{position:relative;overflow:hidden}
.kpi:before{content:"";position:absolute;inset:0 0 auto 0;height:2px;background:linear-gradient(90deg,var(--ac),var(--ac2))}
.k{color:var(--mu);font-size:12px}.v{font-size:30px;font-weight:800;margin-top:4px;background:linear-gradient(120deg,#fff,#c7c9ff);-webkit-background-clip:text;background-clip:text;color:transparent}
.mu{color:var(--mu);font-size:12px;margin-top:4px}.err{color:var(--bad);font-size:13px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;background:var(--bad);box-shadow:0 0 10px var(--bad)}.dot.ok{background:var(--ok);box-shadow:0 0 10px var(--ok)}
a{color:var(--ac);text-decoration:none}
.bar{height:7px;background:rgba(255,255,255,.08);border-radius:99px;overflow:hidden;margin-top:10px}
.bar i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--ac),var(--ac2))}
.bar.g i{background:linear-gradient(90deg,#10b981,#34d399)}
.row{display:flex;justify-content:space-between;gap:10px;font-size:13px;margin-top:8px}
.pill{display:inline-block;font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--mu);margin-left:6px}
.pill.w{color:var(--warn);border-color:rgba(251,191,36,.4)}.pill.b{color:var(--ac);border-color:rgba(129,140,248,.4)}
details summary{cursor:pointer;color:var(--mu);font-size:12px;margin-top:10px}
details li{font-size:12.5px;margin:6px 0;color:#cfd2e0;list-style:none}
details ul{padding:0;margin:8px 0 0}
.tag{font-size:10px;padding:1px 6px;border-radius:6px;margin-right:6px}.tag.w{background:rgba(251,191,36,.15);color:var(--warn)}.tag.t{background:rgba(129,140,248,.15);color:var(--ac)}
.ev{display:flex;flex-wrap:wrap;gap:8px}
.ev span{font-size:12.5px;background:rgba(255,255,255,.06);border:1px solid var(--line);border-radius:99px;padding:5px 11px}.ev b{margin-left:5px;color:#fff}
footer{margin-top:40px;color:var(--mu);font-size:11px;text-align:center}
</style></head><body><div class="wrap">
<header><div class="brand"><img src="/t4-logo.png" alt="T4"><div><b>T4 HQ</b><span>Komuta merkezi · yigitemreturkkan.com</span></div></div>
<div class="tools"><span id="at"></span><button onclick="load()">Yenile</button></div></header>
<div class="kpis" id="kpis"></div>
<h2>Siteler</h2><div class="grid" id="sites"></div>
<h2>Ziyaret · son 7 gün</h2><div class="grid" id="traffic"></div>
<h2>ChainBud uygulaması</h2><div class="grid" id="cb"></div><div class="card" id="cbev" style="margin-top:12px"></div>
<h2>Poliçem AI</h2><div class="grid" id="pol"></div>
<h2>Shopier siparişleri</h2><div class="grid" id="shop"></div>
<h2>Satış hattı · Poliçem AI acenteleri</h2><div class="grid" id="sales"></div>
<h2>Görevler</h2><div class="grid" id="tasks"></div>
<h2>Projeler · git durumu</h2><div class="grid" id="projects"></div>
<footer>T4 Group · veriler Cloudflare, Supabase ve Google Analytics'ten canlı çekilir</footer>
<script>
const $=(i)=>document.getElementById(i);
const esc=(s)=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const card=(k,v,extra)=>'<div class="card"><div class="k">'+esc(k)+'</div><div class="v">'+v+'</div>'+(extra||'')+'</div>';
const kpi=(k,v,extra)=>'<div class="card kpi"><div class="k">'+esc(k)+'</div><div class="v">'+v+'</div>'+(extra?'<div class="mu">'+extra+'</div>':'')+'</div>';
const pct=(a,b)=>b?Math.round(a*100/b):0;
const ago=(iso)=>{const m=Math.round((Date.now()-new Date(iso))/60000);return m<60?m+' dk önce':m<1440?Math.round(m/60)+' sa önce':Math.round(m/1440)+' gün önce'};
async function load(){
  $('at').textContent='yükleniyor…';
  const r=await fetch('/dashboard/api/data',{cache:'no-store'});
  if(r.status===401){location.reload();return}
  const d=await r.json();
  $('at').textContent='Güncellendi: '+new Date(d.at).toLocaleTimeString('tr-TR');
  const sites=Array.isArray(d.sites)?d.sites:[],up=sites.filter(s=>s.ok).length;
  const t=d.traffic,c=d.chainbud,p=d.policemai,h=d.hq||{};
  const visits=t&&t.byHost?Object.values(t.byHost).reduce((a,x)=>a+x.visits,0):0;
  const open=(h.tasks||[]).reduce((a,s)=>a+s.wait+s.todo,0),done=(h.tasks||[]).reduce((a,s)=>a+s.done,0);
  const sent=h.sales?(h.sales.counts['mesaj atıldı']||0):0;
  $('kpis').innerHTML=
    kpi('Siteler ayakta',up+' / '+sites.length,up===sites.length?'hepsi sağlıklı':'kontrol et')+
    kpi('Site ziyareti (7 gün)',visits)+
    kpi('ChainBud aktif (7 gün)',c&&!c.error?c.active7:'-',c&&!c.error?c.new7+' yeni kullanıcı':'')+
    kpi('Poliçem AI acente',p&&!p.error?p.agencies_total:'-',p&&!p.error?p.policies_total+' poliçe':'')+
    kpi('Gönderilen mesaj',sent,h.sales?h.sales.total+' acente listede':'')+
    kpi('Açık iş',open,done+' tamamlandı');
  $('sites').innerHTML=sites.map(s=>'<div class="card"><div class="k"><span class="dot '+(s.ok?'ok':'')+'"></span><a href="'+esc(s.url)+'" target="_blank" rel="noopener">'+esc(s.name)+'</a></div><div class="v">'+(s.ok?s.ms+' ms':'KAPALI')+'</div><div class="mu">HTTP '+s.status+'</div></div>').join('');
  if(t.error){$('traffic').innerHTML='<div class="err">'+esc(t.error)+'</div>'}else{
    const ent=Object.entries(t.byHost).sort((a,b)=>b[1].views-a[1].views),mx=ent.length?ent[0][1].views:1;
    $('traffic').innerHTML=ent.map(([k,x])=>'<div class="card"><div class="k">'+esc(k)+'</div><div class="v">'+x.views+'</div><div class="bar"><i style="width:'+pct(x.views,mx)+'%"></i></div><div class="mu">'+x.visits+' ziyaret</div></div>').join('')||'<div class="mu">Veri yok</div>';
  }
  if(c.error){$('cb').innerHTML='<div class="err">'+esc(c.error)+'</div>';$('cbev').style.display='none'}else{
    $('cb').innerHTML=card('Aktif kullanıcı (7 gün)',c.active7,'<div class="mu">30 gün: '+c.active30+'</div>')+card('Yeni kullanıcı (7 gün)',c.new7,'<div class="mu">30 gün: '+c.new30+'</div>')+card('Oturum (7 gün)',c.sessions7,'<div class="mu">30 gün: '+c.sessions30+'</div>')+
      card('Ülkeler (30 gün)','<span style="font-size:15px;font-weight:600;line-height:1.7">'+(c.countries.filter(x=>x.name).map(x=>esc(x.name)+' <b>'+x.n+'</b>').join('<br>')||'-')+'</span>');
    $('cbev').style.display='';
    $('cbev').innerHTML='<div class="k" style="margin-bottom:10px">Olaylar · son 30 gün</div><div class="ev">'+c.events.map(x=>'<span>'+esc(x.name)+'<b>'+x.n+'</b></span>').join('')+'</div>';
  }
  $('pol').innerHTML=p.error?'<div class="err">'+esc(p.error)+'</div>':
    card('Acente',p.agencies_total,'<div class="mu">'+p.agencies_approved+' onaylı · '+p.agencies_pending+' bekleyen</div>')+
    card('Son 7 gün kayıt',p.signups_7d,'<div class="mu">Son kayıt: '+(p.last_signup?new Date(p.last_signup).toLocaleDateString('tr-TR'):'-')+'</div>')+
    card('Poliçe',p.policies_total,'<div class="mu">Son 7 gün: '+p.policies_7d+'</div>')+card('Müşteri kaydı',p.customers_total);
  const sh=h.shopier,tl=(n)=>Number(n).toLocaleString('tr-TR')+' ₺';
  $('shop').innerHTML=!sh?'<div class="mu">Shopier verisi yok (hq.ps1 panel çalıştır)</div>':
    [['Bugün (24 sa)',sh.d1],['7 gün',sh.d7],['30 gün',sh.d30],['90 gün',sh.d90]].map(([k,x])=>card(k,x.n+' sipariş','<div class="mu">'+tl(x.total)+'</div>')).join('')+
    card('Bekleyen sipariş',sh.open,'<div class="mu">'+(sh.last?'son sipariş '+ago(sh.last):'')+'</div>');
  if(!h.sales){$('sales').innerHTML='<div class="mu">Anlık görüntü yok (hq-snapshot çalıştır)</div>'}else{
    const tot=h.sales.total||1;
    $('sales').innerHTML=Object.entries(h.sales.counts).sort((a,b)=>b[1]-a[1]).map(([k,n])=>'<div class="card"><div class="k">'+esc(k)+'</div><div class="v">'+n+'</div><div class="bar"><i style="width:'+pct(n,tot)+'%"></i></div><div class="mu">%'+pct(n,tot)+'</div></div>').join('');
  }
  $('tasks').innerHTML=(h.tasks||[]).map(s=>{
    const tot=s.done+s.wait+s.todo,list=s.open.map(o=>'<li><span class="tag '+(o.s==='wait'?'w':'t')+'">'+(o.s==='wait'?'bekliyor':'sırada')+'</span>'+esc(o.t)+'</li>').join('');
    return '<div class="card"><div class="k">'+esc(s.name)+'</div><div class="row"><span><b>'+s.done+'</b> / '+tot+' tamam</span><span>'+(s.wait?'<span class="pill w">'+s.wait+' bekliyor</span>':'')+(s.todo?'<span class="pill b">'+s.todo+' sırada</span>':'')+'</span></div><div class="bar g"><i style="width:'+pct(s.done,tot)+'%"></i></div>'+(list?'<details><summary>Açık işler ('+(s.wait+s.todo)+')</summary><ul>'+list+'</ul></details>':'')+'</div>';
  }).join('')||'<div class="mu">Anlık görüntü yok</div>';
  $('projects').innerHTML=(h.projects||[]).map(x=>'<div class="card"><div class="k">'+esc(x.name)+'<span class="pill">'+esc(x.branch||'?')+'</span></div><div class="row"><span>'+(x.dirty?'<span class="pill w">'+x.dirty+' değişiklik</span>':'<span class="pill">temiz</span>')+(x.ahead?'<span class="pill b">'+x.ahead+' push bekliyor</span>':'')+'</span></div><div class="mu">'+esc(x.lastMsg)+'</div><div class="mu">'+ago(x.lastAt)+'</div></div>').join('')||'<div class="mu">Anlık görüntü yok</div>';
}
load();setInterval(load,120000);
</script></div></body></html>`;
}
