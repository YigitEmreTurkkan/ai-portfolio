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
const MAX_AGE = 60 * 60 * 24 * 7;
const fails = new Map(); // ip -> {n, until}  (per isolate; a soft brake, not the only defence)

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
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

async function safe(fn) {
  try {
    return await fn();
  } catch (e) {
    return { error: String(e.message || e) };
  }
}

// ---------- routes ----------

// TEMPORARY: panel is open without a password (owner choice, 24 Nov 2026). Set to false to require the login again.
const OPEN = true;

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const ip = request.headers.get('CF-Connecting-IP') || 'x';

  if (path === '/dashboard/login' && request.method === 'POST') {
    const f = fails.get(ip) || { n: 0, until: 0 };
    if (f.until > Date.now()) return html(loginPage('Çok fazla deneme. Biraz bekleyin.'), 429);
    if (!env.DASH_SALT || !env.DASH_PASS_HASH || !env.DASH_SECRET) return html(loginPage('Şifre henüz tanımlanmamış.'), 503);
    const form = await request.formData();
    const given = await hmac(env.DASH_SALT, String(form.get('p') || ''));
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
    const [sites, tr, pol] = await Promise.all([safe(health), safe(() => traffic(env)), safe(() => policemai(env))]);
    return json({ at: new Date().toISOString(), sites, traffic: tr, policemai: pol });
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
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Kontrol paneli</title>
<style>
:root{--bg:#0f1115;--card:#181b22;--tx:#e8e8ea;--mu:#8b8f9a;--ok:#34d399;--bad:#f87171;--ac:#818cf8}
*{box-sizing:border-box}body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--tx);margin:0;padding:20px;max-width:1100px;margin-inline:auto}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;gap:12px;flex-wrap:wrap}
h1{font-size:22px;margin:0}h2{font-size:14px;color:var(--mu);text-transform:uppercase;letter-spacing:.06em;margin:26px 0 10px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.card{background:var(--card);border-radius:14px;padding:16px}
.k{color:var(--mu);font-size:13px}.v{font-size:26px;font-weight:800;margin-top:2px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;background:var(--bad)}.dot.ok{background:var(--ok)}
a{color:var(--ac);text-decoration:none}.err{color:var(--bad);font-size:13px}.mu{color:var(--mu);font-size:12px}
button,.btn{background:var(--card);color:var(--tx);border:1px solid #2a2e38;padding:8px 14px;border-radius:10px;cursor:pointer;font-size:14px}
</style></head><body>
<header><h1>Kontrol paneli</h1><div><span class="mu" id="at"></span> <button onclick="load()">Yenile</button> <a class="btn" href="/dashboard/logout">Çıkış</a></div></header>
<h2>Siteler</h2><div class="grid" id="sites"></div>
<h2>Ziyaret (son 7 gün, Cloudflare Web Analytics)</h2><div class="grid" id="traffic"></div>
<h2>Poliçem AI (Supabase, yalnızca sayılar)</h2><div class="grid" id="pol"></div>
<script>
const $=(i)=>document.getElementById(i);
const esc=(s)=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const card=(k,v,extra='')=>'<div class="card"><div class="k">'+esc(k)+'</div><div class="v">'+v+'</div>'+extra+'</div>';
async function load(){
  $('at').textContent='yükleniyor…';
  const r=await fetch('/dashboard/api/data',{cache:'no-store'});
  if(r.status===401){location.reload();return}
  const d=await r.json();
  $('at').textContent=new Date(d.at).toLocaleString('tr-TR');
  $('sites').innerHTML=d.sites.error?'<div class="err">'+esc(d.sites.error)+'</div>':d.sites.map(s=>
    '<div class="card"><div class="k"><span class="dot '+(s.ok?'ok':'')+'"></span><a href="'+esc(s.url)+'" target="_blank" rel="noopener">'+esc(s.name)+'</a></div>'+
    '<div class="v">'+(s.ok?s.ms+' ms':'KAPALI')+'</div><div class="mu">HTTP '+s.status+(s.error?' · '+esc(s.error):'')+'</div></div>').join('');
  const t=d.traffic;
  $('traffic').innerHTML=t.error?'<div class="err">'+esc(t.error)+'</div>':Object.entries(t.byHost).sort((a,b)=>b[1].views-a[1].views).map(([h,x])=>
    card(h,x.views,'<div class="mu">'+x.visits+' ziyaret</div>')).join('')||'<div class="mu">Veri yok</div>';
  const p=d.policemai;
  $('pol').innerHTML=p.error?'<div class="err">'+esc(p.error)+'</div>':
    card('Acente',p.agencies_total,'<div class="mu">'+p.agencies_approved+' onaylı · '+p.agencies_pending+' bekleyen</div>')+
    card('Son 7 gün kayıt',p.signups_7d,'<div class="mu">Son: '+(p.last_signup?new Date(p.last_signup).toLocaleDateString('tr-TR'):'-')+'</div>')+
    card('Poliçe',p.policies_total,'<div class="mu">Son 7 gün: '+p.policies_7d+'</div>')+
    card('Müşteri kaydı',p.customers_total);
}
load();setInterval(load,120000);
</script></body></html>`;
}
