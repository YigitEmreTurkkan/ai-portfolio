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
// Same-origin check for POSTs. Referrer-Policy: no-referrer makes browsers send "Origin: null" on same-site forms,
// so Sec-Fetch-Site (set by the browser, not forgeable by page scripts) is the primary signal.
function sameOrigin(request, url) {
  const sf = request.headers.get('Sec-Fetch-Site');
  if (sf) return sf === 'same-origin';
  const o = request.headers.get('Origin');
  return !o || o === url.origin;
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

// ---------- Produstra accounting: live Shopier orders + a small ledger kept in hq_snapshot row 2 ----------
// Orders are read live from the Shopier API (SHOPIER_PAT secret). Only product/amount fields are passed on,
// never customer name, address or phone. Costs and extra income/expenses are stored in Supabase.

const LEDGER_ID = 2;
const sbHeaders = (env) => ({ apikey: env.SUPABASE_SERVICE_KEY, Authorization: 'Bearer ' + env.SUPABASE_SERVICE_KEY, 'Content-Type': 'application/json' });
const sbUrl = (env, p) => env.SUPABASE_URL.replace(/\/$/, '') + '/rest/v1/' + p;

async function ledgerGet(env) {
  const r = await fetch(sbUrl(env, 'hq_snapshot?id=eq.' + LEDGER_ID + '&select=data'), { headers: sbHeaders(env) });
  if (!r.ok) throw new Error('ledger ' + r.status);
  const rows = await r.json();
  const d = (rows[0] && rows[0].data) || {};
  return { costs: d.costs || {}, entries: d.entries || [], settings: { shopierPct: 8.5, kdvPct: 20, kdvPaid: false, ...(d.settings || {}) } };
}
async function ledgerSave(env, data) {
  const r = await fetch(sbUrl(env, 'hq_snapshot?on_conflict=id'), {
    method: 'POST',
    headers: { ...sbHeaders(env), Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify({ id: LEDGER_ID, data, updated_at: new Date().toISOString() }),
  });
  if (!r.ok) throw new Error('ledger save ' + r.status);
}

async function shopierOrders(env) {
  if (!env.SHOPIER_PAT) throw new Error('SHOPIER_PAT tanımlı değil');
  const iso = (d) => d.toISOString().replace(/\.\d+Z$/, 'Z');
  const now = new Date();
  const since = new Date(now.getTime() - 365 * 864e5);
  const all = [];
  for (let page = 1; page <= 20; page++) {
    const r = await fetch('https://api.shopier.com/v1/orders?dateStart=' + iso(since) + '&dateEnd=' + iso(now) + '&limit=50&page=' + page, {
      headers: { Authorization: 'Bearer ' + env.SHOPIER_PAT, Accept: 'application/json' },
    });
    if (!r.ok) throw new Error('Shopier ' + r.status);
    all.push(...(await r.json()));
    if (page >= Number(r.headers.get('Shopier-Pagination-Total-Pages') || 1)) break;
  }
  return all.map((o) => ({
    id: String(o.id),
    date: o.dateCreated,
    status: o.status,
    pay: o.paymentStatus,
    method: o.paymentMethod,
    title: (o.lineItems || []).map((l) => (l.quantity > 1 ? l.quantity + '× ' : '') + l.title).join(', ').slice(0, 120),
    qty: (o.lineItems || []).reduce((a, l) => a + Number(l.quantity || 0), 0),
    subtotal: Number((o.totals || {}).subtotal || 0),
    shipping: Number((o.totals || {}).shipping || 0),
    total: Number((o.totals || {}).total || 0),
    refunded: (o.refunds || []).length > 0 || (o.returns || []).length > 0,
  }));
}

const num = (v) => (v === null || v === '' || v === undefined ? null : Number.isFinite(Number(v)) && Math.abs(Number(v)) < 1e8 ? Number(v) : NaN);
async function produstraApi(request, env, url, path) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_KEY) return json({ error: 'Supabase tanımlı değil' }, 503);
  const sub = path.slice('/dashboard/api/produstra'.length);
  if (request.method === 'GET' && sub === '') {
    const [orders, ledger] = await Promise.all([safe(() => shopierOrders(env)), ledgerGet(env)]);
    return json({ orders: Array.isArray(orders) ? orders : [], ordersError: Array.isArray(orders) ? null : orders.error, ledger });
  }
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  if (!sameOrigin(request, url)) return json({ error: 'origin' }, 403);
  let b;
  try { b = await request.json(); } catch { return json({ error: 'json' }, 400); }
  const L = await ledgerGet(env);
  if (sub === '/cost') {
    const id = String(b.orderId || '');
    const cost = num(b.cost), ship = num(b.ship);
    if (!/^\d{1,20}$/.test(id) || Number.isNaN(cost) || Number.isNaN(ship) || (cost !== null && cost < 0) || (ship !== null && ship < 0)) return json({ error: 'invalid' }, 400);
    const cur = L.costs[id] || {};
    if ('cost' in b) cur.cost = cost;
    if ('ship' in b) cur.ship = ship;
    if (cur.cost == null && cur.ship == null) delete L.costs[id]; else L.costs[id] = cur;
  } else if (sub === '/entry') {
    const amount = num(b.amount);
    if (!['gelir', 'gider'].includes(b.type) || !(amount > 0) || !/^\d{4}-\d{2}-\d{2}$/.test(String(b.date || '')) || !String(b.title || '').trim() || L.entries.length >= 2000) return json({ error: 'invalid' }, 400);
    L.entries.push({ id: crypto.randomUUID(), type: b.type, title: String(b.title).trim().slice(0, 80), amount, date: b.date, note: String(b.note || '').slice(0, 200) });
  } else if (sub === '/entry/delete') {
    L.entries = L.entries.filter((e) => e.id !== String(b.id));
  } else if (sub === '/settings') {
    const sp = num(b.shopierPct), kp = num(b.kdvPct);
    if (!(sp >= 0 && sp <= 50) || !(kp >= 0 && kp <= 50)) return json({ error: 'invalid' }, 400);
    L.settings = { shopierPct: sp, kdvPct: kp, kdvPaid: !!b.kdvPaid };
  } else return json({ error: 'not found' }, 404);
  await ledgerSave(env, L);
  return json({ ledger: L });
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
    if (!sameOrigin(request, url)) return html(loginPage('Geçersiz istek.'), 403);
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
    return path.startsWith('/dashboard/api/') ? json({ error: 'unauthorized' }, 401) : html(loginPage(''));
  }

  if (path.startsWith('/dashboard/api/produstra')) return safe(() => produstraApi(request, env, url, path)).then((r) => (r instanceof Response ? r : json(r, 500)));

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
.tabs{display:flex;gap:6px}.tabs button.on{border-color:var(--ac);color:#fff;background:rgba(129,140,248,.2)}
.seg{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 14px}.seg button.on{border-color:var(--ac);color:#fff;background:rgba(129,140,248,.2)}
table.t{width:100%;border-collapse:collapse;font-size:12.5px;min-width:760px}
table.t th{color:var(--mu);font-weight:600;text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap}
table.t td{padding:8px 6px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:middle}
.r{text-align:right}.pos{color:var(--ok)}.neg{color:var(--bad)}
input,select{background:rgba(255,255,255,.06);color:var(--tx);border:1px solid var(--line);border-radius:8px;padding:7px 9px;font-size:13px;font-family:inherit;max-width:100%}
input[type=number]{width:96px}input[type=text]{min-width:160px}
.form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.chart{width:100%;height:auto;display:block}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px}
.scroll{overflow-x:auto}
.big{font-size:34px;font-weight:800}
.note{font-size:12px;color:var(--mu);line-height:1.6}
footer{margin-top:40px;color:var(--mu);font-size:11px;text-align:center}
</style></head><body><div class="wrap">
<header><div class="brand"><img src="/t4-logo.png" alt="T4"><div><b>T4 HQ</b><span>Komuta merkezi · yigitemreturkkan.com</span></div></div>
<div class="tools"><span class="tabs"><button id="t-gen" class="on" onclick="tab('gen')">Genel</button><button id="t-pro" onclick="tab('pro')">Produstra</button></span><span id="at"></span><button onclick="load()">Yenile</button></div></header>
<div id="v-gen">
<div class="kpis" id="kpis"></div>
<h2>Siteler</h2><div class="grid" id="sites"></div>
<h2>Ziyaret · son 7 gün</h2><div class="grid" id="traffic"></div>
<h2>ChainBud uygulaması</h2><div class="grid" id="cb"></div><div class="card" id="cbev" style="margin-top:12px"></div>
<h2>Poliçem AI</h2><div class="grid" id="pol"></div>
<h2>Shopier siparişleri</h2><div class="grid" id="shop"></div>
<h2>Satış hattı · Poliçem AI acenteleri</h2><div class="grid" id="sales"></div>
<h2>Görevler</h2><div class="grid" id="tasks"></div>
<h2>Projeler · git durumu</h2><div class="grid" id="projects"></div>
</div>
<div id="v-pro" hidden><div id="pro"><div class="mu">Yükleniyor…</div></div></div>
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
const money=(n)=>(Math.round(n*100)/100).toLocaleString(\'tr-TR\',{minimumFractionDigits:0,maximumFractionDigits:2})+\' ₺\';
const ymd=(d)=>d.getFullYear()+\'-\'+String(d.getMonth()+1).padStart(2,\'0\')+\'-\'+String(d.getDate()).padStart(2,\'0\');
const MON=[\'Oca\',\'Şub\',\'Mar\',\'Nis\',\'May\',\'Haz\',\'Tem\',\'Ağu\',\'Eyl\',\'Eki\',\'Kas\',\'Ara\'];
const mlab=(k)=>MON[Number(k.slice(5,7))-1]+\' \'+k.slice(2,4);
let PRO=null,PER=\'month\';
function tab(n){
  $(\'v-gen\').hidden=n!==\'gen\';$(\'v-pro\').hidden=n!==\'pro\';
  $(\'t-gen\').className=n===\'gen\'?\'on\':\'\';$(\'t-pro\').className=n===\'pro\'?\'on\':\'\';
  if(n===\'pro\'&&!PRO)loadPro();
}
async function loadPro(){
  const r=await fetch(\'/dashboard/api/produstra\',{cache:\'no-store\'});
  if(r.status===401){location.reload();return}
  PRO=await r.json();
  if(PRO.error){$(\'pro\').innerHTML=\'<div class="err">\'+esc(PRO.error)+\'</div>\';return}
  renderPro();
}
async function proPost(p,b){
  const r=await fetch(\'/dashboard/api/produstra/\'+p,{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify(b)});
  if(r.status===401){location.reload();return}
  const d=await r.json();
  if(!r.ok){$(\'pmsg\').textContent=\'Kaydedilemedi: \'+(d.error||r.status);return}
  PRO.ledger=d.ledger;renderPro();
}
function setCost(id,k,v){const b={orderId:id};b[k]=v===\'\'?null:Number(String(v).replace(\',\',\'.\'));proPost(\'cost\',b)}
function addEntry(){
  const g=(i)=>$(i).value;
  proPost(\'entry\',{type:g(\'e-type\'),title:g(\'e-title\'),amount:Number(String(g(\'e-amt\')).replace(\',\',\'.\')),date:g(\'e-date\'),note:g(\'e-note\')});
}
function delEntry(id,b){if(b.dataset.s!==\'1\'){b.dataset.s=\'1\';b.textContent=\'Emin misin?\';return}proPost(\'entry/delete\',{id:id})}
function saveSet(){
  proPost(\'settings\',{shopierPct:Number(String($(\'s-fee\').value).replace(\',\',\'.\')),kdvPct:Number(String($(\'s-kdv\').value).replace(\',\',\'.\')),kdvPaid:$(\'s-paid\').checked});
}
function setPer(p){PER=p;renderPro()}
function calc(o,L){
  const s=L.settings,c=L.costs[o.id]||{};
  const valid=o.pay===\'paid\'&&!o.refunded&&o.status!==\'cancelled\';
  const fee=o.subtotal*s.shopierPct/100;
  const kdv=o.subtotal*s.kdvPct/(100+s.kdvPct);
  const ship=c.ship==null?o.shipping:Number(c.ship);
  const cost=c.cost==null?null:Number(c.cost);
  const net=o.subtotal-(cost||0)-fee-(s.kdvPaid?kdv:0)+(o.shipping-ship);
  return {valid,fee,kdv,ship,cost,net,miss:cost==null};
}
function barsSvg(d){
  const W=560,H=220,pl=46,pb=26,pt=14,pr=8;
  const mx=Math.max(1,...d.map(x=>Math.max(x.a,x.b))),mn=Math.min(0,...d.map(x=>x.b));
  const y=(v)=>pt+(H-pt-pb)*(1-(v-mn)/(mx-mn));
  let s=\'<svg class="chart" viewBox="0 0 \'+W+\' \'+H+\'">\';
  for(let i=0;i<=4;i++){const v=mn+(mx-mn)*i/4,yy=y(v);s+=\'<line x1="\'+pl+\'" x2="\'+(W-pr)+\'" y1="\'+yy+\'" y2="\'+yy+\'" stroke="rgba(255,255,255,.07)"/><text x="\'+(pl-6)+\'" y="\'+(yy+4)+\'" text-anchor="end" font-size="10" fill="#8a8fa8">\'+Math.round(v)+\'</text>\'}
  const step=(W-pl-pr)/Math.max(1,d.length),bw=Math.min(22,step/2.6);
  d.forEach((x,i)=>{
    const cx=pl+step*i+step/2,z=y(0);
    s+=\'<rect x="\'+(cx-bw-1)+\'" y="\'+Math.min(y(x.a),z)+\'" width="\'+bw+\'" height="\'+Math.abs(z-y(x.a))+\'" rx="4" fill="#818cf8"/>\';
    s+=\'<rect x="\'+(cx+1)+\'" y="\'+Math.min(y(x.b),z)+\'" width="\'+bw+\'" height="\'+Math.abs(z-y(x.b))+\'" rx="4" fill="\'+(x.b>=0?\'#34d399\':\'#f87171\')+\'"/>\';
    s+=\'<text x="\'+cx+\'" y="\'+(H-8)+\'" text-anchor="middle" font-size="10" fill="#8a8fa8">\'+esc(x.l)+\'</text>\';
  });
  return s+\'</svg>\';
}
function lineSvg(d){
  const W=560,H=200,pl=46,pb=24,pt=14,pr=8;
  const mx=Math.max(1,...d.map(x=>x.v));
  const x=(i)=>pl+(W-pl-pr)*i/Math.max(1,d.length-1),y=(v)=>pt+(H-pt-pb)*(1-v/mx);
  let s=\'<svg class="chart" viewBox="0 0 \'+W+\' \'+H+\'"><defs><linearGradient id="lg" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#818cf8" stop-opacity=".55"/><stop offset="1" stop-color="#818cf8" stop-opacity="0"/></linearGradient></defs>\';
  for(let i=0;i<=3;i++){const v=mx*i/3,yy=y(v);s+=\'<line x1="\'+pl+\'" x2="\'+(W-pr)+\'" y1="\'+yy+\'" y2="\'+yy+\'" stroke="rgba(255,255,255,.07)"/><text x="\'+(pl-6)+\'" y="\'+(yy+4)+\'" text-anchor="end" font-size="10" fill="#8a8fa8">\'+Math.round(v)+\'</text>\'}
  const pts=d.map((p,i)=>x(i)+\',\'+y(p.v)).join(\' \');
  s+=\'<polygon points="\'+pl+\',\'+y(0)+\' \'+pts+\' \'+x(d.length-1)+\',\'+y(0)+\'" fill="url(#lg)"/><polyline points="\'+pts+\'" fill="none" stroke="#c084fc" stroke-width="2.2" stroke-linejoin="round"/>\';
  d.forEach((p,i)=>{if(p.v>0)s+=\'<circle cx="\'+x(i)+\'" cy="\'+y(p.v)+\'" r="3.2" fill="#fff"/>\'});
  [0,Math.floor((d.length-1)/2),d.length-1].forEach(i=>{s+=\'<text x="\'+x(i)+\'" y="\'+(H-6)+\'" text-anchor="middle" font-size="10" fill="#8a8fa8">\'+esc(d[i].l)+\'</text>\'});
  return s+\'</svg>\';
}
function rowsBar(items,fmt){
  const mx=Math.max(1,...items.map(i=>i.v));
  return items.map(i=>\'<div class="row"><span>\'+esc(i.k)+\'</span><span>\'+fmt(i)+\'</span></div><div class="bar"><i style="width:\'+Math.round(i.v*100/mx)+\'%"></i></div>\').join(\'\')||\'<div class="mu">Veri yok</div>\';
}
function renderPro(){
  const P=PRO,L=P.ledger,s=L.settings,now=new Date();
  const cm=ymd(now).slice(0,7),pm=ymd(new Date(now.getFullYear(),now.getMonth()-1,1)).slice(0,7);
  const inP=(d)=>PER===\'all\'||(PER===\'month\'&&d.slice(0,7)===cm)||(PER===\'prev\'&&d.slice(0,7)===pm);
  const all=P.orders.map(o=>({o:o,c:calc(o,L),d:ymd(new Date(o.date))})).sort((a,b)=>b.o.date<a.o.date?-1:1);
  const ords=all.filter(x=>inP(x.d)),ok=ords.filter(x=>x.c.valid);
  const sum=(f)=>ok.reduce((a,x)=>a+f(x),0);
  const sales=sum(x=>x.o.subtotal),fee=sum(x=>x.c.fee),kdv=sum(x=>x.c.kdv),cost=sum(x=>x.c.cost||0),orderNet=sum(x=>x.c.net);
  const miss=ok.filter(x=>x.c.miss).length;
  const ents=L.entries.filter(e=>inP(e.date)).sort((a,b)=>b.date<a.date?-1:1);
  const oin=ents.filter(e=>e.type===\'gelir\').reduce((a,e)=>a+e.amount,0),oout=ents.filter(e=>e.type===\'gider\').reduce((a,e)=>a+e.amount,0);
  const net=orderNet+oin-oout,margin=sales+oin>0?Math.round(net*100/(sales+oin)):0;
  const netKdv=s.kdvPaid?net:net-kdv;
  const K=(k,v,x,c)=>\'<div class="card kpi"><div class="k">\'+k+\'</div><div class="v"\'+(c?\' style="background:none;-webkit-text-fill-color:\'+c+\'"\':\'\')+\'>\'+v+\'</div>\'+(x?\'<div class="mu">\'+x+\'</div>\':\'\')+\'</div>\';
  let h=\'<div class="seg">\'+[[\'month\',\'Bu ay\'],[\'prev\',\'Geçen ay\'],[\'all\',\'Tümü\']].map(p=>\'<button class="\'+(PER===p[0]?\'on\':\'\')+\'" onclick="setPer(\\'\'+p[0]+\'\\')">\'+p[1]+\'</button>\').join(\'\')+\'<button onclick="loadPro()">Shopier\\'den yenile</button><span class="mu" id="pmsg" style="align-self:center"></span></div>\';
  if(P.ordersError)h+=\'<div class="err" style="margin-bottom:10px">Shopier: \'+esc(P.ordersError)+\'</div>\';
  h+=\'<div class="kpis">\'+
    K(\'Net kâr\',money(net),\'marj %\'+margin+(miss?\' · \'+miss+\' siparişte maliyet girilmedi\':\'\'),net>=0?\'#34d399\':\'#f87171\')+
    K(\'Satış (ürün)\',money(sales),ok.length+\' sipariş · ort. \'+money(ok.length?sales/ok.length:0))+
    K(\'Shopier kesintisi\',money(fee),\'%\'+s.shopierPct+\' · ürün tutarı üzerinden\')+
    K(\'Ürün maliyeti\',money(cost))+
    K(\'KDV \'+(s.kdvPaid?\'(ödeniyor)\':\'(şimdilik ödenmiyor)\'),money(kdv),s.kdvPaid?\'kârdan düşüldü\':\'ödense net kâr: \'+money(netKdv))+
    K(\'Diğer gelir\',money(oin))+K(\'Diğer gider\',money(oout))+\'</div>\';
  // charts
  const months={};
  all.filter(x=>x.c.valid).forEach(x=>{const k=x.d.slice(0,7);(months[k]=months[k]||{a:0,b:0}).a+=x.o.subtotal;months[k].b+=x.c.net});
  L.entries.forEach(e=>{const k=e.date.slice(0,7);(months[k]=months[k]||{a:0,b:0}).b+=e.type===\'gelir\'?e.amount:-e.amount;if(e.type===\'gelir\')months[k].a+=e.amount});
  const mk=Object.keys(months).sort().slice(-12).map(k=>({l:mlab(k),a:months[k].a,b:months[k].b}));
  const days=[];for(let i=29;i>=0;i--){const d=new Date(now.getFullYear(),now.getMonth(),now.getDate()-i);days.push({k:ymd(d),l:d.getDate()+\' \'+MON[d.getMonth()],v:0})}
  all.filter(x=>x.c.valid).forEach(x=>{const t=days.find(d=>d.k===x.d);if(t)t.v+=x.o.total});
  const prod={},pay={};
  ok.forEach(x=>{const t=x.o.title.toLowerCase().replace(/^[0-9]+× /,\'\');(prod[t]=prod[t]||{k:x.o.title,n:0,v:0}).n+=x.o.qty||1;prod[t].v+=x.o.subtotal;const m=x.o.method===\'creditCard\'?\'Kredi kartı\':x.o.method===\'debitCard\'?\'Banka kartı\':(x.o.method||\'?\');(pay[m]=pay[m]||{k:m,v:0}).v+=1});
  h+=\'<h2>Grafikler</h2><div class="cols"><div class="card"><div class="k">Aylık satış <span style="color:#818cf8">■</span> ve net kâr <span style="color:#34d399">■</span></div>\'+(mk.length?barsSvg(mk):\'<div class="mu">Veri yok</div>\')+\'</div>\'+
    \'<div class="card"><div class="k">Günlük ciro · son 30 gün</div>\'+lineSvg(days)+\'</div>\'+
    \'<div class="card"><div class="k">Ürünler · satış tutarı</div>\'+rowsBar(Object.values(prod).sort((a,b)=>b.v-a.v).slice(0,7).map(p=>({k:p.k,v:p.v,n:p.n})),i=>i.n+\' adet · \'+money(i.v))+\'</div>\'+
    \'<div class="card"><div class="k">Ödeme yöntemi · sipariş</div>\'+rowsBar(Object.values(pay),i=>i.v+\' sipariş\')+\'<div class="k" style="margin-top:16px">Sipariş durumu</div>\'+rowsBar(Object.entries(ords.reduce((a,x)=>{const k=x.o.refunded?\'iade\':x.o.status;a[k]=(a[k]||0)+1;return a},{})).map(e=>({k:e[0],v:e[1]})),i=>i.v)+\'</div></div>\';
  // order table
  h+=\'<h2>Siparişler · maliyet gir, kârı gör</h2><div class="card scroll"><table class="t"><tr><th>Tarih</th><th>Ürün</th><th class="r">Ürün ₺</th><th class="r">Kargo ₺</th><th>Maliyet ₺</th><th>Kargo gideri ₺</th><th class="r">Shopier</th><th class="r">KDV</th><th class="r">Net kâr</th></tr>\'+
    ords.map(x=>{const o=x.o,c=x.c,cs=L.costs[o.id]||{};
      return \'<tr style="\'+(c.valid?\'\':\'opacity:.5\')+\'"><td>\'+esc(x.d.slice(5).split(\'-\').reverse().join(\'.\'))+\'</td><td>\'+esc(o.title)+(c.valid?\'\':\'<span class="pill w">\'+(o.refunded?\'iade\':esc(o.status))+\'</span>\')+\'</td><td class="r">\'+money(o.subtotal)+\'</td><td class="r">\'+money(o.shipping)+\'</td>\'+
      \'<td><input type="number" step="any" min="0" placeholder="maliyet" value="\'+(cs.cost==null?\'\':cs.cost)+\'" onchange="setCost(\\'\'+o.id+\'\\',\\'cost\\',this.value)"></td>\'+
      \'<td><input type="number" step="any" min="0" placeholder="\'+o.shipping+\'" value="\'+(cs.ship==null?\'\':cs.ship)+\'" onchange="setCost(\\'\'+o.id+\'\\',\\'ship\\',this.value)"></td>\'+
      \'<td class="r">\'+money(c.fee)+\'</td><td class="r">\'+money(c.kdv)+\'</td><td class="r \'+(c.valid?(c.net>=0?\'pos\':\'neg\'):\'\')+\'">\'+(c.valid?money(c.net)+(c.miss?\'<span class="pill w">tahmini</span>\':\'\'):\'-\')+\'</td></tr>\'}).join(\'\')+
    (ords.length?\'\':\'<tr><td colspan="9" class="mu">Bu dönemde sipariş yok</td></tr>\')+\'</table></div>\'+
    \'<div class="note" style="margin-top:8px">Net kâr = ürün tutarı − maliyet − Shopier kesintisi\'+(s.kdvPaid?\' − KDV\':\'\')+\' + (müşteriden alınan kargo − kargo gideri). Kargo gideri boş bırakılırsa müşteriden alınan kargoyla aynı sayılır (kâra etkisi 0).</div>\';
  // other income / expenses
  h+=\'<h2>Diğer gelir / gider</h2><div class="card"><div class="form"><select id="e-type"><option value="gider">Gider</option><option value="gelir">Gelir</option></select><input type="text" id="e-title" placeholder="Başlık (filament, kutu, reklam…)"><input type="number" id="e-amt" step="any" min="0" placeholder="Tutar ₺"><input type="date" id="e-date" value="\'+ymd(now)+\'"><input type="text" id="e-note" placeholder="Not (isteğe bağlı)"><button onclick="addEntry()">Ekle</button></div>\'+
    \'<div class="scroll" style="margin-top:12px"><table class="t" style="min-width:520px"><tr><th>Tarih</th><th>Tür</th><th>Başlık</th><th class="r">Tutar</th><th></th></tr>\'+
    ents.map(e=>\'<tr><td>\'+esc(e.date.slice(5).split(\'-\').reverse().join(\'.\'))+\'</td><td><span class="pill \'+(e.type===\'gider\'?\'w\':\'b\')+\'">\'+e.type+\'</span></td><td>\'+esc(e.title)+(e.note?\'<div class="mu">\'+esc(e.note)+\'</div>\':\'\')+\'</td><td class="r \'+(e.type===\'gider\'?\'neg\':\'pos\')+\'">\'+(e.type===\'gider\'?\'-\':\'+\')+money(e.amount)+\'</td><td class="r"><button onclick="delEntry(\\'\'+e.id+\'\\',this)">Sil</button></td></tr>\').join(\'\')+
    (ents.length?\'\':\'<tr><td colspan="5" class="mu">Bu dönemde kayıt yok</td></tr>\')+\'</table></div></div>\';
  // settings
  h+=\'<h2>Ayarlar</h2><div class="card"><div class="form"><label class="mu">Shopier kesintisi %<br><input type="number" id="s-fee" step="any" value="\'+s.shopierPct+\'"></label><label class="mu">KDV %<br><input type="number" id="s-kdv" step="any" value="\'+s.kdvPct+\'"></label><label class="mu" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="s-paid"\'+(s.kdvPaid?\' checked\':\'\')+\'> KDV ödüyoruz (kârdan düş)</label><button onclick="saveSet()">Kaydet</button></div>\'+
    \'<div class="note" style="margin-top:8px">Şirket olmadığı için KDV şimdilik ödenmiyor: tutar bilgi olarak ayrı gösterilir, kâra dahil edilmez. Şirket kurulunca kutuyu işaretle. Fiyat formülü: maliyet × 2 kâr, +%20 KDV, +Shopier kesintisi (%8,5) → örnek 500 TL maliyet = 1.302 TL.</div></div>\';
  $(\'pro\').innerHTML=h;
}
load();setInterval(load,120000);
</script></div></body></html>`;
}
