// Builds a small summary of everything in Repos/ (tasks, sales funnel, git state) and stores it in Supabase
// table hq_snapshot (id=1). The dashboard function reads it. No names, phones or secrets are included.
// Run:  node ai-portfolio/tools/hq-snapshot.mjs
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repos = resolve(here, '../..');
const secrets = JSON.parse(readFileSync(resolve(repos, 'keys/dash-secrets.json'), 'utf8'));

// ---- tasks: GOREVLER.md ----
function tasks() {
  const lines = readFileSync(resolve(repos, 'GOREVLER.md'), 'utf8').split(/\r?\n/);
  const sections = [];
  let cur = null;
  for (const raw of lines) {
    const h = raw.match(/^#{2,3} (.+)/);
    if (h) {
      cur = { name: h[1].trim(), done: 0, wait: 0, todo: 0, open: [] };
      sections.push(cur);
      continue;
    }
    const m = raw.match(/^- (✅|🟡|⬜)\s*(.*)/u);
    if (!m || !cur) continue;
    const text = m[2].replace(/[`*]/g, '').slice(0, 110);
    if (m[1] === '✅') cur.done++;
    else if (m[1] === '🟡') { cur.wait++; cur.open.push({ s: 'wait', t: text }); }
    else { cur.todo++; cur.open.push({ s: 'todo', t: text }); }
  }
  return sections.filter((s) => s.done + s.wait + s.todo > 0);
}

// ---- sales funnel: counts only ----
function sales() {
  const f = resolve(repos, 'police-webapp/satis-paketi/hedef-acenteler.csv');
  if (!existsSync(f)) return null;
  const rows = readFileSync(f, 'utf8').split(/\r?\n/).filter(Boolean);
  const head = rows[0].split(',');
  const di = head.indexOf('durum');
  const counts = {};
  for (const r of rows.slice(1)) {
    const c = r.split(',');
    const d = (c[di] || 'bekliyor').trim() || 'bekliyor';
    counts[d] = (counts[d] || 0) + 1;
  }
  return { total: rows.length - 1, counts };
}

// ---- git state per project ----
const PROJECTS = ['chainbud', 'police-webapp', 'produstra', 'ai-portfolio', 'decan-tech', 't4-digital', 'academy-groupt4', 'hizli-sozlesme-private', 't4-group-website'];
function git(dir, ...args) {
  return execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}
function projects() {
  const out = [];
  for (const p of PROJECTS) {
    const dir = resolve(repos, p);
    if (!existsSync(resolve(dir, '.git'))) continue;
    try {
      const branch = git(dir, 'branch', '--show-current');
      const dirty = git(dir, 'status', '--short').split('\n').filter(Boolean).length;
      const last = git(dir, 'log', '-1', '--format=%cI|%s').split('|');
      let ahead = null;
      try { ahead = Number(git(dir, 'rev-list', '--count', '@{u}..HEAD')); } catch { /* no upstream */ }
      out.push({ name: p, branch, dirty, ahead, lastAt: last[0], lastMsg: last.slice(1).join('|').slice(0, 80) });
    } catch { /* skip */ }
  }
  return out;
}

// ---- Shopier orders: counts and totals only (no customer data). Key: keys/shopier.key ----
async function shopier() {
  const kf = resolve(repos, 'keys/shopier.key');
  if (!existsSync(kf)) return null;
  const key = readFileSync(kf, 'utf8').trim();
  const now = new Date();
  const iso = (d) => d.toISOString().replace(/\.\d+Z$/, 'Z');
  const since = new Date(now.getTime() - 90 * 864e5);
  const all = [];
  for (let page = 1; page <= 20; page++) {
    const u = `https://api.shopier.com/v1/orders?dateStart=${iso(since)}&dateEnd=${iso(now)}&limit=50&page=${page}`;
    const r = await fetch(u, { headers: { Authorization: 'Bearer ' + key, Accept: 'application/json' } });
    if (!r.ok) { console.error('Shopier ' + r.status); return null; }
    all.push(...(await r.json()));
    if (page >= Number(r.headers.get('Shopier-Pagination-Total-Pages') || 1)) break;
  }
  const paid = all.filter((o) => o.paymentStatus === 'paid');
  const sum = (days) => {
    const from = now.getTime() - days * 864e5;
    const l = paid.filter((o) => new Date(o.dateCreated).getTime() >= from);
    return { n: l.length, total: Math.round(l.reduce((a, o) => a + Number(o.totals?.total || 0), 0)) };
  };
  const open = all.filter((o) => o.status !== 'fulfilled' && o.status !== 'cancelled').length;
  return { d1: sum(1), d7: sum(7), d30: sum(30), d90: sum(90), open, last: paid[0]?.dateCreated || null };
}

const data = { at: new Date().toISOString(), tasks: tasks(), sales: sales(), projects: projects(), shopier: await shopier() };
const r = await fetch(secrets.SUPABASE_URL.replace(/\/$/, '') + '/rest/v1/hq_snapshot?on_conflict=id', {
  method: 'POST',
  headers: {
    apikey: secrets.SUPABASE_SERVICE_KEY,
    Authorization: 'Bearer ' + secrets.SUPABASE_SERVICE_KEY,
    'Content-Type': 'application/json',
    Prefer: 'resolution=merge-duplicates,return=minimal',
  },
  body: JSON.stringify({ id: 1, data, updated_at: data.at }),
});
if (!r.ok) { console.error('Supabase ' + r.status + ': ' + (await r.text()).slice(0, 200)); process.exit(1); }
console.log('Anlık görüntü yazıldı: ' + data.tasks.length + ' bölüm, ' + data.projects.length + ' proje' + (data.sales ? ', satış ' + data.sales.total : ''));
