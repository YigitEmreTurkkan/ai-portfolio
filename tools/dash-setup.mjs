// Creates the login secrets for yigitemreturkkan.com/dashboard.
// Run:  node tools/dash-setup.mjs        (you type the password; it is never printed)
// Output: ../keys/dash-secrets.json  (outside git). Then add the API values to the same file and upload:
//   npx wrangler pages secret bulk ../keys/dash-secrets.json --project-name <pages-project>
import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import readline from 'node:readline';

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, '../../keys/dash-secrets.json');

function askHidden(q) {
  return new Promise((res) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(q)) rl.output.write(s); };
    rl.question(q, (a) => { rl.close(); process.stdout.write('\n'); res(a); });
  });
}

const p1 = await askHidden('Yeni dashboard şifresi (en az 12 karakter): ');
if (p1.length < 12) { console.error('En az 12 karakter olmalı.'); process.exit(1); }
const p2 = await askHidden('Tekrar: ');
if (p1 !== p2) { console.error('Şifreler uyuşmuyor.'); process.exit(1); }

const salt = randomBytes(24).toString('hex');
const secrets = existsSync(out) ? JSON.parse(readFileSync(out, 'utf8')) : {};
Object.assign(secrets, {
  DASH_SALT: salt,
  DASH_PASS_HASH: createHmac('sha256', salt).update(p1).digest('hex'),
  DASH_SECRET: randomBytes(32).toString('hex'),
});
for (const k of ['CF_ACCOUNT_ID', 'CF_API_TOKEN', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) secrets[k] ??= '';
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(secrets, null, 2));
console.log('Yazıldı: ' + out + '\nŞimdi bu dosyadaki boş CF_* ve SUPABASE_* alanlarını doldurun.');
