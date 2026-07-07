/**
 * HTTP smoke test. Exercises the real Worker end-to-end:
 * create -> share -> decrypt, plus negative cases.
 *
 * Prerequisite: a running dev server (`npm run dev`, http://127.0.0.1:8788).
 * Override the target with the BASE environment variable.
 * Run: npm run smoke
 */
import { b64u, unb64u, xor, randomBytes, aesEncrypt, aesDecrypt } from '../public/crypto.js';

const BASE = process.env.BASE || 'http://127.0.0.1:8788';
let pass = 0, fail = 0;
const check = (n, c) => (c ? (pass++, console.log(`  ok   ${n}`)) : (fail++, console.log(`  FAIL ${n}`)));

// 1) create
const cr = await fetch(`${BASE}/api/create`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ ttl: 120 }),
});
check('POST /api/create 200', cr.status === 200);
const { id, serverShare } = await cr.json();
check('create returns id + serverShare', !!id && !!serverShare);

// 2) client encrypts
const msg = 'HTTP round-trip secret 🔐 ' + 'y'.repeat(40);
const K = randomBytes(32);
const { iv, ct } = await aesEncrypt(K, msg);
const mixed = xor(K, unb64u(serverShare));

// 3) fetch the share back over HTTP and decrypt
const sh = await fetch(`${BASE}/api/share/${encodeURIComponent(id)}`);
check('GET /api/share/:id 200', sh.status === 200);
const share2 = unb64u((await sh.json()).serverShare);
const K2 = xor(mixed, share2);
check('decrypts to original over HTTP', (await aesDecrypt(K2, iv, ct)) === msg);

// 4) bogus id -> 410
const bad = await fetch(`${BASE}/api/share/9.AAAA.9999999999.AAAA`);
check('bogus id -> 410', bad.status === 410);

// 5) ttl bounds
const badTtl = await fetch(`${BASE}/api/create`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ ttl: 5 }),
});
check('ttl=5 rejected -> 400', badTtl.status === 400);
const maxTtl = await fetch(`${BASE}/api/create`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ ttl: 86400 }),
});
check('ttl=86400 (24h) accepted -> 200', maxTtl.status === 200);
const overTtl = await fetch(`${BASE}/api/create`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ ttl: 86401 }),
});
check('ttl=86401 rejected -> 400', overTtl.status === 400);

// 5b) burn-after-read: first open succeeds, second is gone. Deterministic
// locally (wrangler dev KV is immediately consistent); production KV is
// eventually consistent, so this proves the logic, not the global race.
const crB = await fetch(`${BASE}/api/create`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ ttl: 120, burn: true }),
});
const { id: burnId } = await crB.json();
check('burn create returns flagged id', crB.status === 200 && burnId.split('.')[4] === 'b');
const shB1 = await fetch(`${BASE}/api/share/${encodeURIComponent(burnId)}`);
check('burn link: first open 200', shB1.status === 200);
const shB2 = await fetch(`${BASE}/api/share/${encodeURIComponent(burnId)}`);
check('burn link: second open 410', shB2.status === 410);

// 6) ad endpoint returns first-party house ad
const ad = await (await fetch(`${BASE}/api/ad`)).json();
check('GET /api/ad returns text', !!ad.text);

// 7) /view serves the reveal page directly (no redirect; id rides in #fragment)
const view = await fetch(`${BASE}/view`, { redirect: 'manual' });
const html = view.status === 200 ? await view.text() : '';
check('/view serves reveal page (200, no redirect)', view.status === 200 && html.includes('Reveal message'));

// 8) full new-scheme link: build it like create.js, parse it like view.js
const payload = [b64u(iv), '-', b64u(mixed), b64u(ct)].join('.');
const fullLink = `${BASE}/view#${id}~${payload}`;
const hash = fullLink.slice(fullLink.indexOf('#') + 1);
const sep = hash.indexOf('~');
const id3 = hash.slice(0, sep);
const parts = hash.slice(sep + 1).split('.');
check('link parses back to same id', id3 === id);
const sh3 = await fetch(`${BASE}/api/share/${encodeURIComponent(id3)}`);
const share3 = unb64u((await sh3.json()).serverShare);
const K3 = xor(unb64u(parts[2]), share3);
check('parsed-link round-trip decrypts', (await aesDecrypt(K3, unb64u(parts[0]), unb64u(parts[3]))) === msg);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
