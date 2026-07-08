/**
 * End-to-end crypto self-test — no server, no network. Proves the split-key
 * design round-trips and that expiry/tampering/wrong-phrase all fail closed,
 * plus the hourly root lifecycle: lazy mint, pre-mint of the next hour,
 * deterministic promotion at the flip, and overlap across the boundary.
 * Run: node scripts/selftest.mjs
 *
 * Imports the REAL server lib and the REAL client crypto (both standards-only).
 * KV is a Map-backed mock that records write order and TTLs.
 */
import {
  createToken,
  resolveShare,
  getOrMintRoot,
  rootFrom,
  burnStamped,
  stampBurn,
  epochInWindow,
  epochOf,
  PERIOD,
  ROOT_TTL,
  EPOCH_ACCEPT,
  TTL_MAX,
  b64u as srvB64u,
} from '../functions/_lib.js';
import { b64u, unb64u, xor, randomBytes, pbkdf2, aesEncrypt, aesDecrypt, sealMessage } from '../public/crypto.js';
import { sealMessage as sdkSealMessage } from '../sdk/crypto.js';
import { sealMessage as srvSealMessage } from '../functions/_seal.js';
import { verifySlackSignature, signContext, verifyContext } from '../functions/_slack.js';
import { createHmac } from 'node:crypto';

let pass = 0;
let fail = 0;
function check(name, cond) {
  if (cond) {
    pass++;
    console.log(`  ok   ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}`);
  }
}

function mockKV() {
  const store = new Map();
  const puts = [];
  return {
    store,
    puts,
    async get(k, type) {
      const v = store.get(k);
      if (v == null) return null;
      return type === 'json' ? JSON.parse(v) : v;
    },
    async put(k, v, opts) {
      puts.push({ k, ttl: opts?.expirationTtl });
      store.set(k, v);
    },
  };
}

const PEPPER = 'test-pepper';
const message = 'Meet me at 6. Code word: pineapple 🍍. ' + 'x'.repeat(50);

// Deterministic timeline anchored to an epoch boundary, so cross-epoch checks
// can't flake depending on when the test runs.
const E = Math.floor(Date.now() / 1000 / PERIOD);
const t0 = E * PERIOD + 100; // early in epoch E

// --- cold start: lazy mint + pre-mint of next --------------------------------
const kv = mockKV();
const m0 = await getOrMintRoot(kv, t0);
const root0 = await rootFrom(PEPPER, m0.kvRandom);

check('keyId is 12 base64url chars', /^[A-Za-z0-9_-]{12}$/.test(m0.keyId));
check('cold start mints active AND next root', kv.puts.filter((p) => p.k.startsWith('root:')).length === 2);
check('root: writes precede the current pointer', kv.puts.at(-1).k === 'current' && kv.puts.slice(0, -1).every((p) => p.k.startsWith('root:')));
check('all KV writes carry ROOT_TTL', kv.puts.every((p) => p.ttl === ROOT_TTL));

// --- epoch/TTL invariants -----------------------------------------------------
check('EPOCH_ACCEPT covers TTL_MAX (+1 skew)', EPOCH_ACCEPT >= Math.ceil(TTL_MAX / PERIOD) + 1);
check('ROOT_TTL outlives any link a root can sign', ROOT_TTL >= TTL_MAX + 2 * PERIOD);
// A link minted at the last second of epoch E, max TTL, resolvable at its
// final second.
check(
  'epoch window holds at the worst-case boundary',
  epochInWindow(E, epochOf((E + 1) * PERIOD - 1 + TTL_MAX - 1)),
);

// --- server mints id + share (no message involved) ---------------------------
const tok = await createToken(root0, m0.keyId, m0.epoch, 120, t0);
check('id has 6 parts', tok.id.split('.').length === 6);
check('expiresAt stays at parts[2] (client contract)', tok.id.split('.')[2] === String(tok.expiresAt));
check('flags default to 0 at parts[4] (client contract)', tok.id.split('.')[4] === '0');
const share0 = unb64u(tok.serverShare);

// --- client encrypts, splits the key -----------------------------------------
const K = randomBytes(32);
const { iv, ct } = await aesEncrypt(K, message);
const mixed = xor(K, share0); // urlKeyPart (no phrase)

// --- recipient resolves the share before expiry, decrypts --------------------
const r1 = await resolveShare(root0, tok.id, t0 + 10);
check('share resolves before expiry', r1.ok);
const Kback = xor(mixed, unb64u(r1.serverShare));
const decrypted = await aesDecrypt(Kback, iv, ct);
check('round-trips to original plaintext', decrypted === message);
check('serverShare is deterministic', r1.serverShare === tok.serverShare);

// --- expiry: past the TTL the share is withheld ------------------------------
const r2 = await resolveShare(root0, tok.id, t0 + 121);
check('share refused after expiry (410)', !r2.ok && r2.reason === 'expired');

// --- tampered id is rejected by the signature --------------------------------
const badId = tok.id.slice(0, -3) + (tok.id.endsWith('AAA') ? 'BBB' : 'AAA');
const r3 = await resolveShare(root0, badId, t0 + 10);
check('tampered id rejected', !r3.ok);

// --- wrong root / wrong pepper cannot resolve --------------------------------
const r4 = await resolveShare(crypto.getRandomValues(new Uint8Array(32)), tok.id, t0 + 10);
check('wrong root cannot resolve', !r4.ok);
const r5 = await resolveShare(await rootFrom('other-pepper', m0.kvRandom), tok.id, t0 + 10);
check('correct KV random + wrong pepper cannot resolve', !r5.ok);

// --- steady state: same epoch reuses the root, zero writes -------------------
const putsBefore = kv.puts.length;
const mAgain = await getOrMintRoot(kv, t0 + 500);
check('same-epoch call reuses root with zero writes', mAgain.keyId === m0.keyId && kv.puts.length === putsBefore);

// --- hour flip: promotion of the pre-minted next -----------------------------
const cur0 = JSON.parse(kv.store.get('current'));
// A long-TTL link minted late in epoch E must survive the flip (overlap).
const tokLate = await createToken(root0, m0.keyId, m0.epoch, 3600, E * PERIOD + 3500);
const t1 = (E + 1) * PERIOD + 10;
const m1 = await getOrMintRoot(kv, t1);
const root1 = await rootFrom(PEPPER, m1.kvRandom);
check('flip promotes the pre-minted next root (propagation fix)', m1.keyId === cur0.nextKeyId);
check('promoted root differs from the old root', m1.keyId !== m0.keyId);
check('flip pre-mints a fresh next', JSON.parse(kv.store.get('current')).nextKeyId !== cur0.nextKeyId);

const t2 = (E + 1) * PERIOD + 3000; // still inside tokLate's TTL, next epoch
const rOv = await resolveShare(root0, tokLate.id, t2);
check('link minted before the flip still resolves (overlap)', rOv.ok);
const rX = await resolveShare(root1, tokLate.id, t2);
check('new root rejects old id', !rX.ok && rX.reason === 'signature');

// --- keyId is signed: splicing another epoch's keyId is rejected -------------
const parts = tokLate.id.split('.');
parts[3] = m1.keyId; // point the id at the new root
const rSplice = await resolveShare(root1, parts.join('.'), t2);
check('keyId-swapped id rejected by signature', !rSplice.ok && rSplice.reason === 'signature');

// --- retired epoch is rejected ------------------------------------------------
const tOld = t0 - (EPOCH_ACCEPT + 1) * PERIOD; // just past the accept window
const kvOld = mockKV();
const mOld = await getOrMintRoot(kvOld, tOld);
const rootOld = await rootFrom(PEPPER, mOld.kvRandom);
const tokOld = await createToken(rootOld, mOld.keyId, mOld.epoch, 120, tOld);
const r6 = await resolveShare(rootOld, tokOld.id, t0);
check('retired-epoch link rejected', !r6.ok && r6.reason === 'epoch');

// --- burn-after-read: flag is signed, tombstone helpers -----------------------
const tokBurn = await createToken(root0, m0.keyId, m0.epoch, 120, t0, { burn: true });
check('burn token carries flag b at parts[4]', tokBurn.id.split('.')[4] === 'b');
const rB = await resolveShare(root0, tokBurn.id, t0 + 10);
check('burn link resolves and reports its flag', rB.ok && rB.flags === 'b' && rB.nonceB64 === tokBurn.id.split('.')[1]);

// Flipping the flag in either direction must break the signature — otherwise a
// recipient could strip the burn.
const stripParts = tokBurn.id.split('.');
stripParts[4] = '0';
const rStrip = await resolveShare(root0, stripParts.join('.'), t0 + 10);
check('stripped burn flag rejected by signature', !rStrip.ok && rStrip.reason === 'signature');
const addParts = tok.id.split('.');
addParts[4] = 'b';
const rAdd = await resolveShare(root0, addParts.join('.'), t0 + 10);
check('injected burn flag rejected by signature', !rAdd.ok && rAdd.reason === 'signature');
const junkParts = tok.id.split('.');
junkParts[4] = 'z';
const rJunk = await resolveShare(root0, junkParts.join('.'), t0 + 10);
check('unknown flag is malformed', !rJunk.ok && rJunk.reason === 'malformed');

// Tombstone lifecycle against the KV mock.
const kvBurn = mockKV();
const nonceB = tokBurn.id.split('.')[1];
check('burn link starts unstamped', !(await burnStamped(kvBurn, nonceB)));
await stampBurn(kvBurn, nonceB, t0 + 120, t0 + 10);
check('stamp marks the link opened', await burnStamped(kvBurn, nonceB));
check('tombstone TTL matches remaining lifetime', kvBurn.puts.at(-1).ttl === 110);
await stampBurn(kvBurn, 'near-expiry-nonce', t0 + 5, t0);
check('tombstone TTL clamps to the KV minimum (60s)', kvBurn.puts.at(-1).ttl === 60);

// --- secret-phrase path -------------------------------------------------------
const salt = randomBytes(16);
const pk = await pbkdf2('blue-otter-lamp', salt);
const mixedP = xor(xor(K, share0), pk);
const rP = await resolveShare(root0, tok.id, t0 + 10);
const Kp = xor(xor(mixedP, unb64u(rP.serverShare)), pk);
check('correct phrase decrypts', (await aesDecrypt(Kp, iv, ct)) === message);
const wrongPk = await pbkdf2('wrong-phrase', salt);
const Kw = xor(xor(mixedP, unb64u(rP.serverShare)), wrongPk);
let phraseFailed = false;
try {
  await aesDecrypt(Kw, iv, ct);
} catch {
  phraseFailed = true;
}
check('wrong phrase fails to decrypt', phraseFailed);

// --- sealMessage: the shared seal used by create.js, cli.mjs, and the SDK -----
// Proves the one implementation of the split-key payload round-trips both with
// and without a phrase, so all three callers stay in lock-step.
{
  const payload = await sealMessage(tok.serverShare, message, {});
  const [ivB, saltB, mixB, ctB] = payload.split('.');
  const rSeal = await resolveShare(root0, tok.id, t0 + 10);
  const Kseal = xor(unb64u(mixB), unb64u(rSeal.serverShare));
  check('sealMessage omits the salt without a phrase', saltB === '-');
  check('sealMessage round-trips (no phrase)', (await aesDecrypt(Kseal, unb64u(ivB), unb64u(ctB))) === message);
}
{
  const payload = await sealMessage(tok.serverShare, message, { phrase: 'blue-otter-lamp' });
  const [ivB, saltB, mixB, ctB] = payload.split('.');
  check('sealMessage includes a salt with a phrase', saltB !== '-');
  const rSeal = await resolveShare(root0, tok.id, t0 + 10);
  const pkSeal = await pbkdf2('blue-otter-lamp', unb64u(saltB));
  const Kseal = xor(xor(unb64u(mixB), unb64u(rSeal.serverShare)), pkSeal);
  check('sealMessage round-trips (with phrase)', (await aesDecrypt(Kseal, unb64u(ivB), unb64u(ctB))) === message);
}

// --- SDK crypto stays in lock-step with the website ---------------------------
// The published @whisperfox/sdk vendors its own crypto copy; assert its seal
// produces a payload the same server share decrypts, so the mirror can't drift.
{
  const payload = await sdkSealMessage(tok.serverShare, message, {});
  const [ivB, , mixB, ctB] = payload.split('.');
  const rSeal = await resolveShare(root0, tok.id, t0 + 10);
  const Kseal = xor(unb64u(mixB), unb64u(rSeal.serverShare));
  check('sdk sealMessage round-trips (parity with website)', (await aesDecrypt(Kseal, unb64u(ivB), unb64u(ctB))) === message);
}

// --- server-side seal (Slack quick path) stays in lock-step -------------------
{
  const payload = await srvSealMessage(tok.serverShare, message, {});
  const [ivB, , mixB, ctB] = payload.split('.');
  const rSeal = await resolveShare(root0, tok.id, t0 + 10);
  const Kseal = xor(unb64u(mixB), unb64u(rSeal.serverShare));
  check('server _seal round-trips (parity with website)', (await aesDecrypt(Kseal, unb64u(ivB), unb64u(ctB))) === message);
}

// --- Slack request-signature verification -------------------------------------
{
  const secret = 'slack-signing-secret';
  const ts = String(Math.floor(t0));
  const now = Number(ts);
  const rawBody = 'command=%2Fwhisperfox&text=quick+hunter2&response_url=https%3A%2F%2Fhooks.slack.com%2Fx';
  const good = 'v0=' + createHmac('sha256', secret).update(`v0:${ts}:${rawBody}`).digest('hex');
  const hdr = (sig, t) => new Headers({ 'x-slack-signature': sig, 'x-slack-request-timestamp': String(t) });
  check('slack signature accepts a valid request', await verifySlackSignature(hdr(good, ts), rawBody, secret, now));
  check('slack signature rejects a tampered body', !(await verifySlackSignature(hdr(good, ts), rawBody + 'x', secret, now)));
  check('slack signature rejects a wrong secret', !(await verifySlackSignature(hdr(good, ts), rawBody, 'other-secret', now)));
  check('slack signature rejects a stale timestamp', !(await verifySlackSignature(hdr(good, ts), rawBody, secret, now + 400)));
  check('slack signature rejects a missing header', !(await verifySlackSignature(hdr('', ts), rawBody, secret, now)));
}

// --- signed handoff / OAuth-state context -------------------------------------
{
  const secret = 'state-secret';
  const ctxToken = await signContext({ response_url: 'https://hooks.slack.com/x', channel_id: 'C1' }, secret, 100, t0);
  const decoded = await verifyContext(ctxToken, secret, t0 + 10);
  check('signContext verifies and decodes its payload', !!decoded && decoded.response_url === 'https://hooks.slack.com/x' && decoded.channel_id === 'C1');
  check('signContext rejects after exp', !(await verifyContext(ctxToken, secret, t0 + 101)));
  check('signContext rejects a wrong secret', !(await verifyContext(ctxToken, 'other-secret', t0 + 10)));
  const tampered = ctxToken.slice(0, -2) + (ctxToken.endsWith('AA') ? 'BB' : 'AA');
  check('signContext rejects a tampered token', !(await verifyContext(tampered, secret, t0 + 10)));
}

// --- base64url helpers agree client<->server ----------------------------------
const probe = randomBytes(20);
check('b64url client==server', b64u(probe) === srvB64u(probe));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
