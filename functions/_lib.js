/**
 * Server-side crypto for WhisperFox. Runs in the Cloudflare Worker (Pages
 * Functions) and is also imported by scripts/selftest.mjs under Node, so it
 * uses only the standard Web Crypto + TextEncoder + btoa/atob available in
 * both. The module has no I/O of its own: KV arrives as a duck-typed
 * {get, put} parameter.
 *
 * Nothing about a message's content is ever stored. Key material comes from
 * two places:
 *   - ROOT_PEPPER: a static env secret.
 *   - A per-hour random 32-byte value in Workers KV, erased by KV TTL ~27h
 *     after minting (see getOrMintRoot for the mint/promote lifecycle).
 *
 *   root        = HMAC(ROOT_PEPPER, kvRandom)          // effective per-epoch root
 *   serverShare = HMAC(root, "share:" + nonce)         // the withheld key-share
 *   idSignature = HMAC(root, "id4:" + epoch + nonce + expiresAt + keyId + flags)
 *
 * A link id embeds {epoch, nonce, expiresAt, keyId, flags, signature}. keyId
 * is a SHA-256 prefix of the KV random that minted the link; once KV expires
 * that value, the share can no longer be derived. The one per-message record
 * is opt-in: burn-after-read links (flags 'b') get a content-free
 * "already opened" tombstone in KV on first read (see stampBurn) — its key is
 * the link's nonce, which is already public in the link itself. See README.md
 * for the security model.
 */

export const PERIOD = 3600;       // key-rotation epoch length, seconds (1 hour)
export const TTL_MIN = 60;        // 1 minute
export const TTL_MAX = 86400;     // 24 hours
/** Accept links from the last N epochs. A link minted at the last second of
 *  epoch e expires at most ceil(TTL_MAX/PERIOD) epochs later, so
 *  ceil(TTL_MAX/PERIOD) is exact; +1 covers resolver clock skew. */
export const EPOCH_ACCEPT = Math.ceil(TTL_MAX / PERIOD) + 1;
/** KV lifetime of an epoch's random value. A *next* root minted at the start
 *  of hour e serves links created through hour e+1, which live at most
 *  TTL_MAX past that — EPOCH_ACCEPT+1 periods from mint, with ≥1h margin. */
export const ROOT_TTL = (EPOCH_ACCEPT + 2) * PERIOD;

const KEY_ID_RE = /^[A-Za-z0-9_-]{12}$/;

const encoder = new TextEncoder();

/**
 * The epoch index containing a point in time.
 * @param {number} nowSec Unix time in seconds.
 * @returns {number}
 */
export function epochOf(nowSec) {
  return Math.floor(nowSec / PERIOD);
}

/**
 * Whether a link's epoch is currently accepted: at most one epoch ahead
 * (colo clock skew) and at most EPOCH_ACCEPT epochs behind.
 * @param {number} epoch Epoch embedded in the link id.
 * @param {number} currentEpoch Epoch containing the current time.
 * @returns {boolean}
 */
export function epochInWindow(epoch, currentEpoch) {
  return epoch <= currentEpoch + 1 && epoch >= currentEpoch - EPOCH_ACCEPT;
}

// Kept intentionally in sync with public/crypto.js (separate deploy surfaces);
// scripts/selftest.mjs asserts parity.

/**
 * Encode bytes as unpadded base64url.
 * @param {Uint8Array | ArrayBuffer} bytes
 * @returns {string}
 */
export function b64u(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a base64url string (padded or not) to bytes.
 * @param {string} str
 * @returns {Uint8Array}
 * @throws {Error} If the input is not valid base64.
 */
export function unb64u(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const pad = s + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmac(keyBytes, msg) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = typeof msg === 'string' ? encoder.encode(msg) : msg;
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

/**
 * Derive the effective per-epoch root; the KV random is never used as a key
 * directly.
 * @param {string} pepperStr The ROOT_PEPPER secret.
 * @param {Uint8Array} kvRandom The epoch's random value from KV.
 * @returns {Promise<Uint8Array>} 32-byte HMAC-SHA-256 output.
 */
export function rootFrom(pepperStr, kvRandom) {
  return hmac(encoder.encode(pepperStr), kvRandom);
}

/**
 * Pepper-independent name for a KV random, computable from the stored value
 * alone.
 * @param {Uint8Array} kvRandom
 * @returns {Promise<string>} 12-character base64url SHA-256 prefix.
 */
export async function keyIdOf(kvRandom) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', kvRandom));
  return b64u(digest).slice(0, 12);
}

/**
 * Constant-time byte-array comparison (also used for API-key checks; the
 * early length-mismatch return leaks only length, which isn't secret).
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

// Link flags: '0' plain, 'b' burn-after-read. Anything else is malformed —
// unknown flags must fail parsing, not silently verify.
const FLAGS_RE = /^[0b]$/;

/**
 * Parse a 6-part link id.
 * @param {string} id `epoch.nonce.expiresAt.keyId.flags.signature`.
 * @returns {{epoch: number, nonceB64: string, expiresAt: number, keyId: string, flags: string, sigB64: string} | null}
 *   Parsed fields, or null for anything malformed.
 */
export function parseId(id) {
  const parts = String(id).split('.');
  if (parts.length !== 6) return null;
  const [epochStr, nonceB64, expStr, keyId, flags, sigB64] = parts;
  const epoch = Number(epochStr);
  const expiresAt = Number(expStr);
  if (!Number.isInteger(epoch) || !Number.isInteger(expiresAt)) return null;
  if (!KEY_ID_RE.test(keyId)) return null;
  if (!FLAGS_RE.test(flags)) return null;
  return { epoch, nonceB64, expiresAt, keyId, flags, sigB64 };
}

/** HMAC payload for a link id's signature; shared by createToken and
 *  resolveShare. flags is inside the signed payload — stripping or flipping
 *  the burn flag must invalidate the signature. */
function idPayload(epoch, nonceB64, expiresAt, keyId, flags) {
  return `id4:${epoch}:${nonceB64}:${expiresAt}:${keyId}:${flags}`;
}

/**
 * Return the current epoch's root, minting lazily.
 *
 * The `current` KV record carries the active random plus a pre-minted next one.
 * On an hour flip the next is promoted — its `root:` key has been in KV for a
 * full hour, so every colo already sees it (no propagation gap) — and a fresh
 * next is pre-minted for the following hour. Promotion is deterministic, so
 * colos racing at the boundary all activate the same root; the losers merely
 * orphan spare next-candidates that expire unreferenced.
 *
 * Write ordering matters: a `root:{keyId}` key is always written BEFORE any
 * `current` that references it, so a partial failure yields a retryable 500,
 * never a minted-but-unresolvable link.
 *
 * @param {{get: Function, put: Function}} kv Workers KV namespace (or a mock).
 * @param {number} nowSec Unix time in seconds.
 * @returns {Promise<{epoch: number, keyId: string, kvRandom: Uint8Array}>}
 */
export async function getOrMintRoot(kv, nowSec) {
  const epoch = epochOf(nowSec);
  const current = await kv.get('current', 'json');

  if (current && current.epoch === epoch) {
    return { epoch, keyId: current.keyId, kvRandom: unb64u(current.rootB64) };
  }
  // Another colo's clock is slightly ahead: use its state rather than
  // overwriting newer with older. resolveShare accepts epoch <= current+1.
  if (current && current.epoch > epoch) {
    return { epoch: current.epoch, keyId: current.keyId, kvRandom: unb64u(current.rootB64) };
  }

  const nextRandom = crypto.getRandomValues(new Uint8Array(32));
  const nextKeyId = await keyIdOf(nextRandom);
  const nextRootB64 = b64u(nextRandom);

  let keyId, rootB64;
  if (current && current.epoch === epoch - 1 && current.nextKeyId && current.nextRootB64) {
    // Normal hourly flip: promote the pre-minted (already propagated) next.
    keyId = current.nextKeyId;
    rootB64 = current.nextRootB64;
    await kv.put('root:' + nextKeyId, nextRootB64, { expirationTtl: ROOT_TTL });
  } else {
    // Cold start or long-dormant site: mint the active root too. Only this
    // path has the ~60s cross-colo propagation window (the share endpoint
    // answers 503-retry, not 410, for fresh epochs it can't find).
    const activeRandom = crypto.getRandomValues(new Uint8Array(32));
    keyId = await keyIdOf(activeRandom);
    rootB64 = b64u(activeRandom);
    await kv.put('root:' + keyId, rootB64, { expirationTtl: ROOT_TTL });
    await kv.put('root:' + nextKeyId, nextRootB64, { expirationTtl: ROOT_TTL });
  }
  await kv.put(
    'current',
    JSON.stringify({ epoch, keyId, rootB64, nextKeyId, nextRootB64 }),
    { expirationTtl: ROOT_TTL },
  );
  return { epoch, keyId, kvRandom: unb64u(rootB64) };
}

/**
 * Mint a signed, self-expiring id and its serverShare for a new message.
 * @param {Uint8Array} root Effective per-epoch root (see rootFrom).
 * @param {string} keyId Name of the KV random behind `root` (see keyIdOf).
 * @param {number} epoch Epoch the root belongs to.
 * @param {number} ttl Message lifetime in seconds.
 * @param {number} nowSec Unix time in seconds.
 * @param {{burn?: boolean}} [opts] burn: link dies on first read (see stampBurn).
 * @returns {Promise<{id: string, serverShare: string, expiresAt: number}>}
 *   The link id, the base64url key-share, and the expiry timestamp.
 */
export async function createToken(root, keyId, epoch, ttl, nowSec, opts) {
  const now = Math.floor(nowSec);
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const nonceB64 = b64u(nonce);
  const expiresAt = now + ttl;
  const flags = opts?.burn ? 'b' : '0';
  const share = await hmac(root, 'share:' + nonceB64);
  const sig = await hmac(root, idPayload(epoch, nonceB64, expiresAt, keyId, flags));
  const id = `${epoch}.${nonceB64}.${expiresAt}.${keyId}.${flags}.${b64u(sig)}`;
  return { id, serverShare: b64u(share), expiresAt };
}

/**
 * Verify a link id against its (already looked-up) effective root and, if it's
 * authentic and unexpired, reproduce its serverShare.
 * @param {Uint8Array} root Effective per-epoch root (see rootFrom).
 * @param {string} id The link id to verify.
 * @param {number} nowSec Unix time in seconds.
 * @returns {Promise<{ok: true, serverShare: string, expiresAt: number, flags: string, nonceB64: string} | {ok: false, reason: string}>}
 *   The base64url key-share, or {ok: false} for anything malformed, forged,
 *   from a retired epoch, or past its deadline.
 */
export async function resolveShare(root, id, nowSec) {
  const p = parseId(id);
  if (!p) return { ok: false, reason: 'malformed' };

  const now = Math.floor(nowSec);
  // Reject retired epochs (and implausible future ones); their KV randoms
  // stop existing shortly after.
  if (!epochInWindow(p.epoch, epochOf(now))) return { ok: false, reason: 'epoch' };

  const expectedSig = await hmac(root, idPayload(p.epoch, p.nonceB64, p.expiresAt, p.keyId, p.flags));
  let providedSig;
  try {
    providedSig = unb64u(p.sigB64);
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (!timingSafeEqual(expectedSig, providedSig)) return { ok: false, reason: 'signature' };

  if (now >= p.expiresAt) return { ok: false, reason: 'expired' };

  const share = await hmac(root, 'share:' + p.nonceB64);
  return { ok: true, serverShare: b64u(share), expiresAt: p.expiresAt, flags: p.flags, nonceB64: p.nonceB64 };
}

/**
 * Whether a burn-after-read link has already been opened.
 * Call only after resolveShare succeeds — forged ids must never reach KV.
 * @param {{get: Function}} kv Workers KV namespace (or a mock).
 * @param {string} nonceB64 The link's nonce (already public in the link).
 * @returns {Promise<boolean>}
 */
export async function burnStamped(kv, nonceB64) {
  return (await kv.get('burn:' + nonceB64)) !== null;
}

/**
 * Record that a burn-after-read link has been opened. The tombstone is
 * content-free — its key is the link's own public nonce — and KV erases it at
 * the link's expiry (KV's minimum TTL is 60s, so it may outlive the message
 * by up to a minute; harmless, the share endpoint refuses expired ids first).
 *
 * Best-effort semantics: KV has no compare-and-set and ~60s cross-colo
 * propagation, so two near-simultaneous opens can both succeed. Burn is a
 * hardening layer on top of the TTL, not an exactly-once guarantee.
 * @param {{put: Function}} kv Workers KV namespace (or a mock).
 * @param {string} nonceB64 The link's nonce.
 * @param {number} expiresAt Link expiry, unix seconds.
 * @param {number} nowSec Unix time in seconds.
 * @returns {Promise<void>}
 */
export async function stampBurn(kv, nonceB64, expiresAt, nowSec) {
  const ttl = Math.max(60, expiresAt - Math.floor(nowSec));
  await kv.put('burn:' + nonceB64, '1', { expirationTtl: ttl });
}
