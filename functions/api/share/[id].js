/**
 * GET /api/share/:id  ->  { serverShare }   (or 410 Gone / 503 retry)
 *
 * Reproduces the message's key-share IFF the signed id is authentic and still
 * within its TTL. Past the deadline (or if forged / from a retired epoch) it
 * returns 410 and the message can no longer be decrypted — the epoch's KV
 * random has expired and the share can no longer be derived.
 *
 * 503 is returned only when the id claims a fresh epoch whose root isn't
 * visible at this colo yet (possible for ~60s after a cold start, since roots
 * are otherwise pre-minted an hour before use). The client treats non-410 as
 * retryable.
 *
 * Burn-after-read links (signed flag 'b') additionally check a content-free
 * "already opened" tombstone in KV — only AFTER the signature verifies, so
 * forged ids never trigger extra KV traffic. Best-effort: KV has no
 * compare-and-set and ~60s cross-colo propagation, so two near-simultaneous
 * opens can both succeed; burn hardens the TTL, it doesn't replace it.
 */
import { resolveShare, parseId, rootFrom, unb64u, epochOf, epochInWindow, burnStamped, stampBurn } from '../../_lib.js';
import { json } from '../../_http.js';

export async function onRequestGet({ params, env }) {
  if (!env.ROOT_PEPPER || !env.ROOT_KV) {
    return json({ error: 'server misconfigured: ROOT_PEPPER or ROOT_KV unset' }, 500);
  }

  // Cheap pre-checks before touching KV: anything malformed, self-admittedly
  // expired, or outside the epoch window is 410 without burning a read.
  const p = parseId(params.id);
  if (!p) return json({ error: 'gone' }, 410);
  const now = Math.floor(Date.now() / 1000);
  const current = epochOf(now);
  if (now >= p.expiresAt) return json({ error: 'gone' }, 410);
  if (!epochInWindow(p.epoch, current)) return json({ error: 'gone' }, 410);

  const kvRandomB64 = await env.ROOT_KV.get('root:' + p.keyId);
  if (!kvRandomB64) {
    // A fresh root may still be propagating cross-colo (cold-start hour only).
    if (p.epoch >= current - 1) return json({ error: 'retry' }, 503, { 'retry-after': '10' });
    return json({ error: 'gone' }, 410); // root erased by KV TTL
  }

  const root = await rootFrom(env.ROOT_PEPPER, unb64u(kvRandomB64));
  const res = await resolveShare(root, params.id, now);
  if (!res.ok) return json({ error: 'gone' }, 410);

  if (res.flags === 'b') {
    if (await burnStamped(env.ROOT_KV, res.nonceB64)) return json({ error: 'gone' }, 410);
    // Awaited BEFORE the share is released: if the stamp fails, a 500 (retry)
    // beats handing out the share unburned.
    await stampBurn(env.ROOT_KV, res.nonceB64, res.expiresAt, now);
  }

  return json({ serverShare: res.serverShare });
}
