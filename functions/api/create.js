/**
 * POST /api/create  { ttl, burn? }  ->  { id, serverShare }
 *
 * The request body carries no message and no key — only the requested TTL and
 * an optional burn-after-read flag. Mints a signed, self-expiring id and the
 * matching key-share (see ../_lib.js).
 *
 * Abuse protection is handled at the Cloudflare edge (a rate-limit rule on
 * this path plus Bot Fight Mode), so the endpoint is otherwise open. Callers
 * may still send `Authorization: Bearer <key>` matching the API_KEYS env
 * secret (comma-separated); a presented-but-wrong key fails closed with 403.
 */
import { createToken, getOrMintRoot, rootFrom, timingSafeEqual, TTL_MIN, TTL_MAX } from '../_lib.js';
import { json } from '../_http.js';

const encoder = new TextEncoder();

export async function onRequestPost({ request, env }) {
  if (!env.ROOT_PEPPER || !env.ROOT_KV) {
    return json({ error: 'server misconfigured: ROOT_PEPPER or ROOT_KV unset' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }

  const ttl = Number(body?.ttl);
  if (!Number.isInteger(ttl) || ttl < TTL_MIN || ttl > TTL_MAX) {
    return json({ error: `ttl must be an integer ${TTL_MIN}-${TTL_MAX} seconds` }, 400);
  }

  // A presented-but-wrong API key fails closed; an absent key is fine (the
  // edge rate-limit rule, not the key, is what gates anonymous callers).
  if (checkApiKey(request, env) === 'invalid') return json({ error: 'invalid api key' }, 403);

  const { kvRandom, keyId, epoch } = await getOrMintRoot(env.ROOT_KV, Date.now() / 1000);
  const root = await rootFrom(env.ROOT_PEPPER, kvRandom);
  const tok = await createToken(root, keyId, epoch, ttl, Date.now() / 1000, { burn: body?.burn === true });
  return json({ id: tok.id, serverShare: tok.serverShare });
}

/**
 * Match a Bearer token against the API_KEYS env secret.
 * @param {Request} request
 * @param {object} env Worker environment (reads API_KEYS, comma-separated).
 * @returns {'ok' | 'invalid' | 'absent'} 'absent' when no keys are configured
 *   or no Bearer header was sent — the request proceeds either way (the edge
 *   rate limit is what gates it); 'invalid' is a wrong key and fails closed.
 */
function checkApiKey(request, env) {
  const keys = String(env.API_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!keys.length) return 'absent';
  const auth = request.headers.get('authorization') || '';
  if (!auth.toLowerCase().startsWith('bearer ')) return 'absent';
  const candidate = encoder.encode(auth.slice(7).trim());
  // Compare against every key so timing reveals only the key count.
  let matched = false;
  for (const key of keys) {
    if (timingSafeEqual(candidate, encoder.encode(key))) matched = true;
  }
  return matched ? 'ok' : 'invalid';
}
