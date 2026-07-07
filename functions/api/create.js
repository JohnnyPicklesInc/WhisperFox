/**
 * POST /api/create  { ttl, burn?, turnstileToken? }  ->  { id, serverShare }
 *
 * The request body carries no message and no key — only the requested TTL, an
 * optional burn-after-read flag, and a CAPTCHA token. Mints a signed,
 * self-expiring id and the matching key-share (see ../_lib.js).
 *
 * Instead of a CAPTCHA token, automated callers may send
 * `Authorization: Bearer <key>` matching the API_KEYS env secret
 * (comma-separated). A presented-but-wrong key fails closed with 403 rather
 * than falling through to a confusing captcha error.
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

  const apiAuth = checkApiKey(request, env);
  if (apiAuth === 'invalid') return json({ error: 'invalid api key' }, 403);
  if (apiAuth !== 'ok') {
    const ts = await verifyTurnstile(body?.turnstileToken, env, request);
    if (!ts.ok) {
      // Surface Cloudflare's own error codes so a misconfig is diagnosable
      // (e.g. invalid-input-secret, timeout-or-duplicate, hostname mismatch).
      return json({ error: 'captcha verification failed', codes: ts.codes }, 403);
    }
  }

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
 *   or no Bearer header was sent — the caller falls back to Turnstile.
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

/**
 * Verify a Turnstile response token with Cloudflare.
 * @param {string | undefined} token Token produced by the Turnstile widget.
 * @param {object} env Worker environment (reads TURNSTILE_SECRET).
 * @param {Request} request Used for the client IP hint.
 * @returns {Promise<{ok: boolean, codes?: string[]}>} ok, plus Cloudflare's
 *   error-codes array when it rejects (for diagnosing config mismatches).
 */
async function verifyTurnstile(token, env, request) {
  const secret = env.TURNSTILE_SECRET;
  // Dev / self-host without a real Turnstile key: skip the network call for the
  // official always-pass test secrets (and when unset).
  if (!secret || secret.startsWith('1x0000000000000000000000000000000')) return { ok: true };
  if (!token) return { ok: false, codes: ['missing-input-response'] };
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) form.append('remoteip', ip);
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
    const d = await r.json();
    return { ok: d.success === true, codes: d['error-codes'] };
  } catch {
    return { ok: false, codes: ['siteverify-unreachable'] };
  }
}
