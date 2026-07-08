/**
 * Slack helpers for WhisperFox: inbound request-signature verification and
 * signed, self-expiring context tokens (the browser-handoff blob and the OAuth
 * state). Standards-only Web Crypto — runs in the Worker and imports cleanly
 * under Node for the selftest. No I/O of its own.
 *
 * Slack signs each request as:
 *   v0=hex(HMAC_SHA256(signingSecret, "v0:" + timestamp + ":" + rawBody))
 * We recompute over the RAW body and constant-time compare, rejecting
 * timestamps older than 5 minutes to blunt replay.
 *
 * signContext/verifyContext mint tamper-proof blobs as `b64u(json).b64u(HMAC)`
 * with an embedded `exp`, so the browser can carry a Slack response_url back to
 * us without being able to forge or outlive it.
 */
import { b64u, unb64u, timingSafeEqual } from './_lib.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Max age (seconds) for a Slack request timestamp — replay guard. */
export const SLACK_MAX_SKEW = 300;

async function hmacBytes(secret, msg) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = typeof msg === 'string' ? encoder.encode(msg) : msg;
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

/**
 * Verify a Slack request signature over the RAW request body.
 * @param {Headers} headers Reads x-slack-signature and x-slack-request-timestamp.
 * @param {string} rawBody The exact body text (the signature is over bytes, so
 *   read `request.text()` before any parsing).
 * @param {string} signingSecret The Slack app signing secret.
 * @param {number} [nowSec] Unix seconds (injectable for tests).
 * @returns {Promise<boolean>}
 */
export async function verifySlackSignature(headers, rawBody, signingSecret, nowSec = Date.now() / 1000) {
  if (!signingSecret) return false;
  const sig = headers.get('x-slack-signature') || '';
  const ts = headers.get('x-slack-request-timestamp') || '';
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || Math.abs(Math.floor(nowSec) - tsNum) > SLACK_MAX_SKEW) return false;
  if (!sig.startsWith('v0=')) return false;
  const expected = 'v0=' + toHex(await hmacBytes(signingSecret, `v0:${ts}:${rawBody}`));
  return timingSafeEqual(encoder.encode(expected), encoder.encode(sig));
}

/**
 * Mint a tamper-proof, self-expiring token carrying a small JSON context.
 * @param {object} obj JSON-serializable context (an `exp` field is added).
 * @param {string} secret HMAC key.
 * @param {number} ttlSec Lifetime in seconds.
 * @param {number} [nowSec] Unix seconds (injectable for tests).
 * @returns {Promise<string>} `b64u(json).b64u(sig)`.
 */
export async function signContext(obj, secret, ttlSec, nowSec = Date.now() / 1000) {
  const body = { ...obj, exp: Math.floor(nowSec) + ttlSec };
  const payload = b64u(encoder.encode(JSON.stringify(body)));
  const sig = b64u(await hmacBytes(secret, payload));
  return `${payload}.${sig}`;
}

/**
 * Verify and decode a signContext token.
 * @param {string} token
 * @param {string} secret
 * @param {number} [nowSec] Unix seconds.
 * @returns {Promise<object | null>} The context, or null if forged/expired/malformed.
 */
export async function verifyContext(token, secret, nowSec = Date.now() / 1000) {
  if (!secret || typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if (dot < 1) return null;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  let expected;
  try {
    expected = b64u(await hmacBytes(secret, payload));
  } catch {
    return null;
  }
  if (!timingSafeEqual(encoder.encode(expected), encoder.encode(sig))) return null;
  let obj;
  try {
    obj = JSON.parse(decoder.decode(unb64u(payload)));
  } catch {
    return null;
  }
  if (!obj || typeof obj.exp !== 'number' || Math.floor(nowSec) >= obj.exp) return null;
  return obj;
}
