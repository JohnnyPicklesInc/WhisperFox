/**
 * Server-side message seal for the Slack `quick` path (see
 * api/slack/command.js). Standards-only Web Crypto, self-contained within
 * functions/ so the Worker bundle never reaches into public/. It mirrors
 * sealMessage in public/crypto.js and scripts/selftest.mjs asserts the two
 * agree — keep them in sync.
 *
 * IMPORTANT: sealing HERE means the plaintext is handled server-side. Only the
 * opt-in `quick` command uses it. The default Slack handoff and the SDK seal in
 * the caller (browser / user's process), never on the server.
 */
import { b64u, unb64u } from './_lib.js';

const encoder = new TextEncoder();

function xor(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

async function pbkdf2(phrase, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(phrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, material, 256);
  return new Uint8Array(bits);
}

/**
 * Seal a message into the `iv.salt.urlKeyPart.ct` fragment payload — the same
 * split-key contract as public/crypto.js sealMessage.
 * @param {string} serverShareB64 base64url server key-share.
 * @param {string} message UTF-8 plaintext.
 * @param {{phrase?: string}} [opts]
 * @returns {Promise<string>} The fragment payload (everything after the `~`).
 */
export async function sealMessage(serverShareB64, message, opts = {}) {
  const share = unb64u(serverShareB64);
  const K = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', K, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(message)));
  let saltSeg = '-';
  let mixed = xor(K, share);
  if (opts.phrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    mixed = xor(mixed, await pbkdf2(opts.phrase, salt));
    saltSeg = b64u(salt);
  }
  return [b64u(iv), saltSeg, b64u(mixed), b64u(ct)].join('.');
}
