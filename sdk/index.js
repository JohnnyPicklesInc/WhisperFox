/**
 * @whisperfox/sdk — create a WhisperFox self-destructing link from Node or the
 * browser, with encryption happening IN-PROCESS. The server never sees the
 * plaintext, the key, or the phrase (zero-knowledge): the SDK asks the API only
 * for a signed id + a server key-share, then seals the message locally into the
 * link's #fragment. Same split-key flow as the website and the CLI.
 *
 *   import { createSecret } from '@whisperfox/sdk';
 *   const { link } = await createSecret('the wifi password is hunter2', {
 *     ttl: 3600, burn: true, apiKey: process.env.WHISPERFOX_API_KEY,
 *   });
 *   // share `link`; it stops working after the TTL (or first read, if burn)
 *
 * Requires a Web Crypto + fetch runtime: Node >= 19, modern browsers, or any
 * bundler target. Zero dependencies.
 */
import { sealMessage } from './crypto.js';

/** Max message length — mirrors the website and the server contract. */
export const MAX_MESSAGE = 500;
const TTL_MIN = 60;
const TTL_MAX = 86400;
const DEFAULT_BASE_URL = 'https://whisperfox.pages.dev';

/**
 * Create a self-destructing WhisperFox link. Encryption is local; only the
 * `ttl`/`burn` flags ever reach the server — never the message, key, or phrase.
 *
 * @param {string} message UTF-8 plaintext, up to 500 characters.
 * @param {object} [opts]
 * @param {number} [opts.ttl=900] Lifetime in seconds (60–86400).
 * @param {string} [opts.phrase] Optional secret phrase, folded into the key locally.
 *   Share it out-of-band; the recipient needs it to open the link.
 * @param {boolean} [opts.burn=false] Link stops working after the first open.
 * @param {string} [opts.apiKey] Bearer key (set `API_KEYS` server-side). Omit against local dev.
 * @param {string} [opts.baseUrl] WhisperFox origin, no trailing slash. Defaults to the hosted instance.
 * @param {typeof fetch} [opts.fetch] Custom fetch (defaults to the global).
 * @returns {Promise<{link: string, id: string, expiresAt: number}>} The shareable
 *   link, the server id, and the unix-seconds expiry.
 * @throws {Error} On validation failure or a non-2xx API response.
 */
export async function createSecret(message, opts = {}) {
  const {
    ttl = 900,
    phrase,
    burn = false,
    apiKey,
    baseUrl = DEFAULT_BASE_URL,
    fetch: fetchImpl = globalThis.fetch,
  } = opts;

  if (typeof message !== 'string' || !message) {
    throw new Error('message must be a non-empty string');
  }
  if (message.length > MAX_MESSAGE) {
    throw new Error(`message is limited to ${MAX_MESSAGE} characters (got ${message.length})`);
  }
  if (!Number.isInteger(ttl) || ttl < TTL_MIN || ttl > TTL_MAX) {
    throw new Error(`ttl must be an integer ${TTL_MIN}-${TTL_MAX} seconds`);
  }
  if (typeof fetchImpl !== 'function') {
    throw new Error('no fetch available; pass opts.fetch on runtimes without a global fetch');
  }

  const origin = baseUrl.replace(/\/+$/, '');
  const headers = { 'content-type': 'application/json' };
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;

  const res = await fetchImpl(`${origin}/api/create`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ ttl, burn }),
  });
  if (!res.ok) {
    let detail = '';
    try {
      const e = await res.json();
      detail = e?.error ? `: ${e.error}` : '';
    } catch { /* non-JSON body */ }
    throw new Error(`WhisperFox create failed (${res.status})${detail}`);
  }
  const { id, serverShare } = await res.json();

  const payload = await sealMessage(serverShare, message, { phrase });
  // expiresAt is signed into the id at parts[2] (see functions/_lib.js).
  const expiresAt = Number(id.split('.')[2]);
  return { link: `${origin}/view#${id}~${payload}`, id, expiresAt };
}
