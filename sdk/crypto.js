/**
 * Crypto for @whisperfox/sdk. Pure Web Crypto (standards-only), so it runs the
 * same in Node >= 19, modern browsers, and bundler targets.
 *
 * This file is a deliberate MIRROR of ../public/crypto.js: the SDK is published
 * as a standalone package and cannot reach outside its own directory, and the
 * project already keeps parallel crypto copies across deploy surfaces (browser
 * vs Worker). scripts/selftest.mjs asserts this copy's sealMessage stays in
 * lock-step with the website's — keep the two in sync.
 *
 *   urlKeyPart = K  XOR  serverShare  [ XOR  PBKDF2(secretPhrase, salt) ]
 *
 * urlKeyPart + iv + ciphertext travel in the link's #fragment (never sent to a
 * server). To read: K = urlKeyPart XOR serverShare [ XOR PBKDF2(phrase) ].
 */

const encoder = new TextEncoder();

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

/**
 * Cryptographically secure random bytes.
 * @param {number} n Byte count.
 * @returns {Uint8Array}
 */
export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Bytewise XOR of two equal-length byte arrays.
 * @param {Uint8Array} a
 * @param {Uint8Array} b Must be at least as long as `a`.
 * @returns {Uint8Array} Result with `a`'s length.
 */
export function xor(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/**
 * Derive a 256-bit key from a secret phrase (PBKDF2, SHA-256, 600k iterations).
 * @param {string} phrase
 * @param {Uint8Array} salt
 * @returns {Promise<Uint8Array>} 32-byte derived key.
 */
export async function pbkdf2(phrase, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(phrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    material,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Encrypt UTF-8 text with AES-256-GCM under a fresh random IV.
 * @param {Uint8Array} keyBytes 32-byte key.
 * @param {string} plaintext
 * @returns {Promise<{iv: Uint8Array, ct: Uint8Array}>} 12-byte IV and ciphertext (tag included).
 */
export async function aesEncrypt(keyBytes, plaintext) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(plaintext)));
  return { iv, ct };
}

/**
 * Seal a message into the `/view#<id>~<payload>` fragment payload
 * `iv.salt.urlKeyPart.ct` (base64url, `.`-joined). Mirrors sealMessage in
 * ../public/crypto.js: a fresh random 256-bit K encrypts the message, and
 * `urlKeyPart = K XOR serverShare [XOR PBKDF2(phrase, salt)]`. `salt` is `-`
 * when no phrase is used.
 * @param {string} serverShareB64 base64url server key-share from POST /api/create.
 * @param {string} message UTF-8 plaintext (the caller enforces any length cap).
 * @param {{phrase?: string}} [opts] Optional secret phrase folded into the key.
 * @returns {Promise<string>} The fragment payload (everything after the `~`).
 */
export async function sealMessage(serverShareB64, message, opts = {}) {
  const share = unb64u(serverShareB64);
  const K = randomBytes(32);
  const { iv, ct } = await aesEncrypt(K, message);
  let saltSeg = '-';
  let mixed = xor(K, share);
  if (opts.phrase) {
    const salt = randomBytes(16);
    mixed = xor(mixed, await pbkdf2(opts.phrase, salt));
    saltSeg = b64u(salt);
  }
  return [b64u(iv), saltSeg, b64u(mixed), b64u(ct)].join('.');
}
