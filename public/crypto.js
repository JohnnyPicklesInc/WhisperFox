/**
 * Client-side crypto for WhisperFox. Pure Web Crypto — runs in the browser,
 * and (being standards-only) is also imported by scripts/selftest.mjs under
 * Node.
 *
 * The message is encrypted with a fresh random 256-bit key K that exists only
 * here. K is split so it can only be reassembled with the server's key-share
 * (released before the TTL) and, optionally, a user "secret phrase":
 *
 *   urlKeyPart = K  XOR  serverShare  [ XOR  PBKDF2(secretPhrase, salt) ]
 *
 * urlKeyPart + iv + ciphertext travel in the link's #fragment (never sent to a
 * server). To read: K = urlKeyPart XOR serverShare [ XOR PBKDF2(phrase) ].
 *
 * b64u/unb64u are intentionally duplicated in functions/_lib.js — the browser
 * and the Worker are separate deploy surfaces; scripts/selftest.mjs asserts
 * they agree.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
 * Decrypt AES-256-GCM ciphertext back to UTF-8 text.
 * @param {Uint8Array} keyBytes 32-byte key.
 * @param {Uint8Array} iv 12-byte IV from aesEncrypt.
 * @param {Uint8Array} ct Ciphertext (tag included).
 * @returns {Promise<string>}
 * @throws {Error} If the key is wrong or the ciphertext was tampered with.
 */
export async function aesDecrypt(keyBytes, iv, ct) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return decoder.decode(pt);
}

/**
 * Whether subtle Web Crypto is usable. Requires a secure context (HTTPS or
 * localhost); false over plain http://<ip>.
 * @returns {boolean}
 */
export function webCryptoAvailable() {
  return !!(globalThis.isSecureContext && globalThis.crypto?.subtle);
}
