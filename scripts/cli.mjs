/**
 * WhisperFox CLI — create a self-destructing link from the terminal.
 * Encryption happens HERE, in this process; the server never sees the
 * message (same split-key flow as the create page, see public/create.js).
 *
 *   node scripts/cli.mjs "the secret"                      # 15 min, local dev
 *   echo "the secret" | node scripts/cli.mjs --ttl 3600
 *   node scripts/cli.mjs "psst" --burn --phrase blue-otter-lamp \
 *     --url https://whisperfox.example --key $WHISPERFOX_API_KEY
 *
 * The endpoint is rate-limited at the Cloudflare edge, not gated by a CAPTCHA,
 * so no token is needed; pass --key only if you've set API_KEYS server-side.
 * Prints ONLY the link to stdout — pipe it wherever you like; diagnostics go
 * to stderr.
 *
 * Requires Node >= 19 (global fetch + Web Crypto), same as the selftest.
 */
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { sealMessage } from '../public/crypto.js';

const MAX = 500; // mirrors the create page

const { values: opts, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    ttl: { type: 'string', default: '900' },
    phrase: { type: 'string' },
    burn: { type: 'boolean', default: false },
    url: { type: 'string', default: 'http://localhost:8788' },
    key: { type: 'string' },
    help: { type: 'boolean', short: 'h', default: false },
  },
});

if (opts.help) {
  console.error('usage: node scripts/cli.mjs [message] [--ttl seconds] [--phrase word] [--burn] [--url base] [--key apiKey]');
  console.error('       message falls back to stdin when omitted');
  process.exit(0);
}

const message = positionals[0] ?? (process.stdin.isTTY ? '' : readFileSync(0, 'utf8').replace(/\r?\n$/, ''));
if (!message.trim()) {
  console.error('error: no message (pass it as an argument or on stdin)');
  process.exit(1);
}
if (message.length > MAX) {
  console.error(`error: messages are limited to ${MAX} characters (got ${message.length})`);
  process.exit(1);
}

const headers = { 'content-type': 'application/json' };
if (opts.key) headers.authorization = `Bearer ${opts.key}`;

const res = await fetch(`${opts.url}/api/create`, {
  method: 'POST',
  headers,
  body: JSON.stringify({ ttl: Number(opts.ttl), burn: opts.burn }),
});
if (!res.ok) {
  const e = await res.json().catch(() => ({}));
  console.error(`error: create failed (${res.status}) ${e.error || ''}`.trim());
  process.exit(1);
}
const { id, serverShare } = await res.json();

// Same key-split as public/create.js, via the shared seal (see crypto.js):
// urlKeyPart = K XOR share [XOR PBKDF2(phrase)].
const payload = await sealMessage(serverShare, message, { phrase: opts.phrase });
console.error(`expires in ${Number(opts.ttl)}s${opts.burn ? ', burns on first read' : ''}${opts.phrase ? ', phrase required' : ''}`);
console.log(`${opts.url}/view#${id}~${payload}`);
