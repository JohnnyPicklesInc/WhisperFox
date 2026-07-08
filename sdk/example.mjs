/**
 * Runnable SDK example. Against local dev no API key is needed:
 *
 *   npm run dev                       # in another terminal (http://localhost:8788)
 *   node sdk/example.mjs
 *
 * Against a real deploy, pass the base URL and key via env:
 *
 *   WHISPERFOX_URL=https://your-domain WHISPERFOX_API_KEY=... node sdk/example.mjs
 */
import { createSecret } from './index.js';

const baseUrl = process.env.WHISPERFOX_URL || 'http://localhost:8788';
const apiKey = process.env.WHISPERFOX_API_KEY;

const { link, expiresAt } = await createSecret('the wifi password is hunter2', {
  ttl: 900,
  burn: true,
  baseUrl,
  apiKey,
});

console.error(`created (expires ${new Date(expiresAt * 1000).toISOString()}):`);
console.log(link);
