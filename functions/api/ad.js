/**
 * GET /api/ad  ->  { text, link, image?, view_url? }
 *
 * Fetches the ad decision server-side and returns it as plain data; the client
 * renders it as first-party HTML, so no third-party script runs on a page that
 * may hold a decrypted secret.
 *
 * With no publisher configured it returns a built-in first-party "house" ad.
 */
import { json } from '../_http.js';

export async function onRequestGet({ env }) {
  const house = {
    type: 'house',
    text: '🦊 WhisperFox — send a secret that deletes itself.',
    link: '/',
    image: null,
    view_url: null,
  };

  const publisher = env.ETHICALADS_PUBLISHER;
  if (!publisher) return json(house);

  try {
    const url =
      'https://server.ethicalads.io/api/v1/decision/' +
      `?publisher=${encodeURIComponent(publisher)}` +
      '&ad_types=image.v1&keywords=security,privacy,developers';
    const r = await fetch(url, { headers: { accept: 'application/json' } });
    if (!r.ok) return json(house);
    const d = await r.json();
    if (!d || (!d.body && !d.image)) return json(house);
    return json({
      type: 'ethicalads',
      text: stripTags(d.body || ''),
      link: httpUrl(d.link) || '/',
      image: httpUrl(d.image),
      view_url: httpUrl(d.view_url), // first-party <img> impression pixel
    });
  } catch {
    return json(house);
  }
}

/** Remove HTML tags from an ad body, leaving plain text. */
function stripTags(s) {
  return String(s || '').replace(/<[^>]*>/g, '').trim();
}

/**
 * Pass a URL through only if it parses as http(s); anything else (javascript:,
 * data:, relative junk) becomes null. The ad server is semi-trusted — its
 * values end up in <a href> and <img src> on pages that can hold a secret.
 * @param {unknown} u
 * @returns {string | null}
 */
function httpUrl(u) {
  if (typeof u !== 'string' || !u) return null;
  try {
    const parsed = new URL(u);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? u : null;
  } catch {
    return null;
  }
}
