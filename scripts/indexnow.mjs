// Tell Bing, Yandex and the other IndexNow search engines about every URL in the
// sitemap, so new and changed pages get crawled in days rather than weeks.
// Reads public/sitemap.xml rather than the live one (Bot Fight Mode challenges scripts),
// so run it after a deploy, once the key file (public/<KEY>.txt) is live:
// npm run indexnow
import { readFileSync } from 'node:fs';

const HOST = 'whisper-fox.com';
const KEY = '8f9b5a1e1243cc2dc90aea2437b29cc3';

const xml = readFileSync(new URL('../public/sitemap.xml', import.meta.url), 'utf8');
const urlList = [...xml.matchAll(/<loc>\s*(.*?)\s*<\/loc>/g)].map((m) => m[1]);
const res = await fetch('https://api.indexnow.org/indexnow', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json; charset=utf-8' },
  body: JSON.stringify({ host: HOST, key: KEY, keyLocation: `https://${HOST}/${KEY}.txt`, urlList }),
});
console.log(`IndexNow: ${res.status} ${res.statusText} for ${urlList.length} URLs`);
if (!res.ok) {
  console.log(await res.text());
  process.exitCode = 1;
}
