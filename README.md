# WhisperFox

Ad-supported, serverless, zero-knowledge ephemeral messages. Write a secret
(up to 500 characters), pick an expiry timer from 5 minutes to 24 hours,
optionally add a secret phrase and/or burn-after-first-read, and get a link.
The message is encrypted in the browser; the server never sees the message,
the key, or the phrase, and stores nothing about the message's content (the
one opt-in per-message record is burn-after-read's content-free "already
opened" marker; see Security model).

## Design overview

- The ciphertext lives inside the link's `#fragment`, which browsers never
  send to a server. The server only ever handles a random, content-free
  key-share.
- The message key is split: `urlKeyPart = K XOR serverShare [XOR
  PBKDF2(phrase)]`. Reassembling `K` requires the link, the server's share,
  and the phrase if one was set.
- The server stores no message data. Each hour gets a fresh random root (a
  content-free 32-byte value in Workers KV that self-erases about 27 hours
  later), combined with a static `ROOT_PEPPER` secret. Each message's share is
  derived on the fly, and the server refuses to reproduce it after the
  deadline — once the hour's root is erased, it couldn't even if asked.
- Burn-after-read (optional) refuses the key-share after the first successful
  open, tracked by a content-free KV tombstone keyed on the link's own public
  nonce. Best-effort: KV has no compare-and-set and ~60s cross-colo
  propagation, so it hardens the TTL rather than guaranteeing exactly-once
  (strict exactly-once would need a Durable Object — a possible upgrade path).
- The view page also runs a live countdown that wipes the plaintext from the
  page and memory when the timer hits, even if the tab was left open.

```
Sender browser: encrypt -> K; urlKeyPart = K XOR serverShare; link = /view#<id>~<iv.salt.urlKeyPart.ct>
Worker:         POST /api/create -> {signed id, serverShare};  GET /api/share/:id -> share or 410 (past TTL)
Recipient:      read id+parts from #fragment; GET /api/share/:id -> serverShare; K = urlKeyPart XOR serverShare; decrypt in browser
```

## Project layout

```
public/            static site (Cloudflare Pages)
  index.html       create page   (+ create.js)
  view.html        reveal page   (+ view.js)   — served at /view; payload in #fragment
  how.html         how-it-works / FAQ page (no scripts)
  compare.html     honest comparison vs Privnote / One-Time Secret / Yopass (no scripts)
  privacy.html     privacy policy + abuse contact (no scripts)
  404.html         not-found page (served automatically by Pages)
  crypto.js        browser crypto (AES-GCM, PBKDF2, XOR, base64url)
  ad.js            first-party ad renderer
  vendor/qrcodegen.js  vendored Nayuki QR encoder (MIT) — QR is generated in-browser
  style.css, favicon.svg, robots.txt, .well-known/security.txt
  _redirects, _headers (strict CSP)
functions/         Cloudflare Pages Functions (the "Worker")
  _lib.js          server crypto: hourly KV root lifecycle, sign/verify, share, burn tombstones
  _http.js         shared JSON response helper
  api/create.js        POST /api/create   (edge rate-limit; optional API-key auth)
  api/share/[id].js    GET  /api/share/:id
  api/ad.js            GET  /api/ad   (server-side EthicalAds fetch, house fallback)
scripts/
  selftest.mjs     node crypto self-test (no server, no network)
  smoke.mjs        HTTP smoke test against a running dev server
  cli.mjs          command-line client (encrypts locally, prints a link)
wrangler.toml, .dev.vars.example
```

## Run locally

```bash
npm install
npm run selftest      # crypto end-to-end self-test (no server, no network)
npm run dev           # wrangler pages dev public  -> http://localhost:8788
npm run smoke         # HTTP round-trip against the running dev server
```

Copy `.dev.vars.example` to `.dev.vars` (which is gitignored). It carries a dev
`ROOT_PEPPER` and a dev API key, so the project runs out of the box. There is no
CAPTCHA — `/api/create` is open locally and is protected in production by a
Cloudflare edge rate-limit rule (see the production checklist below).

## Deploy (Cloudflare Pages)

```bash
wrangler pages project create whisperfox
wrangler kv namespace create whisperfox-roots   # paste the id into wrangler.toml [[kv_namespaces]]
wrangler pages secret put ROOT_PEPPER        # a long random string (32+ chars)
# optional: set ETHICALADS_PUBLISHER in wrangler.toml [vars]
npm run deploy
```

### Production checklist

- **Abuse protection — this is required, there is no CAPTCHA.** `/api/create`
  is open by default, so add a Cloudflare WAF **rate-limiting rule** before you
  announce the site (one rule is included on the free plan): match
  `starts_with(http.request.uri.path, "/api/")`, limit ~30 requests per minute
  per IP, action Block. Optionally add a tighter rule for `/api/create`
  specifically. Also enable **Bot Fight Mode** (Security → Bots) for bot
  heuristics. This covers both create-flood cost and phishing/spam link farms —
  each well-formed share/ad request also costs a KV read (free tier: 100k/day)
  or an outbound fetch, so the `/api/*` rule protects those too.
- **`ROOT_PEPPER`**: set a long random production value; never reuse the
  `.dev.vars` one.
- **Custom domain**: attach it to the Pages project.
- **Ads**: apply at [ethicalads.io](https://www.ethicalads.io/publishers/) —
  approval requires a live site with real traffic and a privacy policy
  (`public/privacy.html`). Once approved, set `ETHICALADS_PUBLISHER` in
  `wrangler.toml [vars]` and redeploy. Until then the built-in house ad serves.
- **Contact addresses**: the abuse/security contact appears in
  `public/privacy.html`, `public/how.html`, and
  `public/.well-known/security.txt` (update `Canonical:` there to your real
  domain, and bump `Expires:` yearly).
- **Comparison page facts**: `public/compare.html` states competitor facts "as
  of July 2026" — re-verify against their live sites occasionally.

## API and CLI

`POST /api/create` needs no token — it's open and rate-limited at the edge, so
scripts can call it directly. If you want authenticated callers to be exempt
from the rate limit (configure the exemption in your WAF rule), set an API key
server-side and send it as a Bearer header; a presented-but-wrong key is
rejected with 403:

```bash
wrangler pages secret put API_KEYS    # comma-separated list of long random strings
```

Raw API — the body carries only ttl/burn, never the message:

```bash
curl -s https://your-domain/api/create \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $WHISPERFOX_API_KEY" \
  -d '{"ttl": 3600, "burn": true}'
# -> {"id": "...", "serverShare": "..."}   encrypt locally; see scripts/cli.mjs
```

Or use the bundled CLI, which does the encryption for you (locally — the
message never leaves your machine):

```bash
node scripts/cli.mjs "the wifi password is hunter2" --ttl 3600 --burn \
  --url https://your-domain --key "$WHISPERFOX_API_KEY"
# prints the /view#... link to stdout; add --phrase word for a secret phrase
echo "or pipe it in" | node scripts/cli.mjs --url https://your-domain --key "$WHISPERFOX_API_KEY"
```

Against local dev (`npm run dev`) no key is needed — `/api/create` is open and
there is no rate limit locally.

## Key rotation

Rotation is automatic (`functions/_lib.js`); there is nothing to operate — no
cron, no second deploy artifact, no downtime.

- Each hour's root is 32 fresh random bytes stored in Workers KV; the
  effective signing/share key is `HMAC(ROOT_PEPPER, kvRandom)`.
- The first `/api/create` of an hour promotes a root that was pre-minted an
  hour earlier — it has already propagated to every colo, so there is no
  boundary gap — and pre-mints the next hour's. Boundary races are
  deterministic: racing colos all activate the same root, and spare candidates
  expire unreferenced.
- `/api/create` bakes the root's id into the link; `/api/share` accepts the
  last 25 epochs (enough to cover the 24-hour maximum TTL plus clock skew) and
  refuses older ones.
- KV's `expirationTtl` erases each root about 27 hours after minting, enforced
  by Cloudflare regardless of traffic.

Because retired roots are random values that no longer exist — not something
re-derivable from a master secret — expiry is cryptographic, not policy: past
the overlap window, not even the operator can reproduce a share. The only
manual intervention is for a suspected compromise of both stores at once:
`wrangler pages secret put ROOT_PEPPER` with a new value, after which
outstanding links die once the overlap window passes.

## Security model and limits

- **Zero-knowledge.** The server and operator only ever hold key-gates
  (`ROOT_PEPPER` plus the hour's random KV roots) — never the message, key, or
  phrase. A full server breach exposes zero messages, because no message data
  is stored. The one per-message record is opt-in: burn-after-read links leave
  a content-free "already opened" tombstone whose key is the link's own public
  nonce; it reveals nothing and self-erases at expiry.
- **Stolen root material.** Root material alone cannot read anything from the
  server, and cannot read any message whose link the attacker lacks. Bypassing
  a held link's expiry requires breaching both stores at once: a KV snapshot
  is useless without `ROOT_PEPPER` (a write-only secret store), and the pepper
  is useless without the KV randoms, which self-erase in about 27 hours. Even
  a full one-time breach of both only covers links from a window of roughly a
  day (recent roots plus the pre-minted next hour); every later root is fresh
  randomness the thief never saw, so an undetected theft self-expires. This
  window scales with the maximum TTL — raising it from 1h to 24h widened the
  window from ~4h to ~27h, a deliberate trade for asynchronous recipients.
  Caveats: an attacker with persistent server access reads each new root as it
  is minted (true of any design); KV expiry makes values unreadable via the
  API immediately, but physical garbage collection inside Cloudflare happens
  later; and a flood of well-formed `/api/share` requests costs one KV read
  each against the free tier's 100k/day.
- **Burn-after-read is best-effort.** The tombstone check-then-write is not
  atomic and KV propagates cross-colo in ~60s, so two near-simultaneous opens
  can both succeed. It reliably converts a *later* second open into "already
  opened" — the interception-detection case it exists for — but it is not an
  exactly-once database transaction like storage-based services offer.
- **Ads on the reveal page.** `/api/ad` fetches the creative server-side; the
  browser renders it as first-party HTML with no third-party JavaScript, so ad
  code can never read the decrypted secret. A strict CSP in `public/_headers`
  enforces this.
- **Best-effort expiry.** Once decrypted, nothing can stop screenshots,
  copies, or a debugger-paused viewer. The countdown wipe and server-side
  share withholding cover the normal case, not a determined viewer.
- **Message size** is enforced client-side (500 characters). The server never
  sees the message, so there is nothing server-side to abuse with size.
- **Secret phrase, not password.** The phrase is a throwaway word made up per
  message; the UI discourages reusing a real credential.

## License

[MIT](LICENSE)
