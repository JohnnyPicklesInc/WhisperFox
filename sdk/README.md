# @whisperfox/sdk

Create [WhisperFox](https://whisperfox.pages.dev) self-destructing links from
your own code — **encryption happens in your process, not on the server.**

WhisperFox is zero-knowledge: the message is encrypted with a fresh key that
never leaves the caller, and the ciphertext rides in the link's `#fragment`,
which browsers never transmit. The SDK asks the API only for a signed id and a
server key-share; it seals the message locally. The server never sees your
plaintext, your key, or your phrase — there is nothing on it to leak.

Zero dependencies. Runs on Node ≥ 19, modern browsers, and any bundler target
(needs Web Crypto + `fetch`).

## Install

```bash
npm install @whisperfox/sdk
```

## Usage

```js
import { createSecret } from '@whisperfox/sdk';

const { link, expiresAt } = await createSecret('the wifi password is hunter2', {
  ttl: 3600,          // seconds, 60–86400 (default 900 = 15 min)
  burn: true,         // stop working after the first open
  phrase: 'blue-otter-lamp', // optional; recipient must also have it
  apiKey: process.env.WHISPERFOX_API_KEY, // set API_KEYS server-side
});

console.log(link); // https://whisperfox.pages.dev/view#...  — share it
```

`createSecret` returns `{ link, id, expiresAt }`. Share `link`; it stops working
at `expiresAt` (or on first read, with `burn`). If you set a `phrase`, send it
through a **different** channel than the link.

### Options

| option    | default                          | notes                                              |
|-----------|----------------------------------|----------------------------------------------------|
| `ttl`     | `900`                            | lifetime in seconds, 60–86400                      |
| `burn`    | `false`                          | link dies after the first successful open          |
| `phrase`  | —                                | optional secret phrase, folded into the key locally |
| `apiKey`  | —                                | Bearer key; required against a deploy with `API_KEYS` set |
| `baseUrl` | `https://whisperfox.pages.dev`   | your WhisperFox origin (no trailing slash)         |
| `fetch`   | global `fetch`                   | inject a fetch impl on runtimes without one        |

Messages are capped at 500 characters (`MAX_MESSAGE`).

## GitHub Action example

Post a self-destructing link into a workflow log instead of pasting a raw secret:

```yaml
- run: npm i @whisperfox/sdk
- uses: actions/github-script@v7
  env:
    WHISPERFOX_API_KEY: ${{ secrets.WHISPERFOX_API_KEY }}
  with:
    script: |
      const { createSecret } = await import('@whisperfox/sdk');
      const { link } = await createSecret(process.env.DEPLOY_TOKEN, {
        ttl: 900, burn: true, apiKey: process.env.WHISPERFOX_API_KEY,
      });
      core.notice(`One-time deploy token: ${link}`);
```

## Self-hosting

Point `baseUrl` at your own WhisperFox deployment. Against local dev
(`npm run dev` → `http://localhost:8788`) no `apiKey` is needed.

## License

[MIT](../LICENSE)
