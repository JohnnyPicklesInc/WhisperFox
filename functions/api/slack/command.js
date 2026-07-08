/**
 * POST /api/slack/command  — the `/whisperfox` slash command.
 *
 * Safe by default. With no `quick` keyword we reply with a button that opens the
 * browser compose page: the secret is typed and encrypted on the user's device
 * and never touches Slack or this Worker (zero-knowledge). The explicit
 * `quick <secret>` subcommand encrypts server-side for convenience and says so —
 * that text transits Slack + this Worker, unlike the default flow.
 *
 * Slack posts application/x-www-form-urlencoded and expects a reply within 3s.
 * We verify the request signature over the RAW body first. A URL button does not
 * require interactivity to be configured (Slack just opens the link), so no
 * interaction endpoint is needed for the default loop.
 */
import { json } from '../../_http.js';
import { getOrMintRoot, rootFrom, createToken } from '../../_lib.js';
import { sealMessage } from '../../_seal.js';
import { verifySlackSignature, signContext } from '../../_slack.js';

const HANDOFF_TTL = 1800; // 30 min — matches Slack's response_url validity
const QUICK_TTL = 900;    // 15 min for the server-side quick path

export async function onRequestPost({ request, env }) {
  if (!env.SLACK_SIGNING_SECRET) return json({ error: 'slack not configured' }, 500);

  // Read the raw body ONCE — the signature is computed over these exact bytes.
  const raw = await request.text();
  if (!(await verifySlackSignature(request.headers, raw, env.SLACK_SIGNING_SECRET))) {
    return json({ error: 'bad signature' }, 401);
  }

  const form = new URLSearchParams(raw);
  const text = (form.get('text') || '').trim();
  const responseUrl = form.get('response_url') || '';
  const channelId = form.get('channel_id') || '';
  const teamId = form.get('team_id') || '';
  const origin = new URL(request.url).origin;

  if (/^help\b/i.test(text)) return ephemeral(helpText());

  // `quick [phrase:<word>] <secret>` — server-side seal, burns after first read.
  if (/^quick\b/i.test(text)) {
    if (!env.ROOT_PEPPER || !env.ROOT_KV) return ephemeral('WhisperFox is misconfigured (ROOT_PEPPER/ROOT_KV).');
    let rest = text.replace(/^quick\b/i, '').trim();
    let phrase;
    const pm = rest.match(/^phrase:(\S+)\s+([\s\S]+)$/);
    if (pm) { phrase = pm[1]; rest = pm[2]; }
    const secret = rest.trim();
    if (!secret) return ephemeral('Usage: `/whisperfox quick <secret>` (optionally `quick phrase:<word> <secret>`).');
    if (secret.length > 500) return ephemeral(`That secret is ${secret.length} characters; the limit is 500.`);

    const now = Date.now() / 1000;
    const { kvRandom, keyId, epoch } = await getOrMintRoot(env.ROOT_KV, now);
    const root = await rootFrom(env.ROOT_PEPPER, kvRandom);
    const tok = await createToken(root, keyId, epoch, QUICK_TTL, now, { burn: true });
    const payload = await sealMessage(tok.serverShare, secret, phrase ? { phrase } : {});
    const link = `${origin}/view#${tok.id}~${payload}`;

    // in_channel so the recipient in this channel can open it; burns on first read.
    return json({
      response_type: 'in_channel',
      blocks: [
        { type: 'section', text: { type: 'mrkdwn', text: `🦊 *Self-destructing secret* — opens once, then gone; expires in 15 min.\n<${link}|Open the secret →>` } },
        ...(phrase ? [{ type: 'context', elements: [{ type: 'mrkdwn', text: 'A secret phrase is required to open it — share that phrase separately.' }] }] : []),
        { type: 'context', elements: [{ type: 'mrkdwn', text: '_Sent via quick mode: the server briefly saw this secret. For zero-knowledge, use `/whisperfox` and create it in your browser._' }] },
      ],
    });
  }

  // Default: hand off to the browser (zero-knowledge). Carry a signed context so
  // the compose page can post the finished link back to this channel.
  const ctx = await signContext(
    { response_url: responseUrl, channel_id: channelId, team_id: teamId },
    env.SLACK_STATE_SECRET || env.ROOT_PEPPER,
    HANDOFF_TTL,
  );
  const composeUrl = `${origin}/?slack=${encodeURIComponent(ctx)}`;
  return json({
    response_type: 'ephemeral',
    blocks: [
      { type: 'section', text: { type: 'mrkdwn', text: '*Create a self-destructing secret.* It opens in your browser, so the text is encrypted on your device — it never reaches Slack or our servers.' } },
      { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: 'Create a secret →', emoji: true }, url: composeUrl, style: 'primary' }] },
      { type: 'context', elements: [{ type: 'mrkdwn', text: 'Prefer to stay here? `/whisperfox quick <secret>` encrypts on our server instead — it briefly sees the text.' }] },
    ],
  });
}

function ephemeral(text) {
  return json({ response_type: 'ephemeral', text });
}

function helpText() {
  return [
    '*WhisperFox — self-destructing secrets*',
    '• `/whisperfox` — create a secret in your browser (zero-knowledge; nothing reaches our servers).',
    '• `/whisperfox quick <secret>` — post a one-time secret link right here (server encrypts it; briefly sees the text). Burns after first read, expires in 15 min.',
    '• `/whisperfox quick phrase:<word> <secret>` — also require a secret phrase to open.',
  ].join('\n');
}
