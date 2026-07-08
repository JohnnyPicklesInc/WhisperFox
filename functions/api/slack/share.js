/**
 * POST /api/slack/share  — closes the browser-handoff loop.
 *
 * The compose page (in `?slack=` mode) POSTs { link, slack, inChannel } after it
 * has generated the link locally. We verify the signed context and relay ONLY
 * the link to Slack via the response_url carried in that context. The plaintext
 * never reaches here — the link is the already-shareable artifact, and the
 * response_url was minted by Slack for this exact invocation.
 */
import { json } from '../../_http.js';
import { verifyContext } from '../../_slack.js';

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }

  const link = String(body?.link || '');
  const token = String(body?.slack || '');
  const inChannel = body?.inChannel === true;

  // Only a WhisperFox /view link (carries the secret in its #fragment).
  if (!/^https?:\/\/[^/]+\/view#.+/.test(link)) return json({ error: 'bad link' }, 400);

  const ctx = await verifyContext(token, env.SLACK_STATE_SECRET || env.ROOT_PEPPER);
  if (!ctx || typeof ctx.response_url !== 'string') return json({ error: 'expired or invalid slack context' }, 403);

  // Defense in depth: the response_url is signed by us (came from Slack's
  // verified request), but pin it to Slack's host regardless.
  let host;
  try {
    host = new URL(ctx.response_url).host;
  } catch {
    return json({ error: 'invalid response url' }, 400);
  }
  if (host !== 'hooks.slack.com') return json({ error: 'unexpected response host' }, 400);

  const slackRes = await fetch(ctx.response_url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      response_type: inChannel ? 'in_channel' : 'ephemeral',
      text: `🦊 Self-destructing secret: ${link}`,
    }),
  });
  if (!slackRes.ok) return json({ error: 'slack post failed' }, 502);
  return json({ ok: true });
}
