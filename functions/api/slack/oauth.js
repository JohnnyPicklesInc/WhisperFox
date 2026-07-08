/**
 * GET /api/slack/oauth  — install (OAuth v2) for public distribution.
 *
 * One endpoint, two phases:
 *   - no `code`  → start: mint a signed `state` and redirect to Slack's consent
 *     screen (the "Add to Slack" button links here).
 *   - with `code` → callback: verify `state`, exchange the code via
 *     oauth.v2.access, record a minimal install marker in KV.
 *
 * The app only needs the `commands` scope: the slash command posts results back
 * through Slack's per-request response_url, so no bot token is stored and no
 * chat:write scope is required. We keep as little as possible, on brand.
 */
import { signContext, verifyContext } from '../../_slack.js';

const STATE_TTL = 600; // 10 min to complete the consent round-trip

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const origin = url.origin;
  const redirectUri = `${origin}/api/slack/oauth`;
  const stateSecret = env.SLACK_STATE_SECRET || env.ROOT_PEPPER;

  if (!env.SLACK_CLIENT_ID || !env.SLACK_CLIENT_SECRET || !stateSecret) {
    return html('WhisperFox for Slack is not configured on this deployment.', 500);
  }

  const code = url.searchParams.get('code');

  // --- start: bounce to Slack's consent screen -------------------------------
  if (!code) {
    const oauthErr = url.searchParams.get('error');
    if (oauthErr) return html(`Slack authorization was cancelled (${escapeHtml(oauthErr)}).`, 400);
    const state = await signContext({ k: 'oauth' }, stateSecret, STATE_TTL);
    const authorize = new URL('https://slack.com/oauth/v2/authorize');
    authorize.searchParams.set('client_id', env.SLACK_CLIENT_ID);
    authorize.searchParams.set('scope', 'commands');
    authorize.searchParams.set('state', state);
    authorize.searchParams.set('redirect_uri', redirectUri);
    return Response.redirect(authorize.toString(), 302);
  }

  // --- callback: verify state, exchange the code -----------------------------
  const state = url.searchParams.get('state') || '';
  if (!(await verifyContext(state, stateSecret))) {
    return html('This install link expired or was tampered with. Please start again from the Add to Slack button.', 400);
  }

  const form = new URLSearchParams();
  form.set('client_id', env.SLACK_CLIENT_ID);
  form.set('client_secret', env.SLACK_CLIENT_SECRET);
  form.set('code', code);
  form.set('redirect_uri', redirectUri);

  let data;
  try {
    const r = await fetch('https://slack.com/api/oauth.v2.access', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    data = await r.json();
  } catch {
    return html('Could not reach Slack to finish installation. Please try again.', 502);
  }
  if (!data.ok) return html(`Slack rejected the installation (${escapeHtml(data.error || 'unknown error')}).`, 400);

  // Minimal, content-free install marker — no bot token needed for the core
  // loop (posting uses response_url). Only recorded if a KV namespace is bound.
  const teamId = data.team?.id || data.team_id || 'unknown';
  if (env.ROOT_KV) {
    await env.ROOT_KV.put(
      `slack:team:${teamId}`,
      JSON.stringify({ team_id: teamId, installed_at: Math.floor(Date.now() / 1000) }),
      { expirationTtl: 60 * 60 * 24 * 365 },
    );
  }

  return html('WhisperFox is installed. Type <code>/whisperfox</code> in any channel to create a self-destructing secret.');
}

/**
 * Minimal, script-free HTML response for the install landing.
 * @param {string} bodyHtml Trusted markup (callers escape any dynamic parts).
 * @param {number} [status=200]
 * @returns {Response}
 */
function html(bodyHtml, status = 200) {
  const doc = `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<title>WhisperFox for Slack</title><link rel="stylesheet" href="/style.css"></head>` +
    `<body><main class="card"><h1 class="brand">🦊 WhisperFox</h1>` +
    `<p class="tagline">${bodyHtml}</p>` +
    `<p class="how-cta"><a class="primary" href="/">Go to WhisperFox</a></p></main></body></html>`;
  return new Response(doc, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
