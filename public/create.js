/**
 * Create page: requests a signed id + server key-share from /api/create,
 * encrypts the message locally, and assembles the
 * /view#<id>~<iv.salt.urlKeyPart.ct> link.
 */
import { sealMessage, webCryptoAvailable } from '/crypto.js';
import { renderAd } from '/ad.js';
import qrcodegen from '/vendor/qrcodegen.js';

const MAX = 500;
// Mirrors TTL_MIN/TTL_MAX in functions/_lib.js (the client cannot import
// server code across the deploy boundary).
const TTL_MIN_SEC = 60;
const TTL_MAX_SEC = 86400;
// The slider is an index into these steps (minutes); keep in sync with the
// range input's min/max in index.html.
const STEPS = [5, 15, 30, 60, 240, 720, 1440];
const $ = (s) => document.querySelector(s);

const msg = $('#msg');
const count = $('#count');
const ttl = $('#ttl');
const ttlLabel = $('#ttlLabel');
const phrase = $('#phrase');
const usePhrase = $('#usePhrase');
const phraseRow = $('#phraseRow');
const phraseWarn = $('#phraseWarn');
const burn = $('#burn');
const gen = $('#gen');
const compose = $('#compose');
const out = $('#out');
const newMsg = $('#newMsg');
const shareHint = $('#shareHint');
const qrWrap = $('#qrWrap');
const link = $('#link');
const copy = $('#copy');
const err = $('#err');
const slackBanner = $('#slackBanner');
const slackShare = $('#slackShare');
const shareSlack = $('#shareSlack');
const slackInChannel = $('#slackInChannel');
const slackShareMsg = $('#slackShareMsg');

// crypto.subtle requires a secure context; disable the form when unavailable.
if (!webCryptoAvailable()) {
  err.textContent = 'Encryption is disabled on insecure connections. Open this page over HTTPS (or localhost).';
  gen.disabled = true;
}

// Slack handoff mode: the /whisperfox slash command opens this page with a
// signed context (in ?slack=) so the finished link can be posted back to the
// channel. The secret is still typed and encrypted HERE — nothing about it
// reaches Slack or our server; only the resulting link is relayed, on demand,
// when the user clicks "Share to Slack".
const slackCtx = new URLSearchParams(location.search).get('slack');
if (slackCtx) slackBanner.hidden = false;

function fmtTtl(minutes) {
  if (minutes < 60) return `${minutes} min`;
  const h = minutes / 60;
  return h === 1 ? '1 hour' : `${h} hours`;
}

/** Selected TTL in minutes: the slider value is an index into STEPS. */
function ttlMinutes() {
  const idx = Math.min(STEPS.length - 1, Math.max(0, Number(ttl.value) || 0));
  return STEPS[idx];
}

// Past ~1800 chars a QR gets too dense to scan reliably (and encodeText
// throws past ~2950); show nothing rather than an unscannable smudge.
const QR_MAX_CHARS = 1800;

/**
 * Render the link as an inline SVG QR code, entirely in-browser — the link
 * contains key material, so it must never be sent to a QR image service.
 * @param {string} text The full share link.
 */
function renderQr(text) {
  qrWrap.textContent = '';
  qrWrap.hidden = true;
  if (text.length > QR_MAX_CHARS) return;
  let qr;
  try {
    qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.LOW);
  } catch {
    return;
  }
  const border = 2;
  const size = qr.size + border * 2;
  let path = '';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.getModule(x, y)) path += `M${x + border},${y + border}h1v1h-1z`;
    }
  }
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
  svg.setAttribute('shape-rendering', 'crispEdges');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'QR code for the secure link');
  const bg = document.createElementNS(NS, 'rect');
  bg.setAttribute('width', String(size));
  bg.setAttribute('height', String(size));
  bg.setAttribute('fill', '#ffffff');
  const fg = document.createElementNS(NS, 'path');
  fg.setAttribute('d', path);
  fg.setAttribute('fill', '#0b1020');
  svg.appendChild(bg);
  svg.appendChild(fg);
  qrWrap.appendChild(svg);
  qrWrap.hidden = false;
}

msg.addEventListener('input', () => {
  count.textContent = `${msg.value.length}/${MAX}`;
  count.classList.toggle('over', msg.value.length > MAX);
});
ttl.addEventListener('input', () => {
  ttlLabel.textContent = fmtTtl(ttlMinutes());
});
ttlLabel.textContent = fmtTtl(ttlMinutes());

usePhrase.addEventListener('change', () => {
  phraseRow.hidden = !usePhrase.checked;
  phraseWarn.hidden = usePhrase.checked;
  if (!usePhrase.checked) phrase.value = '';
  else phrase.focus();
});

gen.addEventListener('click', async () => {
  err.textContent = '';
  const text = msg.value;
  if (!text.trim()) {
    err.textContent = 'Type a message first.';
    return;
  }
  if (text.length > MAX) {
    err.textContent = `Messages are limited to ${MAX} characters.`;
    return;
  }
  if (usePhrase.checked && !phrase.value.trim()) {
    err.textContent = 'Enter a secret phrase, or turn that option off.';
    return;
  }

  gen.disabled = true;
  gen.textContent = 'Creating link…';
  try {
    const ttlSec = Math.min(TTL_MAX_SEC, Math.max(TTL_MIN_SEC, ttlMinutes() * 60));

    const res = await fetch('/api/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ttl: ttlSec, burn: burn.checked }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      const detail = e.codes ? ` [${e.codes.join(', ')}]` : '';
      throw new Error((e.error || `Server error (${res.status})`) + detail);
    }
    const { id, serverShare } = await res.json();

    // Encrypt entirely in the browser (shared split-key seal — see crypto.js).
    // Everything rides in the #fragment (never sent to a server):
    //   <id> ~ iv . salt . urlKeyPart . ciphertext
    // The id is only extracted client-side and sent to /api/share via fetch.
    const usedPhrase = usePhrase.checked && !!phrase.value;
    const payload = await sealMessage(serverShare, text, { phrase: usedPhrase ? phrase.value : undefined });
    link.value = `${location.origin}/view#${id}~${payload}`;
    renderQr(link.value);

    const opens = burn.checked ? 'can open it once — then never again' : 'can open it until it expires';
    shareHint.textContent =
      usedPhrase
        ? `Anyone with this link AND the secret phrase ${opens}. Send the link and the phrase separately, through channels you trust.`
        : `Anyone with this link ${opens}. Share it through a channel you trust.`;

    // Clear the draft and phrase before leaving the compose screen.
    msg.value = '';
    count.textContent = `0/${MAX}`;
    count.classList.remove('over');
    phrase.value = '';

    compose.hidden = true;
    out.hidden = false;
    if (slackCtx) {
      slackShare.hidden = false;
      slackShareMsg.textContent = '';
      shareSlack.disabled = false;
      shareSlack.textContent = 'Share to Slack';
    }
    link.focus();
    link.select();
  } catch (e) {
    err.textContent = e.message || String(e);
  } finally {
    gen.disabled = false;
    gen.textContent = 'Generate secure link';
  }
});

newMsg.addEventListener('click', () => {
  link.value = '';
  shareHint.textContent = '';
  qrWrap.textContent = '';
  qrWrap.hidden = true;
  burn.checked = false;
  usePhrase.checked = true;
  phraseRow.hidden = false;
  phraseWarn.hidden = true;
  slackShare.hidden = true;
  slackShareMsg.textContent = '';
  out.hidden = true;
  compose.hidden = false;
  msg.focus();
});

// Relay the finished link back to Slack via the signed handoff context. Only
// the link (the shareable artifact) leaves the browser — never the plaintext.
shareSlack.addEventListener('click', async () => {
  if (!slackCtx || !link.value) return;
  shareSlack.disabled = true;
  const prev = shareSlack.textContent;
  shareSlack.textContent = 'Sharing…';
  slackShareMsg.textContent = '';
  try {
    const res = await fetch('/api/slack/share', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ link: link.value, slack: slackCtx, inChannel: slackInChannel.checked }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.error || `Slack error (${res.status})`);
    }
    slackShareMsg.textContent = slackInChannel.checked ? 'Shared to the channel ✓' : 'Sent to you in Slack ✓';
    shareSlack.textContent = 'Shared ✓';
  } catch (e) {
    slackShareMsg.textContent = e.message || String(e);
    shareSlack.textContent = prev;
    shareSlack.disabled = false;
  }
});

copy.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(link.value);
    copy.textContent = 'Copied ✓';
    setTimeout(() => (copy.textContent = 'Copy'), 1500);
  } catch {
    link.select();
  }
});

renderAd(document.getElementById('ad'));
