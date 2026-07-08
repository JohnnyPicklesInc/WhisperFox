/**
 * Reveal page: parses /view#<id>~<iv.salt.urlKeyPart.ct>, fetches the server
 * key-share, decrypts in the browser, and runs the expiry countdown.
 */
import { unb64u, xor, pbkdf2, aesDecrypt, webCryptoAvailable } from '/crypto.js';
import { renderAd } from '/ad.js';

const $ = (s) => document.querySelector(s);

// Everything is in the #fragment:  <id> ~ iv.salt.urlKeyPart.ciphertext
// (The id never appears in the page-load request; it's sent only via fetch.)
const raw = location.hash.slice(1);
const sep = raw.indexOf('~');
const id = sep >= 0 ? raw.slice(0, sep) : '';
const fragment = sep >= 0 ? raw.slice(sep + 1) : '';

const gate = $('#gate');
const revealBtn = $('#reveal');
const phraseWrap = $('#phraseWrap');
const phraseInput = $('#phraseInput');
const gateErr = $('#gateErr');
const burnNotice = $('#burnNotice');
const afterHint = $('#afterHint');
const messageEl = $('#message');
const bodyEl = $('#body');
const timerEl = $('#timer');
const expiredEl = $('#expired');

let countdown = null;
let plaintext = null; // held only in this tab, wiped on expiry
let K = null;
// The server share is fetched at most ONCE per page. Essential for burn
// links: the first fetch stamps them opened, so a wrong-phrase retry must
// reuse the cached share instead of re-fetching into a 410.
let share = null;

function parseFragment() {
  const p = fragment.split('.');
  if (p.length !== 4) return null;
  try {
    return { iv: unb64u(p[0]), saltSeg: p[1], mixed: unb64u(p[2]), ct: unb64u(p[3]) };
  } catch {
    return null;
  }
}

// Parse once up front so we know whether this link needs a secret phrase.
const parsed = parseFragment();
const hasPhrase = !!parsed && parsed.saltSeg !== '-';
// The signed flags field: 'b' means burn-after-read (verified server-side;
// read here only to adjust the UI copy).
const isBurn = id.split('.')[4] === 'b';

function expiresAt() {
  const parts = id.split('.');
  return Number(parts[2]);
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Clear the plaintext and key from the DOM and memory and show the expired
 * panel. Best-effort — screenshots and copies cannot be undone; the server
 * independently refuses the key-share past the deadline.
 */
function showExpired() {
  if (countdown) clearInterval(countdown);
  plaintext = null;
  K = null;
  share = null;
  gate.hidden = true;
  messageEl.hidden = true;
  bodyEl.textContent = '';
  expiredEl.hidden = false;
}

function startCountdown() {
  const exp = expiresAt();
  const tick = () => {
    const left = exp - nowSec();
    if (left <= 0) {
      showExpired();
      return;
    }
    const h = Math.floor(left / 3600);
    const m = Math.floor((left % 3600) / 60);
    const s = left % 60;
    const mm = String(m).padStart(2, '0');
    const ss = String(s).padStart(2, '0');
    timerEl.textContent = `Disappears in ${h > 0 ? `${h}:${mm}:${ss}` : `${m}:${ss}`}`;
  };
  tick();
  countdown = setInterval(tick, 1000);
}

async function reveal() {
  gateErr.textContent = '';
  if (!parsed) return showExpired();

  if (hasPhrase && !phraseInput.value) {
    gateErr.textContent = 'Enter the secret phrase to open this message.';
    phraseInput.focus();
    return;
  }

  revealBtn.disabled = true;
  revealBtn.textContent = 'Opening…';

  if (share === null) {
    try {
      const r = await fetch(`/api/share/${encodeURIComponent(id)}`);
      if (r.status === 410) return showExpired();
      if (!r.ok) throw new Error('network');
      share = unb64u((await r.json()).serverShare);
    } catch {
      revealBtn.disabled = false;
      revealBtn.textContent = 'Reveal message';
      gateErr.textContent = 'Could not reach the server. Try again.';
      return;
    }
  }

  try {
    K = xor(parsed.mixed, share);
    if (hasPhrase) {
      const pk = await pbkdf2(phraseInput.value, unb64u(parsed.saltSeg));
      K = xor(K, pk);
    }
    plaintext = await aesDecrypt(K, parsed.iv, parsed.ct);
  } catch {
    revealBtn.disabled = false;
    revealBtn.textContent = 'Reveal message';
    gateErr.textContent = hasPhrase ? 'Wrong secret phrase.' : 'This link is corrupted.';
    return;
  }

  gate.hidden = true;
  bodyEl.textContent = plaintext;
  if (isBurn) {
    afterHint.textContent =
      "This message has been opened and can't be opened again — it also disappears from this screen when the timer ends.";
  }
  messageEl.hidden = false;
  startCountdown();
}

revealBtn.addEventListener('click', reveal);
phraseInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') reveal();
});

// Short-circuit if the link is malformed or already past its deadline.
if (!parsed || !expiresAt() || nowSec() >= expiresAt()) {
  showExpired();
} else if (!webCryptoAvailable()) {
  // crypto.subtle is unavailable in insecure contexts, so decryption can't run.
  renderAd(document.getElementById('ad'));
  gateErr.textContent = 'Open this link over HTTPS — decryption is blocked on insecure (http://) connections.';
  revealBtn.disabled = true;
} else {
  renderAd(document.getElementById('ad'));
  // The reveal click is required even when no phrase is set.
  if (hasPhrase) phraseWrap.hidden = false;
  if (isBurn) burnNotice.hidden = false;
}
