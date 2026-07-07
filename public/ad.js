/**
 * Client ad renderer. Fetches the server-side-decided ad from /api/ad and
 * builds it as FIRST-PARTY DOM. No third-party ad script is ever loaded, so
 * this is safe to place on the same page as a decrypted secret.
 */
export async function renderAd(container) {
  if (!container) return;
  let ad;
  try {
    const r = await fetch('/api/ad');
    ad = await r.json();
  } catch {
    return;
  }
  if (!ad) return;

  container.textContent = '';
  const a = document.createElement('a');
  a.href = ad.link || '/';
  a.className = 'ad';
  a.target = '_blank';
  a.rel = 'noopener noreferrer nofollow';

  if (ad.image) {
    const img = document.createElement('img');
    img.src = ad.image;
    img.alt = ad.text || 'advertisement';
    img.loading = 'lazy';
    a.appendChild(img);
  }
  if (ad.text) {
    const span = document.createElement('span');
    span.textContent = ad.text;
    a.appendChild(span);
  }
  container.appendChild(a);

  // Impression pixel as a first-party image request (no script).
  if (ad.view_url) {
    const px = new Image();
    px.width = 1;
    px.height = 1;
    px.alt = '';
    px.src = ad.view_url;
    px.style.position = 'absolute';
    px.style.left = '-9999px';
    container.appendChild(px);
  }
}
