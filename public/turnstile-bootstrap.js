// Initialize Turnstile token and callbacks before api.js loads.
// This must be in a same-origin external file (not inline) to comply with CSP
// script-src 'self' on the create page.
window.turnstileToken = '';
window.onTurnstile = (token) => {
  window.turnstileToken = token;
  window.dispatchEvent(new Event('turnstile-token'));
};
window.onTurnstileError = () => {
  window.turnstileToken = '';
  window.dispatchEvent(new Event('turnstile-token'));
};
window.onTurnstileExpired = () => {
  window.turnstileToken = '';
  window.dispatchEvent(new Event('turnstile-token'));
};
