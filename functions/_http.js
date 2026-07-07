/**
 * Shared HTTP response helper for the API endpoints. Files prefixed with an
 * underscore are not routed by Pages Functions.
 */

/**
 * Build a JSON response with caching disabled.
 * @param {unknown} obj Serialized with JSON.stringify as the response body.
 * @param {number} [status=200] HTTP status code.
 * @param {Record<string, string>} [extraHeaders] Merged over the default headers.
 * @returns {Response}
 */
export function json(obj, status = 200, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...extraHeaders },
  });
}
