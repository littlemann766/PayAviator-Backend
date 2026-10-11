import crypto from 'node:crypto';
import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose';

export class WebhookVerificationError extends Error {}

/**
 * Plaid webhook verification (https://plaid.com/docs/api/webhooks/webhook-verification/):
 *  1. Plaid-Verification header is a JWT signed with ES256.
 *  2. Fetch the JWK for the header's kid via /webhook_verification_key/get (cached by kid).
 *  3. Verify signature; iat must be no older than 5 minutes.
 *  4. payload.request_body_sha256 must equal sha256(raw body).
 *
 * fetchKey(kid) -> JWK object as returned in `key` by /webhook_verification_key/get.
 */
export function createWebhookVerifier({ fetchKey, maxAgeSeconds = 300, now = () => Date.now() }) {
  const cache = new Map();

  async function getKey(kid) {
    const cached = cache.get(kid);
    if (cached && !cached.jwk.expired_at) return cached.key;
    let jwk;
    try { jwk = await fetchKey(kid); } catch { throw new WebhookVerificationError('key_fetch_failed'); }
    if (!jwk) throw new WebhookVerificationError('unknown_key');
    if (jwk.expired_at) {
      cache.delete(kid);
      throw new WebhookVerificationError('key_expired');
    }
    const { expired_at, created_at, ...publicJwk } = jwk;
    const key = await importJWK({ ...publicJwk, alg: 'ES256' }, 'ES256');
    cache.set(kid, { jwk, key });
    return key;
  }

  return async function verify(rawBody, signedJwt) {
    if (!signedJwt) throw new WebhookVerificationError('missing_header');
    if (!Buffer.isBuffer(rawBody)) throw new WebhookVerificationError('missing_body');
    let header;
    try { header = decodeProtectedHeader(signedJwt); } catch { throw new WebhookVerificationError('malformed_jwt'); }
    if (header.alg !== 'ES256') throw new WebhookVerificationError('bad_alg');
    if (!header.kid) throw new WebhookVerificationError('missing_kid');

    const key = await getKey(header.kid);
    let payload;
    try {
      ({ payload } = await jwtVerify(signedJwt, key, {
        algorithms: ['ES256'],
        maxTokenAge: `${maxAgeSeconds}s`,
        currentDate: new Date(now()),
      }));
    } catch (e) {
      throw new WebhookVerificationError(e?.code === 'ERR_JWT_EXPIRED' || /iat|age/i.test(e?.message || '') ? 'stale' : 'bad_signature');
    }
    if (typeof payload.iat !== 'number') throw new WebhookVerificationError('missing_iat');

    const expected = Buffer.from(String(payload.request_body_sha256 || ''), 'utf8');
    const actual = Buffer.from(crypto.createHash('sha256').update(rawBody).digest('hex'), 'utf8');
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
      throw new WebhookVerificationError('body_mismatch');
    }
    return payload;
  };
}
