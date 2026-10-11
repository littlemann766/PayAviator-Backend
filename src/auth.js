import { jwtVerify, createRemoteJWKSet } from 'jose';

export class AuthError extends Error {}

/**
 * Builds an async verifier: (token) => { userId, claims }.
 * Modes: firebase (Google securetoken JWKS, same checks as firebase-admin
 * verifyIdToken minus revocation), jwks (any OIDC provider), hs256 (shared secret).
 */
export function createTokenVerifier(auth, { jwks } = {}) {
  if (!auth || auth.mode === 'disabled') return null;
  let key;
  if (auth.mode === 'hs256') key = new TextEncoder().encode(auth.secret);
  else key = jwks || createRemoteJWKSet(new URL(auth.jwksUrl), { cacheMaxAge: 60 * 60 * 1000 });

  return async function verify(token) {
    let payload;
    try {
      ({ payload } = await jwtVerify(token, key, {
        algorithms: auth.algorithms,
        issuer: auth.issuer,
        audience: auth.audience,
        clockTolerance: 30,
        requiredClaims: ['sub', 'exp'],
      }));
    } catch (e) {
      throw new AuthError(e?.code || 'invalid_token');
    }
    if (auth.mode === 'firebase' && payload.auth_time && payload.auth_time * 1000 > Date.now() + 30000) {
      throw new AuthError('auth_time_in_future');
    }
    const userId = String(payload.sub || payload.uid || '').trim();
    if (!userId || userId.length > 128) throw new AuthError('invalid_subject');
    return { userId, claims: payload };
  };
}

/** Express middleware: requires Authorization: Bearer <token>; sets req.userId. */
export function requireAuth(verifier, { log, devUserHeader = 'x-dev-user-id' } = {}) {
  if (!verifier) {
    // AUTH_DISABLED (sandbox only, enforced in config).
    return (req, _res, next) => {
      req.userId = String(req.get(devUserHeader) || 'payaviator-local-user');
      next();
    };
  }
  return async (req, res, next) => {
    const header = req.get('authorization') || '';
    // Unambiguous pattern (token has no whitespace), so it runs in linear time.
    const match = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(header);
    if (!match) {
      res.set('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: 'Authentication required.', code: 'UNAUTHENTICATED' });
    }
    try {
      const { userId, claims } = await verifier(match[1]);
      req.userId = userId;
      req.authClaims = claims;
      next();
    } catch (e) {
      log?.warn('auth rejected', { reason: e.message, path: req.path });
      res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
      res.status(401).json({ error: 'Invalid or expired session. Please sign in again.', code: 'INVALID_TOKEN' });
    }
  };
}

/**
 * Backward-compatible route shapes: if the legacy :userId path param or a
 * body userId is present it must equal the authenticated user, else 403.
 */
export function enforceUserMatch(req, res, next) {
  const claimed = req.params?.userId ?? req.body?.userId;
  if (claimed !== undefined && claimed !== null && claimed !== '' && String(claimed) !== req.userId) {
    return res.status(403).json({ error: 'Forbidden.', code: 'USER_MISMATCH' });
  }
  next();
}
