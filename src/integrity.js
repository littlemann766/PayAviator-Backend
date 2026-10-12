import crypto from 'node:crypto';
import { GoogleAuth } from 'google-auth-library';

/** Max age of an integrity verdict (requestDetails.timestampMillis). */
export const INTEGRITY_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * requestHash the app must pass to the Play Integrity *standard* request:
 *   lowercase hex SHA-256 of `${androidId}|${firebaseUid}` (androidId lowercased).
 * Binds the verdict to this device and this signed-in account.
 */
export const expectedRequestHash = (deviceId, uid) =>
  crypto.createHash('sha256').update(`${String(deviceId).toLowerCase()}|${uid}`).digest('hex');


/** Validates a decoded tokenPayloadExternal. Returns null when OK, else a reason string. */
export function checkVerdict(payload, { packageName, deviceId, uid, now = Date.now() }) {
  const rd = payload?.requestDetails || {};
  const app = payload?.appIntegrity || {};
  const dev = payload?.deviceIntegrity || {};
  if (rd.requestPackageName !== packageName || (app.packageName && app.packageName !== packageName)) return 'package_mismatch';
  const ts = Number(rd.timestampMillis);
  if (!Number.isFinite(ts) || now - ts > INTEGRITY_MAX_AGE_MS || ts - now > 60_000) return 'stale_token';
  if (rd.requestHash !== expectedRequestHash(deviceId, uid)) return 'request_hash_mismatch';
  if (app.appRecognitionVerdict !== 'PLAY_RECOGNIZED') return 'app_not_recognized';
  const dv = Array.isArray(dev.deviceRecognitionVerdict) ? dev.deviceRecognitionVerdict : [];
  if (!dv.includes('MEETS_DEVICE_INTEGRITY')) return 'device_integrity_failed';
  return null;
}

/** Real client: playintegrity v1 decodeIntegrityToken. Injected so tests can mock it. */
export function createIntegrityClient({ serviceAccount, packageName }) {
  const auth = new GoogleAuth({ credentials: serviceAccount, scopes: ['https://www.googleapis.com/auth/playintegrity'] });
  const url = `https://playintegrity.googleapis.com/v1/${encodeURIComponent(packageName)}:decodeIntegrityToken`;
  return {
    async decode(integrityToken) {
      const client = await auth.getClient();
      const r = await client.request({ method: 'POST', url, data: { integrity_token: integrityToken } });
      return r.data?.tokenPayloadExternal || null;
    },
  };
}

