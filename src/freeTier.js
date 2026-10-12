import crypto from 'node:crypto';

/**
 * Free-tier abuse limits. Only keyed HMAC-SHA256 hashes are stored (never the raw
 * account mask, persistent account id or device id). Without the server secret the
 * hashes cannot be reversed or matched against anything else.
 */
export const KIND = { ACCOUNT: 'acct', PERSISTENT_ACCOUNT: 'pacct', DEVICE: 'device' };

const norm = v => String(v ?? '').trim().toLowerCase();
export const hmac = (secret, value) => crypto.createHmac('sha256', secret).update(value).digest('hex');

/** One hash per (institution, mask) and one per persistent_account_id, so either can match. */
export function accountFingerprints(secret, institutionId, accounts = []) {
  const out = new Map();
  const inst = norm(institutionId);
  for (const a of accounts) {
    if (inst && norm(a?.mask)) { const h = hmac(secret, `acct|${inst}|${norm(a.mask)}`); out.set(`${KIND.ACCOUNT}:${h}`, { kind: KIND.ACCOUNT, hash: h }); }
    if (a?.persistent_account_id) { const h = hmac(secret, `pacct|${String(a.persistent_account_id).trim()}`); out.set(`${KIND.PERSISTENT_ACCOUNT}:${h}`, { kind: KIND.PERSISTENT_ACCOUNT, hash: h }); }
  }
  return [...out.values()];
}

export function deviceFingerprint(secret, deviceId) {
  return { kind: KIND.DEVICE, hash: hmac(secret, `device|${String(deviceId).trim()}`) };
}

/** Raw X-Device-Id: app-generated, 8..256 printable chars. */
export function readDeviceId(req) {
  const v = String(req.get('x-device-id') || '').trim();
  return /^[\x21-\x7e]{8,256}$/.test(v) ? v : null;
}

export const gateError = (status, body) => Object.assign(new Error(body.error), { status, body });
