import crypto from 'node:crypto';

// Access tokens are stored as: enc:v1:<iv b64>:<auth tag b64>:<ciphertext b64>
// AES-256-GCM, 12-byte random IV per value.
export const TOKEN_PREFIX = 'enc:v1:';

export function parseEncryptionKey(value) {
  if (!value) throw new Error('TOKEN_ENCRYPTION_KEY is empty');
  const v = String(value).trim();
  // Accept 32 bytes as 64 hex chars (e.g. `openssl rand -hex 32`) or as base64.
  const key = /^[0-9a-fA-F]{64}$/.test(v) ? Buffer.from(v, 'hex') : Buffer.from(v, 'base64');
  if (key.length !== 32) {
    throw new Error(`TOKEN_ENCRYPTION_KEY must be 32 bytes encoded as 64 hex chars or base64 (got ${key.length} bytes). Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`);
  }
  return key;
}

export function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith(TOKEN_PREFIX);
}

export function encryptToken(plaintext, key) {
  if (typeof plaintext !== 'string' || !plaintext) throw new Error('Cannot encrypt an empty token');
  if (isEncrypted(plaintext)) return plaintext;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${TOKEN_PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
}

export function decryptToken(value, key) {
  if (value == null) return value;
  // Legacy plaintext rows are tolerated (the boot migration encrypts them).
  if (!isEncrypted(value)) return value;
  const parts = value.slice(TOKEN_PREFIX.length).split(':');
  if (parts.length !== 3) throw new Error('Malformed encrypted token');
  const [iv, tag, ct] = parts.map(p => Buffer.from(p, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
