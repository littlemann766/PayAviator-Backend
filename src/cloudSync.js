import crypto from 'node:crypto';

/** Cloud sync (per-user bills/income/spending/cushion/budget/goals/categories). Shared by PgStore and MemoryStore. */
export const SYNC_KINDS = new Set(['bill', 'income', 'spending', 'cushion', 'budget', 'goal', 'category']);
export const SYNC_LIMITS = {
  maxPushItems: 200,
  maxChangesLimit: 500,
  maxItemBytes: 8 * 1024,
  maxItemsPerUser: 20000,
  maxFutureMs: 5 * 60 * 1000,
  tombstoneDays: 90,
  bodyLimit: '512kb',
};

const ID_RE = /^[A-Za-z0-9_.:@-]{1,128}$/;

function stable(v) {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${stable(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

/** Deterministic tie-break fingerprint of an item's content. */
export const contentHash = (data, deleted) => crypto.createHash('sha256').update(stable({ d: Boolean(deleted), v: deleted ? null : data ?? null })).digest('hex');

/** Validates one pushed item. Returns { ok:true, item } (normalised, updatedAt clamped) or { ok:false, reason }. */
export function validateSyncItem(x, now = Date.now()) {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return { ok: false, reason: 'invalid_item' };
  if (typeof x.kind !== 'string' || !SYNC_KINDS.has(x.kind)) return { ok: false, reason: 'invalid_kind' };
  if (typeof x.id !== 'string' || !ID_RE.test(x.id)) return { ok: false, reason: 'invalid_id' };
  if (!Number.isSafeInteger(x.updatedAt) || x.updatedAt <= 0) return { ok: false, reason: 'invalid_updated_at' };
  if (x.deleted !== undefined && typeof x.deleted !== 'boolean') return { ok: false, reason: 'invalid_deleted' };
  const deleted = x.deleted === true;
  let data = null;
  if (!deleted) {
    if (!x.data || typeof x.data !== 'object' || Array.isArray(x.data)) return { ok: false, reason: 'invalid_data' };
    if (Buffer.byteLength(JSON.stringify(x.data)) > SYNC_LIMITS.maxItemBytes) return { ok: false, reason: 'too_large' };
    data = x.data;
  }
  return { ok: true, item: { kind: x.kind, id: x.id, data, deleted, updatedAt: Math.min(x.updatedAt, now + SYNC_LIMITS.maxFutureMs) } };
}

/** Last-write-wins: true if `incoming` should replace `existing` ({updatedAt, deleted, data}). Ties break on content hash. */
export function incomingWins(existing, incoming) {
  if (incoming.updatedAt !== existing.updatedAt) return incoming.updatedAt > existing.updatedAt;
  return contentHash(incoming.data, incoming.deleted) > contentHash(existing.data, existing.deleted);
}

export const sameContent = (a, b) => a.updatedAt === b.updatedAt && contentHash(a.data, a.deleted) === contentHash(b.data, b.deleted);

export const publicItem = r => ({ kind: r.kind, id: r.id, data: r.deleted ? null : r.data, updatedAt: r.updatedAt, deleted: Boolean(r.deleted), seq: r.seq });

/** Shared push loop; `tx` provides getRow/insert/update/count for one user (inside the store's transaction/lock). */
export async function applyPush(tx, items, now = Date.now()) {
  const results = [];
  let count = await tx.count();
  for (const raw of items) {
    const v = validateSyncItem(raw, now);
    if (!v.ok) { results.push({ kind: typeof raw?.kind === 'string' ? raw.kind : null, id: typeof raw?.id === 'string' ? raw.id : null, status: 'rejected', reason: v.reason }); continue; }
    const it = v.item;
    const cur = await tx.getRow(it.kind, it.id);
    if (!cur) {
      if (count >= SYNC_LIMITS.maxItemsPerUser) { results.push({ kind: it.kind, id: it.id, status: 'rejected', reason: 'item_limit' }); continue; }
      await tx.insert(it); count++;
      results.push({ kind: it.kind, id: it.id, status: 'accepted' });
    } else if (sameContent(cur, it)) {
      results.push({ kind: it.kind, id: it.id, status: 'accepted' }); // idempotent replay: no new seq
    } else if (incomingWins(cur, it)) {
      await tx.update(it);
      results.push({ kind: it.kind, id: it.id, status: 'accepted' });
    } else {
      results.push({ kind: it.kind, id: it.id, status: 'rejected', reason: 'stale', winner: publicItem(cur) });
    }
  }
  return results;
}
