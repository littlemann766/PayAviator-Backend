import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStore } from '../src/store.js';

const DAY = 86400e3;
const fp = [{ kind: 'device', hash: 'd1' }, { kind: 'acct', hash: 'a1' }];

test('removed bank: hashes block others for 30 days, then are ignored and purged', async () => {
  const s = new MemoryStore();
  await s.claimFreeTier('u1', 'item1', fp);
  assert.ok(await s.findFreeTierConflict('u2', fp, 30), 'active claim blocks');
  await s.releaseFreeTierItem('item1');
  for (const c of s.claims.values()) c.releasedAt = Date.now() - 29 * DAY;
  assert.ok(await s.findFreeTierConflict('u2', fp, 30), 'day 29 still blocks');
  assert.equal(await s.purgeFreeTier(30), 0);
  for (const c of s.claims.values()) c.releasedAt = Date.now() - 31 * DAY;
  assert.equal(await s.findFreeTierConflict('u2', fp, 30), null, 'expired hash ignored even before purge runs');
  assert.equal(await s.purgeFreeTier(30), 2);
  assert.equal(s.claims.size, 0);
});

test('deleted user: all claims released (except kept items) and purged after 30 days', async () => {
  const s = new MemoryStore();
  await s.claimFreeTier('u1', 'item1', [fp[0]]);
  await s.claimFreeTier('u1', 'item2', [fp[1]]);
  await s.deleteUserData('u1', { keepItemIds: ['item2'] });
  const byItem = Object.fromEntries([...s.claims.values()].map(c => [c.itemId, c.releasedAt]));
  assert.ok(byItem.item1); assert.equal(byItem.item2, null, 'item whose Plaid removal failed stays active');
  for (const c of s.claims.values()) if (c.releasedAt) c.releasedAt = Date.now() - 31 * DAY;
  assert.equal(await s.purgeFreeTier(30), 1);
  assert.equal(s.claims.size, 1);
});

test('active (still linked) claims are never purged', async () => {
  const s = new MemoryStore();
  await s.claimFreeTier('u1', 'item1', fp);
  for (const c of s.claims.values()) c.createdAt = Date.now() - 400 * DAY;
  assert.equal(await s.purgeFreeTier(30), 0);
});
