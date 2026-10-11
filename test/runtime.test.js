import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

// Railway (Railpack) picks Node from package.json engines.node first, then .nvmrc / .node-version.
// Keep all three on the same LTS major so local, CI and Railway builds match.
test('engines.node, .nvmrc and .node-version all pin Node 24 LTS', () => {
  const engines = JSON.parse(read('package.json')).engines.node;
  assert.equal(engines, '24.x');
  assert.equal(read('.nvmrc').trim(), '24');
  assert.equal(read('.node-version').trim(), '24');
  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.packages[''].engines.node, '24.x');
});

test('running on a supported Node major', () => {
  const major = Number(process.versions.node.split('.')[0]);
  assert.ok(major >= 24, `Node ${process.versions.node} is below the pinned 24 LTS`);
});
