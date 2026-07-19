import test from 'node:test';
import assert from 'node:assert/strict';
import { enumerateSimplePaths } from '../src/core/paths.js';

const nodes = ['a', 'b', 'c', 'd', 'e'].map((id) => ({ id, name: id.toUpperCase() }));
const links = [
  { id: 'ab', upstreamId: 'a', downstreamId: 'b', priority: 1 },
  { id: 'bd', upstreamId: 'b', downstreamId: 'd', priority: 1 },
  { id: 'ac', upstreamId: 'a', downstreamId: 'c', priority: 2 },
  { id: 'cd', upstreamId: 'c', downstreamId: 'd', priority: 2 },
  { id: 'bc', upstreamId: 'b', downstreamId: 'c', priority: 3 },
  { id: 'ce', upstreamId: 'c', downstreamId: 'e', priority: 4 },
  { id: 'ed', upstreamId: 'e', downstreamId: 'd', priority: 4 },
];

test('枚举两节点间的无环路径并允许中间节点跨路径重复', () => {
  const result = enumerateSimplePaths({ nodes, links, sourceId: 'a', targetId: 'd' });
  assert.ok(result.paths.length >= 4);
  assert.deepEqual(result.paths[0].nodeIds, ['a', 'b', 'd']);
  for (const path of result.paths) {
    assert.equal(new Set(path.nodeIds).size, path.nodeIds.length);
    assert.equal(path.nodeIds[0], 'a');
    assert.equal(path.nodeIds.at(-1), 'd');
  }
  const occurrencesOfC = result.paths.filter((path) => path.nodeIds.includes('c')).length;
  assert.ok(occurrencesOfC >= 2);
});

test('正反方向使用相同的稳定路径标识', () => {
  const forward = enumerateSimplePaths({ nodes, links, sourceId: 'a', targetId: 'd' });
  const reverse = enumerateSimplePaths({ nodes, links, sourceId: 'd', targetId: 'a' });
  assert.deepEqual(
    new Set(forward.paths.map((path) => path.id)),
    new Set(reverse.paths.map((path) => path.id)),
  );
});

