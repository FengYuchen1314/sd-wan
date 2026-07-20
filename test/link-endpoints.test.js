import test from 'node:test';
import assert from 'node:assert/strict';
import { isDialOutOnlyNode, resolveLinkEndpoints } from '../src/core/link-endpoints.js';

test('主动加入的公网子节点在父子链路上仍由父节点动态学习', () => {
  const upstream = {
    id: 'pub', parentId: null, reachabilityType: 'public', joinMode: 'center',
    dataEndpoint: '203.0.113.1:51820',
  };
  const downstream = {
    id: 'child', parentId: 'pub', reachabilityType: 'public', joinMode: 'active',
    dataEndpoint: '198.51.100.8:51820',
  };
  const resolved = resolveLinkEndpoints(
    {
      upstreamEndpoint: '203.0.113.1:51820',
      downstreamEndpoint: '198.51.100.8:51820',
    },
    upstream,
    downstream,
  );
  assert.equal(resolved.upstreamEndpoint, '203.0.113.1:51820');
  assert.equal(resolved.downstreamEndpoint, null);
});

test('主动加入的公网节点在后续拓扑链路上仍可按公网 Endpoint 被拨入', () => {
  const upstream = {
    id: 'pub', parentId: null, reachabilityType: 'public', joinMode: 'center',
    dataEndpoint: '203.0.113.1:51820',
  };
  const downstream = {
    id: 'child', parentId: 'other', reachabilityType: 'public', joinMode: 'active',
    dataEndpoint: '198.51.100.8:51820',
  };
  const resolved = resolveLinkEndpoints(
    {
      upstreamEndpoint: '203.0.113.1:51820',
      downstreamEndpoint: '198.51.100.8:51820',
    },
    upstream,
    downstream,
  );
  assert.equal(resolved.upstreamEndpoint, '203.0.113.1:51820');
  assert.equal(resolved.downstreamEndpoint, '198.51.100.8:51820');
});

test('isDialOutOnlyNode 仅识别纯 NAT，不含主动加入的公网或 IX', () => {
  assert.equal(isDialOutOnlyNode({ joinMode: 'active', reachabilityType: 'public' }), false);
  assert.equal(isDialOutOnlyNode({ joinMode: 'active', reachabilityType: 'ix' }), false);
  assert.equal(isDialOutOnlyNode({ joinMode: 'passive', reachabilityType: 'nat' }), true);
});
