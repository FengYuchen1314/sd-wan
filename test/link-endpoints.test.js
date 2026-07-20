import test from 'node:test';
import assert from 'node:assert/strict';
import { isDialOutOnlyNode, resolveLinkEndpoints } from '../src/core/link-endpoints.js';

test('主动加入节点在所有链路上都不发布 Endpoint', () => {
  const upstream = {
    id: 'pub', parentId: null, reachabilityType: 'public', joinMode: 'passive',
    dataEndpoint: '203.0.113.1:51820',
  };
  const downstream = {
    id: 'nat', parentId: 'pub', reachabilityType: 'nat', joinMode: 'active',
    dataEndpoint: null,
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

test('主动加入节点作为 upstream 时不提供可被拨入地址', () => {
  const upstream = {
    id: 'nat', parentId: 'root', reachabilityType: 'nat', joinMode: 'active',
    dataEndpoint: null,
  };
  const downstream = {
    id: 'pub', parentId: null, reachabilityType: 'public', joinMode: 'passive',
    dataEndpoint: '203.0.113.2:51820',
  };
  const resolved = resolveLinkEndpoints(
    {
      upstreamEndpoint: '10.0.0.1:51820',
      downstreamEndpoint: '203.0.113.2:51820',
    },
    upstream,
    downstream,
  );
  assert.equal(resolved.upstreamEndpoint, null);
  assert.equal(resolved.downstreamEndpoint, '203.0.113.2:51820');
});

test('isDialOutOnlyNode 识别主动加入与纯 NAT', () => {
  assert.equal(isDialOutOnlyNode({ joinMode: 'active', reachabilityType: 'public' }), true);
  assert.equal(isDialOutOnlyNode({ joinMode: 'passive', reachabilityType: 'nat' }), true);
  assert.equal(isDialOutOnlyNode({ joinMode: 'passive', reachabilityType: 'public' }), false);
});
