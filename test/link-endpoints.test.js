import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isChildInitiatedJoinLink,
  isDialOutOnlyNode,
  isInitializationJoinLink,
  isManualBidirectionalPublicLink,
  resolveLinkEndpoints,
  resolveInitializationJoinUpstreamEndpoint,
  selectLinkBenchmarkDirection,
  selectLinkDialDirection,
  validationInternalProbePlan,
} from '../src/core/link-endpoints.js';

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
  assert.equal(isInitializationJoinLink(upstream, downstream), true);
  assert.equal(isChildInitiatedJoinLink({}, upstream, downstream), true);
  const direction = selectLinkDialDirection({}, upstream, downstream);
  assert.equal(direction.dialerId, 'child');
  assert.equal(direction.targetId, 'pub');
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

test('初始化 join 链路在 upstream_endpoint 为空时回退父节点 WireGuard 端点', () => {
  const upstream = {
    id: 'ix', parentId: null, reachabilityType: 'ix', dataEndpoint: '10.20.0.8:19801', dataIp: '10.1.0.1',
  };
  const downstream = {
    id: 'nat', parentId: 'ix', reachabilityType: 'nat', joinMode: 'active', dataIp: '10.1.0.2',
  };
  const resolved = resolveLinkEndpoints(
    { upstreamEndpoint: '', downstreamEndpoint: '' },
    upstream,
    downstream,
  );
  assert.equal(resolved.upstreamEndpoint, '10.20.0.8:19801');
  assert.equal(resolved.downstreamEndpoint, null);
});

test('初始化 join 链路延迟探测沿 B→A 拨号方向，与节点类型无关', () => {
  const upstream = { id: 'pub', parentId: null, reachabilityType: 'public', joinMode: 'center', dataIp: '10.0.0.1', dataEndpoint: '203.0.113.1:51820' };
  const downstream = { id: 'nat', parentId: 'pub', reachabilityType: 'nat', joinMode: 'active', dataIp: '10.0.0.2' };
  const link = { upstreamId: 'pub', downstreamId: 'nat', upstreamEndpoint: '203.0.113.1:51820', downstreamEndpoint: null };
  const direction = selectLinkBenchmarkDirection(link, upstream, downstream);
  assert.equal(direction.sourceId, 'nat');
  assert.equal(direction.targetId, 'pub');
  const plan = validationInternalProbePlan(
    { upstream_endpoint: null, downstream_endpoint: null, upstream_id: 'pub', downstream_id: 'nat' },
    upstream,
    downstream,
  );
  assert.equal(plan.requested, 1);
  assert.deepEqual(plan.probes, [{ sourceId: 'nat', targetId: 'pub' }]);
});

test('面板手动双公网建链才双向探测', () => {
  const upstream = { id: 'a', reachabilityType: 'public', dataIp: '10.1.0.1', parentId: null, joinMode: 'center' };
  const downstream = { id: 'b', reachabilityType: 'public', dataIp: '10.1.0.2', parentId: null, joinMode: 'center' };
  assert.equal(isManualBidirectionalPublicLink(
    upstream,
    downstream,
    '203.0.113.1:51820',
    '203.0.113.2:51820',
  ), true);
  const plan = validationInternalProbePlan(
    {
      upstream_endpoint: '203.0.113.1:51820',
      downstream_endpoint: '203.0.113.2:51820',
      upstream_id: 'a',
      downstream_id: 'b',
    },
    upstream,
    downstream,
  );
  assert.equal(plan.requested, 2);
});

test('公网 + IX 手动建链只探测单方向', () => {
  const upstream = { id: 'ix', reachabilityType: 'ix', dataIp: '10.2.0.1', parentId: null, joinMode: 'center' };
  const downstream = { id: 'pub', reachabilityType: 'public', dataIp: '10.2.0.2', parentId: null, joinMode: 'center' };
  assert.equal(isManualBidirectionalPublicLink(
    upstream,
    downstream,
    '10.20.0.8:19801',
    '198.51.100.8:19801',
  ), false);
});
