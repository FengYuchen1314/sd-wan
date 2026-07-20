import test from 'node:test';
import assert from 'node:assert/strict';
import { validateAndCompileTopology } from '../src/core/topology.js';

const network = {
  id: 'network', dataCidr: '10.77.0.0/24', controlCidr: '10.254.0.0/24', listenPort: 51820, mtu: 1380,
};

function node(id, offset) {
  return {
    id, name: id.toUpperCase(), dataIp: `10.77.0.${offset}`, controlIp: `10.254.0.${offset}`,
    wgDataPublicKey: `${id}`.padEnd(44, '='), dataEndpoint: `${id}.example:51820`,
    reachabilityType: 'public', hasPublicEndpoint: true,
  };
}

test('链式拓扑严格编译为逐跳路由', () => {
  const nodes = [node('a', 1), node('b', 2), node('c', 3), node('d', 4)];
  const links = [
    { upstreamId: 'a', downstreamId: 'b', priority: 10 },
    { upstreamId: 'b', downstreamId: 'c', priority: 10 },
    { upstreamId: 'c', downstreamId: 'd', priority: 10 },
  ];
  const result = validateAndCompileTopology({ network, nodes, links });
  assert.equal(result.summary.fullyReachable, true);
  assert.deepEqual(result.paths['a:d'], ['a', 'b', 'c', 'd']);
  assert.equal(result.routes.a.d, 'b');
  assert.equal(result.routes.d.a, 'c');
  assert.deepEqual(result.configs.a.data.peers[0].allowedIps, ['10.77.0.2/32', '10.77.0.3/32', '10.77.0.4/32']);
  assert.deepEqual(result.configs.b.data.peers.find((peer) => peer.nodeId === 'c').allowedIps, ['10.77.0.3/32', '10.77.0.4/32']);
});

test('冗余连接根据优先级选择确定性路径', () => {
  const nodes = [node('a', 1), node('b', 2), node('c', 3)];
  const result = validateAndCompileTopology({
    network,
    nodes,
    links: [
      { upstreamId: 'a', downstreamId: 'b', priority: 1 },
      { upstreamId: 'b', downstreamId: 'c', priority: 1 },
      { upstreamId: 'a', downstreamId: 'c', priority: 50 },
    ],
  });
  assert.deepEqual(result.paths['a:c'], ['a', 'b', 'c']);
});

test('每条连接的双方可达地址覆盖节点默认 Endpoint', () => {
  const nodes = [node('a', 1), node('b', 2)];
  const result = validateAndCompileTopology({
    network,
    nodes,
    links: [{
      upstreamId: 'a', downstreamId: 'b', priority: 1,
      upstreamEndpoint: '192.168.1.10:51820', downstreamEndpoint: '10.0.0.20:51820',
    }],
  });
  assert.equal(result.configs.a.data.peers[0].endpoint, '10.0.0.20:51820');
  assert.equal(result.configs.b.data.peers[0].endpoint, '192.168.1.10:51820');
  assert.equal(result.configs.a.data.peers[0].probeIp, '10.77.0.2');
  assert.equal(result.configs.b.data.peers[0].probeIp, '10.77.0.1');
});

test('拒绝孤立节点、自连接和重复 IP', () => {
  const nodes = [node('a', 1), node('b', 2), node('c', 3)];
  assert.throws(() => validateAndCompileTopology({
    network, nodes, links: [{ upstreamId: 'a', downstreamId: 'b', priority: 1 }],
  }), /拓扑不连通/);
  assert.throws(() => validateAndCompileTopology({
    network, nodes, links: [{ upstreamId: 'a', downstreamId: 'a', priority: 1 }],
  }), /不能把自己/);
  assert.throws(() => validateAndCompileTopology({
    network, nodes: [node('a', 1), node('b', 1)], links: [{ upstreamId: 'a', downstreamId: 'b' }],
  }), /被多个节点使用/);
  const dynamicOnly = validateAndCompileTopology({
    network,
    nodes: [node('a', 1), node('b', 2)],
    links: [{ upstreamId: 'a', downstreamId: 'b', upstreamEndpoint: '', downstreamEndpoint: null }],
  });
  assert.ok(Object.values(dynamicOnly.configs).every((config) => config.data.peers[0].endpointMode === 'dynamic-learn'));
});

function childNode(id, offset, parentId, { joinMode = 'active', reachabilityType = 'nat' } = {}) {
  return {
    id, name: id.toUpperCase(), parentId, dataIp: `10.77.0.${offset}`, controlIp: `10.254.0.${offset}`,
    wgDataPublicKey: `${id}`.padEnd(44, '='), dataEndpoint: reachabilityType === 'public' ? `${id}.example:51820` : null,
    reachabilityType, joinMode, hasPublicEndpoint: reachabilityType === 'public',
  };
}

test('主动加入的父子链路强制父节点动态学习，即使子节点误带 Endpoint', () => {
  const nodes = [node('a', 1), childNode('b', 2, 'a')];
  const result = validateAndCompileTopology({
    network,
    nodes,
    links: [{
      upstreamId: 'a', downstreamId: 'b', priority: 100,
      upstreamEndpoint: '203.0.113.1:51820', downstreamEndpoint: '',
    }],
  });
  assert.equal(result.configs.a.data.peers[0].endpoint, null);
  assert.equal(result.configs.a.data.peers[0].endpointMode, 'dynamic-learn');
  assert.equal(result.configs.b.data.peers[0].endpoint, '203.0.113.1:51820');
  assert.equal(result.configs.b.data.peers[0].endpointMode, 'static-dial');
});

test('主动加入链路会清空误写的子节点公网 Endpoint', () => {
  const nodes = [node('a', 1), childNode('b', 2, 'a')];
  const result = validateAndCompileTopology({
    network,
    nodes,
    links: [{
      upstreamId: 'a', downstreamId: 'b', priority: 100,
      upstreamEndpoint: '203.0.113.1:51820', downstreamEndpoint: 'b.example:51820',
    }],
  });
  assert.equal(result.configs.a.data.peers[0].endpoint, null);
  assert.equal(result.configs.a.data.peers[0].endpointMode, 'dynamic-learn');
});
