import test from 'node:test';
import assert from 'node:assert/strict';
import { Database } from '../src/center/database.js';
import { ControlService } from '../src/center/service.js';

function fixture() {
  const database = new Database(':memory:');
  const service = new ControlService(database, { publicUrl: 'https://center.example' });
  const network = service.createNetwork({
    name: '测试网络', dataCidr: '10.77.0.0/24', controlCidr: '10.254.0.0/24', listenPort: 51820, mtu: 1380,
  });
  return { database, service, network, center: service.listNodes(network.id)[0] };
}

test('创建网络时生成中心节点与首个 active 配置', () => {
  const { database, service, network, center } = fixture();
  try {
    assert.equal(center.isCenter, true);
    assert.equal(center.dataIp, '10.77.0.1');
    assert.equal(center.controlIp, '10.254.0.1');
    const versions = service.listConfigurations(network.id);
    assert.equal(versions.length, 1);
    assert.equal(versions[0].status, 'active');
  } finally { database.close(); }
});

test('一次性令牌注册节点并自动加入所选父节点', () => {
  const { database, service, network, center } = fixture();
  try {
    const enrollment = service.createJoinToken(network.id, { parentId: center.id, ttlMinutes: 30 });
    assert.match(enrollment.command, /--join-token/);
    const result = service.registerAgent({
      token: enrollment.token,
      name: '上海边缘-02',
      wgControlPublicKey: 'c'.repeat(44),
      wgDataPublicKey: 'd'.repeat(44),
      dataEndpoint: '203.0.113.2:51820',
    });
    assert.equal(result.node.parentId, center.id);
    assert.equal(result.node.dataIp, '10.77.0.2');
    assert.equal(service.listLinks(network.id).length, 1);
    assert.equal(service.getTopology(network.id).validation.fullyReachable, true);
    assert.throws(() => service.registerAgent({ token: enrollment.token, name: '重复使用' }), /已过期或已使用/);
  } finally { database.close(); }
});

test('修改业务 IP 生成新版本并拒绝地址冲突', () => {
  const { database, service, network, center } = fixture();
  try {
    const enrollment = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: enrollment.token, name: '边缘', wgDataPublicKey: 'd'.repeat(44) }).node;
    const changed = service.updateNode(edge.id, { dataIp: '10.77.0.25' });
    assert.equal(changed.node.dataIp, '10.77.0.25');
    assert.equal(changed.version.status, 'preparing');
    assert.throws(() => service.updateNode(edge.id, { dataIp: center.dataIp }), /被多个节点使用/);
  } finally { database.close(); }
});

test('被动令牌只能通过认领注册流程使用', () => {
  const { database, service, network, center } = fixture();
  try {
    const enrollment = service.createJoinToken(network.id, { parentId: center.id, mode: 'passive' });
    assert.match(enrollment.command, /--claim-token/);
    assert.doesNotMatch(enrollment.command, /--upstream/);
    assert.throws(() => service.registerAgent({ token: enrollment.token, name: '错误主动注册' }), /被动令牌/);
    const claimed = service.registerAgent({ token: enrollment.token, passive: true, name: '被认领节点', wgDataPublicKey: 'e'.repeat(44) });
    assert.equal(claimed.node.parentId, center.id);
  } finally { database.close(); }
});

test('选择边缘父节点时强制携带新设备可达的中继地址', () => {
  const { database, service, network, center } = fixture();
  try {
    const first = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: first.token, name: '一级边缘', wgDataPublicKey: 'f'.repeat(44) }).node;
    assert.throws(() => service.createJoinToken(network.id, { parentId: edge.id }), /尚未配置.*中继地址/);
    service.updateNode(edge.id, { controlEndpoint: 'http://192.168.8.20:8790', dataEndpoint: '192.168.8.20:51820' });
    const second = service.createJoinToken(network.id, { parentId: edge.id });
    assert.match(second.command, /192\.168\.8\.20%3A8790/);
    assert.match(second.command, /--upstream 'http:\/\/192\.168\.8\.20:8790'/);
  } finally { database.close(); }
});

test('可视化新增连接必须经两个节点准备和双向探测后激活', () => {
  const { database, service, network, center } = fixture();
  try {
    const tokenA = service.createJoinToken(network.id, { parentId: center.id });
    const nodeA = service.registerAgent({
      token: tokenA.token, name: '节点 A', wgDataPublicKey: 'a'.repeat(44), dataEndpoint: '192.168.1.10:51820',
    }).node;
    const tokenB = service.createJoinToken(network.id, { parentId: center.id });
    const nodeB = service.registerAgent({
      token: tokenB.token, name: '节点 B', wgDataPublicKey: 'b'.repeat(44), dataEndpoint: '10.10.0.20:51820',
    }).node;

    const candidate = service.createLinkValidation(network.id, {
      nodeAId: nodeA.id, nodeBId: nodeB.id,
      nodeAAddress: '192.168.1.10', nodeBAddress: '10.10.0.20', priority: 5,
    });
    assert.equal(candidate.validationStatus, 'preparing');
    assert.equal(candidate.upstreamEndpoint, '192.168.1.10:51820');
    assert.equal(candidate.downstreamEndpoint, '10.10.0.20:51820');

    const prepareA = service.claimCommand(nodeA.id);
    const prepareB = service.claimCommand(nodeB.id);
    assert.equal(prepareA.type, 'prepare-link-probe');
    assert.equal(prepareB.type, 'prepare-link-probe');
    service.completeCommand(nodeA.id, prepareA.id, { ok: true });
    service.completeCommand(nodeB.id, prepareB.id, { ok: true });
    assert.equal(service.listLinks(network.id).find((link) => link.id === candidate.id).validationStatus, 'probing');

    const probeA = service.claimCommand(nodeA.id);
    const probeB = service.claimCommand(nodeB.id);
    assert.equal(probeA.type, 'execute-link-probe');
    assert.equal(probeB.type, 'execute-link-probe');
    service.completeCommand(nodeA.id, probeA.id, { ok: true, remoteNodeId: nodeB.id });
    service.completeCommand(nodeB.id, probeB.id, { ok: true, remoteNodeId: nodeA.id });

    const active = service.listLinks(network.id).find((link) => link.id === candidate.id);
    assert.equal(active.validationStatus, 'active');
    assert.ok(active.validatedAt);
    assert.equal(service.getTopology(network.id).validation.fullyReachable, true);
    assert.equal(service.listConfigurations(network.id)[0].reason, '新增已验证的数据通路');
  } finally { database.close(); }
});

test('新增连接拒绝非法互访地址和重复节点对', () => {
  const { database, service, network, center } = fixture();
  try {
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: token.token, name: '边缘', wgDataPublicKey: 'c'.repeat(44) }).node;
    const token2 = service.createJoinToken(network.id, { parentId: center.id });
    const edge2 = service.registerAgent({ token: token2.token, name: '边缘 2', wgDataPublicKey: 'd'.repeat(44) }).node;
    assert.throws(() => service.createLinkValidation(network.id, {
      nodeAId: edge.id, nodeBId: edge2.id, nodeAAddress: 'https://bad.example', nodeBAddress: '10.0.0.2',
    }), /不要包含协议/);
    assert.throws(() => service.createLinkValidation(network.id, {
      nodeAId: center.id, nodeBId: edge.id, nodeAAddress: '203.0.113.1', nodeBAddress: '10.0.0.2',
    }), /已经存在连接/);
  } finally { database.close(); }
});
