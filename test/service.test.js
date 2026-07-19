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

test('连接验证超过有效期后自动失败并取消节点命令', () => {
  const { database, service, network, center } = fixture();
  try {
    const tokenA = service.createJoinToken(network.id, { parentId: center.id });
    const nodeA = service.registerAgent({ token: tokenA.token, name: '超时节点 A', wgDataPublicKey: 'a'.repeat(44) }).node;
    const tokenB = service.createJoinToken(network.id, { parentId: center.id });
    const nodeB = service.registerAgent({ token: tokenB.token, name: '超时节点 B', wgDataPublicKey: 'b'.repeat(44) }).node;
    const candidate = service.createLinkValidation(network.id, {
      nodeAId: nodeA.id, nodeBId: nodeB.id,
      nodeAAddress: '192.168.1.20', nodeBAddress: '192.168.1.21', priority: 10,
    });

    const result = service.reconcileRuntimeState(new Date(Date.parse(candidate.validationExpiresAt) + 1));
    const expired = service.listLinks(network.id).find((link) => link.id === candidate.id);
    const commands = database.all(
      "SELECT status, result_json FROM commands WHERE type = 'prepare-link-probe' ORDER BY created_at",
    );

    assert.equal(result.expiredLinks, 1);
    assert.equal(result.cancelledCommands, 2);
    assert.equal(expired.validationStatus, 'failed');
    assert.match(expired.validationError, /超时/);
    assert.deepEqual(commands.map((command) => command.status), ['failed', 'failed']);
    assert.ok(commands.every((command) => JSON.parse(command.result_json).ok === false));
  } finally { database.close(); }
});

test('边缘节点心跳超时后离线并可通过新心跳恢复', () => {
  const { database, service, network, center } = fixture();
  try {
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: token.token, name: '心跳节点', wgDataPublicKey: 'c'.repeat(44) }).node;
    const afterDeadline = new Date(Date.parse(edge.lastSeen) + service.nodeOfflineAfterMs + 1);

    const result = service.reconcileRuntimeState(afterDeadline);
    assert.equal(result.offlineNodes, 1);
    assert.equal(service.getNode(edge.id).status, 'offline');
    assert.equal(service.getNode(center.id).status, 'online');

    service.heartbeat(edge.id);
    assert.equal(service.getNode(edge.id).status, 'online');
  } finally { database.close(); }
});

test('保存两节点多路径权重并写入版本化节点配置', () => {
  const { database, service, network, center } = fixture();
  try {
    const tokenA = service.createJoinToken(network.id, { parentId: center.id });
    const nodeA = service.registerAgent({ token: tokenA.token, name: '多路径 A', wgDataPublicKey: 'a'.repeat(44) }).node;
    const tokenB = service.createJoinToken(network.id, { parentId: center.id });
    const nodeB = service.registerAgent({ token: tokenB.token, name: '多路径 B', wgDataPublicKey: 'b'.repeat(44) }).node;
    const direct = service.createLinkValidation(network.id, {
      nodeAId: nodeA.id, nodeBId: nodeB.id,
      nodeAAddress: '192.168.10.10', nodeBAddress: '192.168.10.11', priority: 1,
    });
    for (const node of [nodeA, nodeB]) {
      const command = service.claimCommand(node.id);
      service.completeCommand(node.id, command.id, { ok: true });
    }
    for (const node of [nodeA, nodeB]) {
      const command = service.claimCommand(node.id);
      service.completeCommand(node.id, command.id, { ok: true });
    }
    assert.equal(service.listLinks(network.id).find((link) => link.id === direct.id).validationStatus, 'active');

    const options = service.getPathOptions(network.id, nodeA.id, nodeB.id);
    assert.equal(options.paths.length, 2);
    const saved = service.savePathPolicy(network.id, {
      sourceId: nodeA.id,
      targetId: nodeB.id,
      paths: [
        { pathId: options.paths[0].id, weight: 3 },
        { pathId: options.paths[1].id, weight: 1 },
      ],
    });
    assert.equal(saved.details.policy.paths.length, 2);
    assert.deepEqual(saved.details.policy.paths.map((path) => path.weight), [3, 1]);

    const row = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', saved.version.id, nodeA.id,
    );
    const config = JSON.parse(row.config_json);
    assert.equal(config.multipathPolicies.length, 1);
    assert.equal(config.multipathPolicies[0].targetNodeId, nodeB.id);
    assert.deepEqual(config.multipathPolicies[0].paths.map((path) => path.share), [0.75, 0.25]);

    const removed = service.deletePathPolicy(network.id, nodeA.id, nodeB.id);
    assert.equal(removed.deleted, true);
    assert.equal(removed.details.policy, null);
  } finally { database.close(); }
});
