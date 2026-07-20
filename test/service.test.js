import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
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

function coordinatorUpstreamUrl(service, networkId) {
  const coordinator = service.getNode(service.getClusterState(networkId).coordinatorNodeId);
  return `http://${coordinator.dataIp}:${coordinator.controlListenPort}`;
}

function internalControlUrl(node) {
  return `http://${node.dataIp}:${node.controlListenPort}`;
}

function registerPublicEdge(service, network, parent, input = {}) {
  const token = service.createJoinToken(network.id, {
    parentId: parent.id,
    mode: 'passive',
    ...(input.tokenOptions ?? {}),
  });
  return service.registerAgent({
    token: token.token,
    passive: true,
    name: input.name ?? '公网边缘',
    wgDataPublicKey: input.wgDataPublicKey ?? 'a'.repeat(44),
    dataEndpoint: input.dataEndpoint ?? '192.168.1.10:51820',
    controlEndpoint: input.controlEndpoint,
    controlListenPort: input.controlListenPort,
    dataListenPort: input.dataListenPort,
    reachabilityType: input.reachabilityType ?? 'public',
    hasPublicEndpoint: input.hasPublicEndpoint ?? true,
    canRelay: input.canRelay,
  });
}

function registerActiveJoinNode(service, network, parent, input = {}) {
  const token = service.createJoinToken(network.id, {
    parentId: parent.id,
    ...(input.tokenOptions ?? {}),
  });
  return service.registerAgent({
    token: token.token,
    name: input.name ?? '主动加入节点',
    wgDataPublicKey: input.wgDataPublicKey ?? 'n'.repeat(44),
    dataListenPort: input.dataListenPort,
    controlListenPort: input.controlListenPort,
    reachabilityType: input.reachabilityType,
    dataEndpoint: input.dataEndpoint,
    controlEndpoint: input.controlEndpoint,
  });
}

test('创建网络时生成初始协调节点与首个 active 配置', () => {
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

test('初始节点使用 IPv6 公网地址时生成合法的 WireGuard Endpoint', () => {
  const database = new Database(':memory:');
  const service = new ControlService(database, { publicUrl: 'https://[2001:db8::10]:19773' });
  try {
    const network = service.createNetwork({
      name: 'IPv6 入口', dataCidr: '10.80.0.0/24', controlCidr: '10.250.0.0/24', listenPort: 19801, mtu: 1380,
    });
    const center = service.listNodes(network.id)[0];
    assert.equal(center.controlEndpoint, 'https://[2001:db8::10]:19773');
    assert.equal(center.dataEndpoint, '[2001:db8::10]:19801');
  } finally { database.close(); }
});

test('一次性令牌注册节点并自动加入所选父节点', () => {
  const { database, service, network, center } = fixture();
  try {
    const enrollment = service.createJoinToken(network.id, { parentId: center.id, ttlMinutes: 30 });
    assert.match(enrollment.command, /--join-token/);
    assert.doesNotMatch(enrollment.command, /--role|--panel-password|--admin-token/);
    const result = service.registerAgent({
      token: enrollment.token,
      name: '上海边缘-02',
      wgControlPublicKey: 'c'.repeat(44),
      wgDataPublicKey: 'd'.repeat(44),
      dataEndpoint: '203.0.113.2:51820',
    });
    assert.equal(result.node.parentId, center.id);
    assert.equal(result.node.dataIp, '10.77.0.2');
    assert.equal(result.node.dataListenPort, 51820);
    const initialLink = service.listLinks(network.id)[0];
    assert.equal(initialLink.upstreamEndpoint, center.dataEndpoint);
    assert.equal(initialLink.downstreamEndpoint, '');
    const version = service.listConfigurations(network.id)[0];
    const centerConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', version.id, center.id,
    ).config_json);
    const childConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', version.id, result.node.id,
    ).config_json);
    assert.equal(centerConfig.data.peers.find((peer) => peer.nodeId === result.node.id).endpoint, null);
    assert.equal(centerConfig.data.peers.find((peer) => peer.nodeId === result.node.id).endpointMode, 'dynamic-learn');
    assert.equal(childConfig.data.peers.find((peer) => peer.nodeId === center.id).endpoint, center.dataEndpoint);
    assert.equal(childConfig.data.peers.find((peer) => peer.nodeId === center.id).endpointMode, 'static-dial');
    assert.equal(service.getTopology(network.id).validation.fullyReachable, true);
    database.run(
      'UPDATE topology_links SET upstream_endpoint = NULL, downstream_endpoint = NULL, endpoint_semantics_version = 0 WHERE id = ?',
      initialLink.id,
    );
    database.migrate();
    const migrated = service.listLinks(network.id)[0];
    assert.equal(migrated.upstreamEndpoint, center.dataEndpoint);
    assert.equal(migrated.downstreamEndpoint, '');
    for (const row of database.all('SELECT node_id, config_json FROM node_configs WHERE version_id = ?', version.id)) {
      const legacyConfig = JSON.parse(row.config_json);
      for (const peer of legacyConfig.data.peers) delete peer.endpointMode;
      database.run(
        'UPDATE node_configs SET config_json = ? WHERE version_id = ? AND node_id = ?',
        JSON.stringify(legacyConfig), version.id, row.node_id,
      );
    }
    const regenerated = service.ensureEndpointSemanticConfigurations();
    assert.equal(regenerated.created.length, 1);
    assert.equal(regenerated.errors.length, 0);
    const regeneratedConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', regenerated.created[0].versionId, center.id,
    ).config_json);
    assert.equal(regeneratedConfig.data.peers[0].endpoint, null);
    assert.equal(regeneratedConfig.data.peers[0].endpointMode, 'dynamic-learn');
    assert.throws(() => service.registerAgent({ token: enrollment.token, name: '重复使用' }), /已过期或已使用/);
  } finally { database.close(); }
});

test('IX 主动加入不会因本机 NAT 端口无效而从节点列表回滚', () => {
  const { database, service, network, center } = fixture();
  try {
    database.run('UPDATE nodes SET data_endpoint = NULL WHERE id = ?', center.id);
    const token = service.createJoinToken(network.id, {
      parentId: center.id,
      parentHost: 'panel-gateway.example',
      parentPort: 19773,
      parentDataHost: 'london-wg.example',
      parentDataPort: 31801,
    });
    assert.deepEqual(token.parentDataConnection, {
      host: 'london-wg.example', port: 31801, endpoint: 'london-wg.example:31801',
    });
    const ix = service.registerAgent({
      token: token.token,
      name: '上海 IX',
      dataEndpoint: '10.20.30.40:19801',
      dataListenPort: 19801,
      wgDataPublicKey: 'i'.repeat(44),
    }).node;
    assert.ok(service.listNodes(network.id).some((node) => node.id === ix.id));
    const link = service.listLinks(network.id, true).find((item) => item.downstreamId === ix.id);
    assert.equal(link.upstreamEndpoint, 'london-wg.example:31801');
    assert.equal(link.downstreamEndpoint, '');
    const version = service.listConfigurations(network.id)[0];
    const parentConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', version.id, center.id,
    ).config_json);
    const ixConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', version.id, ix.id,
    ).config_json);
    assert.equal(parentConfig.data.peers.find((peer) => peer.nodeId === ix.id).endpoint, null);
    assert.equal(parentConfig.data.peers.find((peer) => peer.nodeId === ix.id).endpointMode, 'dynamic-learn');
    assert.equal(ixConfig.data.peers.find((peer) => peer.nodeId === center.id).endpoint, 'london-wg.example:31801');
    assert.equal(ixConfig.data.peers.find((peer) => peer.nodeId === center.id).endpointMode, 'static-dial');

    const legacyToken = service.createJoinToken(network.id, {
      parentId: center.id,
      parentHost: 'panel-gateway.example',
      parentDataHost: 'london-wg.example',
    });
    database.run('UPDATE join_tokens SET parent_data_endpoint = NULL WHERE id = ?', legacyToken.id);
    const legacyIx = service.registerAgent({
      token: legacyToken.token, name: '旧令牌 IX', wgDataPublicKey: 'j'.repeat(44),
    }).node;
    assert.ok(service.listNodes(network.id).some((node) => node.id === legacyIx.id));
    const legacyLink = service.listLinks(network.id, true).find((item) => item.downstreamId === legacyIx.id);
    assert.equal(legacyLink.upstreamEndpoint, 'center.example:51820');
    assert.equal(legacyLink.downstreamEndpoint, '');
  } finally { database.close(); }
});

test('修改业务 IP 生成新版本并拒绝地址冲突', () => {
  const { database, service, network, center } = fixture();
  try {
    const enrollment = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: enrollment.token, name: '边缘', wgDataPublicKey: 'd'.repeat(44) }).node;
    const changed = service.updateNode(edge.id, { dataIp: '10.77.0.25' });
    assert.equal(changed.node.dataIp, edge.dataIp);
    assert.equal(changed.pendingNode.dataIp, '10.77.0.25');
    assert.equal(changed.version.status, 'preparing');
    assert.equal(service.getTopology(network.id).addressChange.assignments[0].after, '10.77.0.25');
    assert.throws(() => service.updateNode(edge.id, { dataIp: center.dataIp }), /被多个节点使用/);
    service.reportConfig(edge.id, changed.version.id, 'prepared');
    service.reportConfig(edge.id, changed.version.id, 'activated');
    assert.equal(service.getNode(edge.id).dataIp, '10.77.0.25');
    assert.equal(service.getTopology(network.id).addressChange, null);
  } finally { database.close(); }
});

test('业务 IP 下发失败时数据库和面板继续保留原地址', () => {
  const { database, service, network, center } = fixture();
  try {
    const enrollment = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: enrollment.token, name: '地址回滚节点', wgDataPublicKey: 'g'.repeat(44) }).node;
    const changed = service.updateNode(edge.id, { dataIp: '10.77.0.88' });
    service.reportConfig(edge.id, changed.version.id, 'prepared', '本机路由冲突');

    assert.equal(service.getConfiguration(changed.version.id).status, 'failed');
    assert.equal(service.getNode(edge.id).dataIp, edge.dataIp);
    const addressChange = service.getTopology(network.id).addressChange;
    assert.equal(addressChange.status, 'failed');
    assert.equal(addressChange.error, '本机路由冲突');
  } finally { database.close(); }
});

test('被动令牌只能通过认领注册流程使用', () => {
  const { database, service, network, center } = fixture();
  try {
    const enrollment = service.createJoinToken(network.id, { parentId: center.id, mode: 'passive' });
    assert.match(enrollment.command, /--claim-token/);
    assert.doesNotMatch(enrollment.command, /--upstream/);
    assert.throws(() => service.registerAgent({ token: enrollment.token, name: '错误主动注册' }), /被动令牌/);
    const claimed = service.registerAgent({
      token: enrollment.token,
      passive: true,
      name: '被认领节点',
      wgDataPublicKey: 'e'.repeat(44),
      controlEndpoint: 'http://192.168.30.50:8792',
      controlListenPort: 8792,
      dataEndpoint: '192.168.30.50:19803',
      dataListenPort: 19803,
    });
    assert.equal(claimed.node.parentId, center.id);
  } finally { database.close(); }
});

test('被动认领固定从指定 GitHub 仓库安装，命令不要求目标访问父节点', () => {
  const { database, service, network, center } = fixture();
  try {
    const enrollment = service.createJoinToken(network.id, {
      parentId: center.id,
      mode: 'passive',
      parentHost: '',
    });
    assert.equal(enrollment.publicSourceUrl, 'https://raw.githubusercontent.com/FengYuchen1314/sd-wan/main');
    assert.match(enrollment.command, /raw\.githubusercontent\.com\/FengYuchen1314\/sd-wan\/main\/scripts\/install\.sh\?cache=\d+/);
    assert.match(enrollment.command, /--source 'https:\/\/raw\.githubusercontent\.com\/FengYuchen1314\/sd-wan\/main'/);
    assert.match(enrollment.command, /--claim-token/);
    assert.doesNotMatch(enrollment.command, /--data-port/);
    assert.doesNotMatch(enrollment.command, /--upstream/);
    assert.equal(enrollment.sourceUrl, null);
    assert.equal(enrollment.parentConnection, null);
  } finally { database.close(); }
});

test('选择边缘父节点时强制携带新设备可达的中继地址', () => {
  const { database, service, network, center } = fixture();
  try {
    const first = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: first.token, name: '一级边缘', wgDataPublicKey: 'f'.repeat(44) }).node;
    assert.throws(() => service.createJoinToken(network.id, { parentId: edge.id }), /纯 NAT 节点|没有公网拨入能力/);
    service.updateNode(edge.id, {
      hasPublicEndpoint: true,
      canRelay: true,
      controlEndpoint: 'http://192.168.8.20:8790',
      dataEndpoint: '192.168.8.20:51820',
    });
    const second = service.createJoinToken(network.id, { parentId: edge.id });
    assert.match(second.command, /curl -fsSL 'http:\/\/192\.168\.8\.20:8790\/install\.sh'/);
    assert.match(second.command, /--source 'http:\/\/192\.168\.8\.20:8790'/);
    assert.match(second.command, /--upstream 'http:\/\/192\.168\.8\.20:8790'/);
  } finally { database.close(); }
});

test('公网子节点通过边缘父节点主动加入时，父节点仍动态学习子节点 Endpoint', () => {
  const { database, service, network, center } = fixture();
  try {
    const edge = registerPublicEdge(service, network, center, {
      name: '边缘 A',
      wgDataPublicKey: 'a'.repeat(44),
      dataEndpoint: '192.168.8.20:51820',
      controlEndpoint: 'http://192.168.8.20:8790',
    }).node;
    const childToken = service.createJoinToken(network.id, {
      parentId: edge.id,
      parentHost: '192.168.8.20',
      parentPort: 8790,
      parentDataHost: '192.168.8.20',
      parentDataPort: 51820,
    });
    const child = service.registerAgent({
      token: childToken.token,
      name: '公网子节点 B',
      wgDataPublicKey: 'b'.repeat(44),
      dataEndpoint: '203.0.113.50:51820',
    });
    assert.equal(child.node.parentId, edge.id);
    assert.equal(child.node.reachabilityType, 'public');
    assert.equal(child.node.joinMode, 'active');
    assert.equal(child.node.dataEndpoint, '203.0.113.50:51820');
    const joinLink = service.listLinks(network.id).find((link) =>
      link.upstreamId === edge.id && link.downstreamId === child.node.id);
    assert.equal(joinLink.downstreamEndpoint, '');

    const edgeConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', child.versionId, edge.id,
    ).config_json);
    const childConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', child.versionId, child.node.id,
    ).config_json);
    assert.equal(edgeConfig.data.peers.find((peer) => peer.nodeId === child.node.id).endpoint, null);
    assert.equal(edgeConfig.data.peers.find((peer) => peer.nodeId === child.node.id).endpointMode, 'dynamic-learn');
    assert.equal(childConfig.data.peers.find((peer) => peer.nodeId === edge.id).endpoint, '192.168.8.20:51820');
    assert.equal(childConfig.data.peers.find((peer) => peer.nodeId === edge.id).endpointMode, 'static-dial');

    const runtime = service.getClusterRuntime(network.id, edge.id);
    assert.equal(runtime.control.forwarders[child.node.id], internalControlUrl(child.node));

    database.run(
      'UPDATE topology_links SET downstream_endpoint = ? WHERE id = ?',
      '203.0.113.50:51820', joinLink.id,
    );
    database.migrate();
    assert.equal(service.listLinks(network.id).find((link) => link.id === joinLink.id).downstreamEndpoint, '');
    let versionId;
    database.transaction(() => {
      versionId = service.createVersionInTransaction(network.id, '修复主动加入 Endpoint 语义');
    });
    const regenerated = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', versionId, edge.id,
    ).config_json);
    assert.equal(regenerated.data.peers.find((peer) => peer.nodeId === child.node.id).endpoint, null);
    assert.equal(regenerated.data.peers.find((peer) => peer.nodeId === child.node.id).endpointMode, 'dynamic-learn');
  } finally { database.close(); }
});

test('可视化新增连接必须经两个节点准备和双向探测后激活', () => {
  const { database, service, network, center } = fixture();
  try {
    const nodeA = registerPublicEdge(service, network, center, {
      name: '节点 A', wgDataPublicKey: 'a'.repeat(44), dataEndpoint: '192.168.1.10:51820',
    }).node;
    const nodeB = registerPublicEdge(service, network, center, {
      name: '节点 B', wgDataPublicKey: 'b'.repeat(44), dataEndpoint: '10.10.0.20:51820',
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
    assert.match(probeA.payload.probeId, /^[0-9a-f-]{36}$/);
    assert.equal(probeA.payload.maxHops, 16);
    service.completeCommand(nodeA.id, probeA.id, { ok: true, remoteNodeId: nodeB.id });
    service.completeCommand(nodeB.id, probeB.id, { ok: true, remoteNodeId: nodeA.id });

    const active = service.listLinks(network.id).find((link) => link.id === candidate.id);
    assert.equal(active.validationStatus, 'active');
    assert.ok(active.validatedAt);
    assert.equal(service.getTopology(network.id).validation.fullyReachable, true);
    assert.equal(service.listConfigurations(network.id)[0].reason, '新增已验证的数据通路');
  } finally { database.close(); }
});

test('面板手动双公网建链必须两个方向都探测成功才激活', () => {
  const { database, service, network, center } = fixture();
  try {
    const nodeA = registerPublicEdge(service, network, center, {
      name: '双向节点 A',
      controlListenPort: 19001,
      dataListenPort: 21001,
      wgDataPublicKey: 'a'.repeat(44),
      dataEndpoint: '192.168.50.10:21001',
    }).node;
    const nodeB = registerPublicEdge(service, network, center, {
      name: '双向节点 B',
      controlListenPort: 19002,
      dataListenPort: 21002,
      wgDataPublicKey: 'b'.repeat(44),
      dataEndpoint: '10.20.30.40:21002',
    }).node;
    const candidate = service.createLinkValidation(network.id, {
      nodeAId: nodeA.id,
      nodeBId: nodeB.id,
      nodeAAddress: '192.168.50.10',
      nodeBAddress: '10.20.30.40',
    });
    for (const node of [nodeA, nodeB]) {
      const command = service.claimCommand(node.id);
      service.completeCommand(node.id, command.id, { ok: true });
    }
    const probeA = service.claimCommand(nodeA.id);
    const probeB = service.claimCommand(nodeB.id);
    service.completeCommand(nodeA.id, probeA.id, { ok: false, error: 'A 无法主动访问 B' });
    service.completeCommand(nodeB.id, probeB.id, { ok: true, remoteNodeId: nodeA.id });
    const failed = service.listLinks(network.id).find((link) => link.id === candidate.id);
    assert.equal(failed.validationStatus, 'failed');
    assert.equal(failed.validationProgress.requested, 2);
    assert.equal(failed.validationProgress.successful, 1);
  } finally { database.close(); }
});

test('单向手动建链只要一个方向成功即可激活', () => {
  const { database, service, network, center } = fixture();
  try {
    const privateNode = registerActiveJoinNode(service, network, center, {
      name: 'NAT 边缘',
      wgDataPublicKey: 'n'.repeat(44),
    }).node;
    const publicNode = registerPublicEdge(service, network, center, {
      name: '公网节点',
      controlListenPort: 19002,
      dataListenPort: 21002,
      wgDataPublicKey: 'b'.repeat(44),
      dataEndpoint: '10.20.30.40:21002',
    }).node;
    const candidate = service.createLinkValidation(network.id, {
      nodeAId: privateNode.id,
      nodeBId: publicNode.id,
      nodeBAddress: '10.20.30.40',
    });
    for (const node of [privateNode, publicNode]) {
      const command = service.claimCommand(node.id);
      service.completeCommand(node.id, command.id, { ok: true });
    }
    const probe = service.claimCommand(privateNode.id);
    assert.equal(probe.payload.remoteUrl, internalControlUrl(publicNode));
    service.completeCommand(privateNode.id, probe.id, { ok: true, remoteNodeId: publicNode.id });
    const active = service.listLinks(network.id).find((link) => link.id === candidate.id);
    assert.equal(active.validationStatus, 'active');
    assert.equal(active.downstreamEndpoint, '10.20.30.40:21002');
    assert.equal(active.upstreamEndpoint, '');
    const version = service.listConfigurations(network.id)[0];
    const natConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', version.id, privateNode.id,
    ).config_json);
    assert.equal(natConfig.data.peers.find((peer) => peer.nodeId === publicNode.id).endpointMode, 'static-dial');
  } finally { database.close(); }
});

test('只填写一个可达地址时仅探测该方向，成功后建立单向发起链路', () => {
  const { database, service, network, center } = fixture();
  try {
    const nodeA = registerPublicEdge(service, network, center, {
      name: '单地址节点 A',
      controlListenPort: 19101,
      dataListenPort: 21101,
      wgDataPublicKey: 'a'.repeat(44),
      dataEndpoint: '192.168.60.10:21101',
    }).node;
    const nodeB = registerPublicEdge(service, network, center, {
      name: '单地址节点 B',
      controlListenPort: 19102,
      dataListenPort: 21102,
      wgDataPublicKey: 'b'.repeat(44),
      dataEndpoint: '10.30.40.50:21102',
    }).node;

    const candidate = service.createLinkValidation(network.id, {
      nodeAId: nodeA.id,
      nodeBId: nodeB.id,
      nodeAAddress: '192.168.60.10',
    });
    assert.equal(candidate.validationProgress.requested, 1);
    assert.equal(candidate.upstreamEndpoint, '192.168.60.10:21101');
    assert.equal(candidate.downstreamEndpoint, null);

    for (const node of [nodeA, nodeB]) {
      const command = service.claimCommand(node.id);
      assert.equal(command.type, 'prepare-link-probe');
      service.completeCommand(node.id, command.id, { ok: true });
    }

    assert.equal(service.claimCommand(nodeA.id), null);
    const probeB = service.claimCommand(nodeB.id);
    assert.equal(probeB.type, 'execute-link-probe');
    assert.equal(probeB.payload.remoteUrl, internalControlUrl(nodeA));
    service.completeCommand(nodeB.id, probeB.id, { ok: true, remoteNodeId: nodeA.id });

    const active = service.listLinks(network.id).find((link) => link.id === candidate.id);
    assert.equal(active.validationStatus, 'active');
    assert.equal(active.validationProgress.requested, 1);
    assert.equal(active.upstreamEndpoint, '192.168.60.10:21101');
    assert.equal(active.downstreamEndpoint, '');
    assert.equal(active.probeDirections.upstreamToDownstream.status, 'not-requested');
    assert.equal(active.probeDirections.downstreamToUpstream.status, 'reachable');

    const version = service.listConfigurations(network.id)[0];
    const configA = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', version.id, nodeA.id,
    ).config_json);
    const configB = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', version.id, nodeB.id,
    ).config_json);
    assert.equal(configA.data.peers.find((peer) => peer.nodeId === nodeB.id).endpoint, null);
    assert.equal(configA.data.peers.find((peer) => peer.nodeId === nodeB.id).endpointMode, 'dynamic-learn');
    assert.equal(configA.data.peers.find((peer) => peer.nodeId === nodeB.id).persistentKeepalive, null);
    assert.equal(configB.data.peers.find((peer) => peer.nodeId === nodeA.id).endpoint, '192.168.60.10:21101');
    assert.equal(configB.data.peers.find((peer) => peer.nodeId === nodeA.id).endpointMode, 'static-dial');
  } finally { database.close(); }
});

test('单向 NAT 直连握手失败时基础拓扑自动回退，恢复后重新启用直连', () => {
  const { database, service, network, center } = fixture();
  try {
    const ix = registerActiveJoinNode(service, network, center, {
      name: '上海 IX',
      controlListenPort: 19201,
      dataListenPort: 21201,
      wgDataPublicKey: 'a'.repeat(44),
    }).node;
    const london = registerPublicEdge(service, network, center, {
      name: '伦敦节点',
      controlListenPort: 19202,
      dataListenPort: 21202,
      wgDataPublicKey: 'b'.repeat(44),
      dataEndpoint: '198.51.100.20:21202',
    }).node;
    const direct = service.createLinkValidation(network.id, {
      nodeAId: ix.id,
      nodeBId: london.id,
      nodeBAddress: '198.51.100.20',
      priority: 1,
    });
    for (const node of [ix, london]) {
      const prepare = service.claimCommand(node.id);
      service.completeCommand(node.id, prepare.id, { ok: true });
    }
    const probe = service.claimCommand(ix.id);
    assert.equal(probe.payload.remoteUrl, internalControlUrl(london));
    assert.equal(service.claimCommand(london.id), null);
    service.completeCommand(ix.id, probe.id, { ok: true, remoteNodeId: london.id });

    const activeVersion = service.listConfigurations(network.id)[0];
    const activeConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', activeVersion.id, ix.id,
    ).config_json);
    assert.equal(activeConfig.routes.find((route) => route.targetNodeId === london.id).viaNodeId, london.id);
    const activePeer = activeConfig.data.peers.find((peer) => peer.nodeId === london.id);
    assert.equal(activePeer.endpoint, '198.51.100.20:21202');
    assert.equal(activePeer.persistentKeepalive, 25);
    assert.equal(activePeer.probeIp, london.dataIp);

    const failed = service.heartbeat(ix.id, {
      linkHealth: { available: true, links: [{ linkId: direct.id, status: 'unreachable' }] },
    });
    assert.ok(failed.versionId);
    assert.match(service.getConfiguration(failed.versionId).reason, /基础拓扑自动绕开/);
    const fallbackConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', failed.versionId, ix.id,
    ).config_json);
    assert.equal(fallbackConfig.routes.find((route) => route.targetNodeId === london.id).viaNodeId, center.id);
    const healthProbePeer = fallbackConfig.data.peers.find((peer) => peer.nodeId === london.id);
    assert.equal(healthProbePeer.healthProbeOnly, true);
    assert.deepEqual(healthProbePeer.allowedIps, []);
    assert.equal(healthProbePeer.endpoint, '198.51.100.20:21202');
    assert.ok(fallbackConfig.data.links.some((link) => link.linkId === direct.id));

    const recovered = service.heartbeat(ix.id, {
      linkHealth: { available: true, links: [{ linkId: direct.id, status: 'reachable' }] },
    });
    assert.ok(recovered.versionId);
    assert.match(service.getConfiguration(recovered.versionId).reason, /重新启用链路/);
    const recoveredConfig = JSON.parse(database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', recovered.versionId, ix.id,
    ).config_json);
    assert.equal(recoveredConfig.routes.find((route) => route.targetNodeId === london.id).viaNodeId, london.id);
  } finally { database.close(); }
});

test('新节点端口由本机安装决定，注册后保存并用于配置和手动连接', () => {
  const { database, service, network, center } = fixture();
  try {
    const joinToken = service.createJoinToken(network.id, { parentId: center.id });
    assert.doesNotMatch(joinToken.command, /--data-port/);
    const nodeA = registerActiveJoinNode(service, network, center, {
      name: '端口节点 A',
      controlListenPort: 18991,
      dataListenPort: 19991,
      wgDataPublicKey: 'a'.repeat(44),
    }).node;
    const nodeB = registerPublicEdge(service, network, center, {
      name: '端口节点 B',
      dataListenPort: 19992,
      wgDataPublicKey: 'b'.repeat(44),
      dataEndpoint: '192.168.20.11:19992',
    }).node;

    assert.equal(nodeA.dataListenPort, 19991);
    assert.equal(nodeA.controlListenPort, 18991);
    const latest = service.listConfigurations(network.id)[0];
    const configRow = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', latest.id, nodeA.id,
    );
    assert.equal(JSON.parse(configRow.config_json).data.listenPort, 19991);

    const candidate = service.createLinkValidation(network.id, {
      nodeAId: nodeB.id,
      nodeBId: nodeA.id,
      nodeAAddress: '192.168.20.11',
      nodeAPort: 21002,
    });
    assert.equal(candidate.upstreamEndpoint, '192.168.20.11:21002');
    assert.equal(candidate.downstreamEndpoint, null);
  } finally { database.close(); }
});

test('选择父节点自动采用已保存的控制地址和端口，并允许仅为本次加入覆盖', () => {
  const { database, service, network, center } = fixture();
  try {
    const automatic = service.createJoinToken(network.id, { parentId: center.id });
    assert.deepEqual(automatic.parentConnection, {
      protocol: 'https', host: 'center.example', port: 443, url: 'https://center.example:443',
    });
    const override = service.createJoinToken(network.id, {
      parentId: center.id,
      parentProtocol: 'http',
      parentHost: '192.168.8.10',
      parentPort: 18090,
    });
    assert.equal(override.sourceUrl, 'http://192.168.8.10:18090');
    assert.match(override.command, /curl -fsSL 'http:\/\/192\.168\.8\.10:18090\/install\.sh'/);
    assert.match(override.command, /--source 'http:\/\/192\.168\.8\.10:18090'/);
    assert.match(override.command, /--upstream 'http:\/\/192\.168\.8\.10:18090'/);
  } finally { database.close(); }
});

test('业务网段只允许私有地址，预检重叠和容量后重新分配并发布', () => {
  const { database, service, network, center } = fixture();
  try {
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: token.token, name: '网段节点', wgDataPublicKey: 'a'.repeat(44) }).node;
    const preview = service.updateNetwork(network.id, { dataCidr: '172.20.10.0/24', dryRun: true });
    assert.equal(preview.preview, true);
    assert.equal(preview.after, '172.20.10.0/24');
    assert.deepEqual(preview.assignments.map((assignment) => assignment.after), ['172.20.10.1', '172.20.10.2']);
    assert.throws(() => service.updateNetwork(network.id, { dataCidr: '8.8.8.0/24', dryRun: true }), /私有地址范围/);
    assert.throws(() => service.updateNetwork(network.id, { dataCidr: network.controlCidr, dryRun: true }), /控制网段重叠/);

    const applied = service.updateNetwork(network.id, { dataCidr: '172.20.10.0/24' });
    assert.equal(applied.network.dataCidr, network.dataCidr);
    assert.equal(applied.pendingNetwork.dataCidr, '172.20.10.0/24');
    assert.equal(service.getNode(center.id).dataIp, center.dataIp);
    assert.equal(service.getNode(edge.id).dataIp, edge.dataIp);
    assert.equal(applied.version.status, 'preparing');
    service.reportConfig(edge.id, applied.version.id, 'prepared');
    assert.equal(service.getConfiguration(applied.version.id).status, 'activating');
    assert.equal(service.getNetwork(network.id).dataCidr, network.dataCidr);
    service.reportConfig(edge.id, applied.version.id, 'activated');
    assert.equal(service.getNetwork(network.id).dataCidr, '172.20.10.0/24');
    assert.equal(service.getNode(center.id).dataIp, '172.20.10.1');
    assert.equal(service.getNode(edge.id).dataIp, '172.20.10.2');
    assert.match(applied.version.reason, /业务网段调整/);
  } finally { database.close(); }
});

test('业务网段运行时预检失败时保留原网段和地址', () => {
  const { database, service, network, center } = fixture();
  try {
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: token.token, name: '冲突节点', wgDataPublicKey: 'b'.repeat(44) }).node;
    const staged = service.updateNetwork(network.id, { dataCidr: '172.21.0.0/24' });
    const failed = service.reportConfig(edge.id, staged.version.id, 'prepared', '业务网段已被本机路由使用');
    assert.equal(failed.status, 'failed');
    assert.equal(service.getNetwork(network.id).dataCidr, network.dataCidr);
    assert.equal(service.getNode(center.id).dataIp, center.dataIp);
    assert.equal(service.getNode(edge.id).dataIp, edge.dataIp);
    const change = database.get('SELECT status, error FROM network_cidr_changes WHERE version_id = ?', staged.version.id);
    assert.equal(change.status, 'failed');
    assert.equal(change.error, '业务网段已被本机路由使用');
  } finally { database.close(); }
});

test('离线节点不再永久阻塞业务网段切换，并在恢复后追赶 active 配置', () => {
  const { database, service, network, center } = fixture();
  try {
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({ token: token.token, name: '暂时离线节点', wgDataPublicKey: 'f'.repeat(44) }).node;
    const staged = service.updateNetwork(network.id, { dataCidr: '172.22.0.0/24' });
    assert.equal(staged.version.status, 'preparing');

    const afterDeadline = new Date(Date.parse(edge.lastSeen) + service.nodeOfflineAfterMs + 1);
    const result = service.reconcileRuntimeState(afterDeadline);
    assert.equal(result.offlineNodes, 1);
    assert.equal(result.advancedRollouts, 1);
    assert.equal(service.getConfiguration(staged.version.id).status, 'active');
    assert.equal(service.getNetwork(network.id).dataCidr, '172.22.0.0/24');
    assert.equal(service.getNode(center.id).dataIp, '172.22.0.1');
    assert.equal(service.getNode(edge.id).dataIp, '172.22.0.2');

    const edgeRollout = service.getConfiguration(staged.version.id).nodes.find((node) => node.nodeId === edge.id);
    assert.equal(edgeRollout.required, false);
    assert.equal(edgeRollout.phase, 'pending');
    const catchUp = service.getDesiredConfig(edge.id, 0);
    assert.equal(catchUp.phase, 'activate');
    assert.equal(catchUp.config.data.address, '172.22.0.2/32');
  } finally { database.close(); }
});

test('新增连接拒绝非法互访地址和重复节点对', () => {
  const { database, service, network, center } = fixture();
  try {
    const edge = registerPublicEdge(service, network, center, {
      name: '边缘', wgDataPublicKey: 'c'.repeat(44), dataEndpoint: '192.168.1.20:19801',
    }).node;
    const edge2 = registerPublicEdge(service, network, center, {
      name: '边缘 2', wgDataPublicKey: 'd'.repeat(44), dataEndpoint: '192.168.1.21:19801',
    }).node;
    assert.throws(() => service.createLinkValidation(network.id, {
      nodeAId: edge.id, nodeBId: edge2.id,
    }), /至少填写一个/);
    assert.throws(() => service.createLinkValidation(network.id, {
      nodeAId: edge.id, nodeBId: edge2.id, nodeAAddress: 'https://bad.example', nodeBAddress: '10.0.0.2',
    }), /不要包含协议/);
    assert.throws(() => service.createLinkValidation(network.id, {
      nodeAId: center.id, nodeBId: edge.id, nodeAAddress: '203.0.113.1', nodeBAddress: '10.0.0.2',
    }), /已经存在连接/);
  } finally { database.close(); }
});

test('无公网节点只主动拨号公网节点，两个无公网节点禁止直连', () => {
  const { database, service, network, center } = fixture();
  try {
    const privateA = registerActiveJoinNode(service, network, center, {
      name: 'NAT A', wgDataPublicKey: 'a'.repeat(44),
    }).node;
    const privateB = registerActiveJoinNode(service, network, center, {
      name: 'NAT B', wgDataPublicKey: 'b'.repeat(44),
    }).node;
    assert.equal(privateA.dataEndpoint, null);
    assert.throws(() => service.createLinkValidation(network.id, {
      nodeAId: privateA.id, nodeBId: privateB.id, nodeAAddress: '192.0.2.10',
    }), /只能和有公网入口的节点建立后续直连|两个都没有公网入口/);

    const publicNode = registerPublicEdge(service, network, center, {
      name: '公网节点',
      dataEndpoint: '198.51.100.8:21980',
      dataListenPort: 21980,
      wgDataPublicKey: 'c'.repeat(44),
    }).node;
    const candidate = service.createLinkValidation(network.id, {
      nodeAId: privateA.id, nodeBId: publicNode.id, nodeAAddress: '192.0.2.10',
    });
    assert.equal(candidate.upstreamEndpoint, null);
    assert.equal(candidate.downstreamEndpoint, '198.51.100.8:21980');
    assert.equal(candidate.validationProgress.requested, 1);
  } finally { database.close(); }
});

test('IX 节点可作主动加入父节点与主动认领，后续可连公网但不能连 NAT', () => {
  const { database, service, network, center } = fixture();
  try {
    const join = service.createJoinToken(network.id, { parentId: center.id });
    const ix = service.registerAgent({
      token: join.token,
      name: '上海 IX',
      reachabilityType: 'ix',
      controlEndpoint: 'http://10.20.0.8:8790',
      dataEndpoint: '10.20.0.8:19801',
      dataListenPort: 19801,
      wgDataPublicKey: 'i'.repeat(44),
    }).node;
    assert.equal(ix.reachabilityType, 'ix');
    assert.equal(ix.hasPublicEndpoint, true);
    assert.equal(ix.canRelay, true);
    assert.equal(ix.dataEndpoint, '10.20.0.8:19801');

    const childToken = service.createJoinToken(network.id, {
      parentId: ix.id,
      parentHost: '10.20.0.8',
      parentPort: 8790,
      parentDataHost: '10.20.0.8',
      parentDataPort: 19801,
    });
    assert.match(childToken.command, /10\.20\.0\.8:8790/);
    assert.equal(childToken.parentDataConnection.endpoint, '10.20.0.8:19801');

    const passive = service.createJoinToken(network.id, { parentId: ix.id, mode: 'passive' });
    assert.equal(passive.mode, 'passive');
    assert.match(passive.command, /--claim-token/);

    const publicNode = registerPublicEdge(service, network, center, {
      name: '公网对照',
      dataEndpoint: '198.51.100.20:19801',
      dataListenPort: 19801,
      wgDataPublicKey: 'p'.repeat(44),
    }).node;
    const ixToPublic = service.createLinkValidation(network.id, {
      nodeAId: ix.id, nodeBId: publicNode.id, nodeBAddress: '198.51.100.20',
    });
    assert.equal(ixToPublic.upstreamEndpoint, null);
    assert.equal(ixToPublic.downstreamEndpoint, '198.51.100.20:19801');

    const nat = registerActiveJoinNode(service, network, center, {
      name: '纯 NAT', wgDataPublicKey: 'n'.repeat(44),
    }).node;
    assert.throws(() => service.createLinkValidation(network.id, {
      nodeAId: ix.id, nodeBId: nat.id, nodeAAddress: '10.20.0.8',
    }), /只能和有公网入口的节点建立后续直连/);

    assert.ok(!service.clusterVoterIds(network.id).includes(ix.id), 'IX 上行按 NAT，不得进入协调选民');
    const runtime = service.getClusterRuntime(network.id, center.id);
    assert.equal(runtime.control.forwarders[ix.id], internalControlUrl(ix), '控制面应走 IX 内网业务地址');
  } finally { database.close(); }
});

test('全网更新选择首个可访问 GitHub 的节点并把同一摘要制品排队到全部设备', () => {
  const database = new Database(':memory:');
  const staged = [];
  const service = new ControlService(database, {
    publicUrl: 'https://center.example',
    stageLocalUpdate: (request) => staged.push(request),
  });
  try {
    const network = service.createNetwork({
      name: '更新网络', dataCidr: '10.90.0.0/24', controlCidr: '10.240.0.0/24', listenPort: 51820, mtu: 1380,
    });
    const center = service.listNodes(network.id)[0];
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({
      token: token.token, name: '可访问 GitHub 的节点', hasPublicEndpoint: false, wgDataPublicKey: 'd'.repeat(44),
    }).node;
    const rollout = service.createUpdateRollout(network.id, center.id);
    const probe = service.claimCommand(edge.id);
    assert.equal(probe.type, 'probe-update-source');
    const bundle = gzipSync(randomBytes(1024));
    service.completeCommand(edge.id, probe.id, {
      ok: true,
      installer: '#!/usr/bin/env bash\n# supports --bundle-file\n',
      bundleBase64: bundle.toString('base64'),
    });
    const distributing = service.getUpdateRollout(rollout.id);
    assert.equal(distributing.status, 'distributing');
    assert.equal(distributing.source.id, edge.id);
    assert.equal(staged.length, 0, '协调节点必须等待更新制品先送达其他在线节点');
    const storedCommand = database.get(
      "SELECT payload_json FROM commands WHERE node_id = ? AND type = 'install-update-bundle'", edge.id,
    );
    assert.equal(Object.hasOwn(JSON.parse(storedCommand.payload_json), 'bundleBase64'), false, '数据库命令不得为每台节点重复保存更新包');
    const install = service.claimCommand(edge.id);
    assert.equal(install.type, 'install-update-bundle');
    assert.equal(install.payload.bundleSha256, distributing.bundleSha256);
    assert.equal(Object.hasOwn(install.payload, 'bundleBase64'), false, '命令领取不得附带整包制品');
    const artifact = service.getUpdateArtifactForAgent(edge.id, rollout.id);
    assert.equal(artifact.bundleSha256, distributing.bundleSha256);
    assert.ok(artifact.bundleBase64);
    service.completeCommand(edge.id, install.id, { ok: true, scheduled: true });
    assert.equal(staged.length, 1);
    assert.equal(staged[0].bundleSha256, distributing.bundleSha256);
    service.recordUpdateApplied(edge.id, rollout.id);
    service.recordUpdateApplied(center.id, rollout.id);
    assert.equal(service.getUpdateRollout(rollout.id).status, 'completed');
  } finally { database.close(); }
});

test('相邻链路延迟探测按目标准备、源节点执行，并汇总到端到端通路', () => {
  const { database, service, network, center } = fixture();
  try {
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({
      token: token.token, name: '延迟边缘', hasPublicEndpoint: false, wgDataPublicKey: 'm'.repeat(44),
    }).node;
    const started = service.createLinkBenchmarks(network.id);
    assert.deepEqual(started.summary, { total: 1, completed: 0, running: 1, failed: 0 });
    const prepare = service.claimCommand(center.id);
    assert.equal(prepare.type, 'prepare-link-benchmark');
    service.completeCommand(center.id, prepare.id, { ok: true, prepared: true });
    const execute = service.claimCommand(edge.id);
    assert.equal(execute.type, 'execute-link-benchmark');
    assert.equal(execute.payload.expectedNodeId, center.id);
    service.completeCommand(edge.id, execute.id, {
      ok: true, latencyMs: 18.25, latencyMinMs: 15.1, latencyP95Ms: 24.2,
      measuredAt: '2026-07-20T08:00:00.000Z',
    });
    const summary = service.getBenchmarkSummary(network.id);
    assert.deepEqual(summary.summary, { total: 1, completed: 1, running: 0, failed: 0 });
    assert.equal(summary.links[0].benchmark.latencyMs, 18.25);
    assert.equal(summary.links[0].benchmark.bandwidthMbps, undefined);
    const paths = service.getPathOptions(network.id, center.id, edge.id);
    assert.equal(paths.paths[0].benchmark.status, 'completed');
    assert.equal(paths.paths[0].benchmark.latencyMs, 18.25);
    assert.equal(paths.paths[0].benchmark.bandwidthMbps, undefined);
  } finally { database.close(); }
});

test('离线节点延期更新不再卡住全网任务，恢复后继续使用同一缓存制品', () => {
  const database = new Database(':memory:');
  const staged = [];
  const service = new ControlService(database, {
    publicUrl: 'https://center.example', stageLocalUpdate: (request) => staged.push(request),
  });
  try {
    const network = service.createNetwork({
      name: '延期更新', dataCidr: '10.92.0.0/24', controlCidr: '10.242.0.0/24', listenPort: 51820, mtu: 1380,
    });
    const center = service.listNodes(network.id)[0];
    const onlineToken = service.createJoinToken(network.id, { parentId: center.id });
    const online = service.registerAgent({
      token: onlineToken.token, name: '在线更新节点', hasPublicEndpoint: false, wgDataPublicKey: 'o'.repeat(44),
    }).node;
    const offlineToken = service.createJoinToken(network.id, { parentId: center.id });
    const offline = service.registerAgent({
      token: offlineToken.token, name: '离线更新节点', hasPublicEndpoint: false, wgDataPublicKey: 'f'.repeat(44),
    }).node;
    database.run("UPDATE nodes SET status = 'offline' WHERE id = ?", offline.id);
    const rollout = service.createUpdateRollout(network.id, center.id);
    const probe = service.claimCommand(online.id);
    const bundle = gzipSync(randomBytes(1024));
    service.completeCommand(online.id, probe.id, {
      ok: true, installer: '#!/usr/bin/env bash\n# supports --bundle-file\n', bundleBase64: bundle.toString('base64'),
    });
    const installOnline = service.claimCommand(online.id);
    service.completeCommand(online.id, installOnline.id, { ok: true, scheduled: true });
    assert.equal(staged.length, 1, '在线节点取得制品后才允许协调节点更新');
    service.recordUpdateApplied(online.id, rollout.id);
    service.recordUpdateApplied(center.id, rollout.id);
    const partial = service.getUpdateRollout(rollout.id);
    assert.equal(partial.status, 'partial');
    assert.equal(partial.nodes.find((node) => node.nodeId === offline.id).status, 'deferred');
    service.heartbeat(offline.id, {});
    const installOffline = service.claimCommand(offline.id);
    assert.equal(installOffline.type, 'install-update-bundle');
    assert.equal(installOffline.payload.bundleSha256, partial.bundleSha256);
    service.completeCommand(offline.id, installOffline.id, { ok: true, scheduled: true });
    service.recordUpdateApplied(offline.id, rollout.id);
    assert.equal(service.getUpdateRollout(rollout.id).status, 'completed');
  } finally { database.close(); }
});

test('领取更新制品后离线的节点会被延期，不再卡住协调节点本机更新', () => {
  const database = new Database(':memory:');
  const staged = [];
  const service = new ControlService(database, {
    publicUrl: 'https://center.example', stageLocalUpdate: (request) => staged.push(request),
  });
  try {
    const network = service.createNetwork({
      name: '卡住恢复', dataCidr: '10.93.0.0/24', controlCidr: '10.243.0.0/24', listenPort: 51820, mtu: 1380,
    });
    const center = service.listNodes(network.id)[0];
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({
      token: token.token, name: '中途离线节点', hasPublicEndpoint: false, wgDataPublicKey: 'z'.repeat(44),
    }).node;
    const rollout = service.createUpdateRollout(network.id, center.id);
    const probe = service.claimCommand(edge.id);
    const bundle = gzipSync(randomBytes(1024));
    service.completeCommand(edge.id, probe.id, {
      ok: true, installer: '#!/usr/bin/env bash\n# supports --bundle-file\n', bundleBase64: bundle.toString('base64'),
    });
    const install = service.claimCommand(edge.id);
    assert.equal(install.type, 'install-update-bundle');
    database.run("UPDATE nodes SET status = 'offline' WHERE id = ?", edge.id);
    service.recoverUpdateRollouts();
    const recovered = service.getUpdateRollout(rollout.id);
    assert.equal(recovered.nodes.find((node) => node.nodeId === edge.id).status, 'deferred');
    assert.equal(staged.length, 1, '远端安装卡住并离线后应允许协调节点继续本机更新');
  } finally { database.close(); }
});

test('Agent 在领取命令后重启时，过期运行租约会自动回队而不是永久卡住', () => {
  const { database, service, network, center } = fixture();
  try {
    const token = service.createJoinToken(network.id, { parentId: center.id });
    const edge = service.registerAgent({
      token: token.token, name: '命令续跑节点', hasPublicEndpoint: false, wgDataPublicKey: 'r'.repeat(44),
    }).node;
    const queued = service.enqueueCommand(edge.id, 'probe', { reason: 'lease-test' });
    assert.equal(service.claimCommand(edge.id).id, queued.id);
    database.run("UPDATE commands SET claimed_at = '2000-01-01T00:00:00.000Z' WHERE id = ?", queued.id);
    const retried = service.claimCommand(edge.id);
    assert.equal(retried.id, queued.id);
    assert.equal(retried.type, 'probe');
  } finally { database.close(); }
});

test('连接验证超过有效期后自动失败并取消节点命令', () => {
  const { database, service, network, center } = fixture();
  try {
    const nodeA = registerPublicEdge(service, network, center, {
      name: '超时节点 A', wgDataPublicKey: 'a'.repeat(44), dataEndpoint: '192.168.1.20:19801',
    }).node;
    const nodeB = registerPublicEdge(service, network, center, {
      name: '超时节点 B', wgDataPublicKey: 'b'.repeat(44), dataEndpoint: '192.168.1.21:19801',
    }).node;
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
    const nodeA = registerPublicEdge(service, network, center, {
      name: '多路径 A', wgDataPublicKey: 'a'.repeat(44), dataEndpoint: '192.168.10.10:19801',
    }).node;
    const nodeB = registerPublicEdge(service, network, center, {
      name: '多路径 B', wgDataPublicKey: 'b'.repeat(44), dataEndpoint: '192.168.10.11:19801',
    }).node;
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
    assert.deepEqual(config.multipathPolicies[0].routeCidrs, [`${nodeB.dataIp}/32`]);
    assert.ok(config.multipathPolicies[0].paths.every((path) => path.localTunnelIp && path.remoteTunnelIp));
    assert.deepEqual(config.multipathPolicies[0].paths.map((path) => path.share), [0.75, 0.25]);

    const relayedPath = config.multipathPolicies[0].paths.find((path) => path.nodeIds.includes(center.id));
    const centerRow = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', saved.version.id, center.id,
    );
    const centerConfig = JSON.parse(centerRow.config_json);
    const aliasesAtCenter = centerConfig.data.peers.flatMap((peer) => peer.allowedIps);
    assert.ok(aliasesAtCenter.includes(`${relayedPath.remoteTunnelIp}/32`));
    assert.ok(aliasesAtCenter.includes(`${relayedPath.localTunnelIp}/32`));

    const directPath = options.paths.find((path) => path.linkIds.includes(direct.id));
    assert.ok(directPath);
    const excluded = service.heartbeat(nodeA.id, {
      linkHealth: {
        available: true,
        links: [{ linkId: direct.id, status: 'unreachable' }],
      },
    });
    assert.ok(excluded.versionId);
    assert.match(service.getConfiguration(excluded.versionId).reason, /负载均衡成员/);
    const excludedRow = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', excluded.versionId, nodeA.id,
    );
    const excludedPolicy = JSON.parse(excludedRow.config_json).multipathPolicies[0];
    const excludedPath = excludedPolicy.paths.find((path) => path.pathId === directPath.id);
    const remainingPath = excludedPolicy.paths.find((path) => path.pathId !== directPath.id);
    assert.equal(excludedPath.available, false);
    assert.equal(excludedPath.effectiveWeight, 0);
    assert.equal(excludedPath.share, 0);
    assert.equal(remainingPath.available, true);
    assert.equal(remainingPath.share, 1);
    const unavailableDetails = service.getPathOptions(network.id, nodeA.id, nodeB.id);
    assert.equal(unavailableDetails.paths.find((path) => path.id === directPath.id).available, false);
    assert.equal(unavailableDetails.policy.paths.find((path) => path.pathId === directPath.id).effectiveWeight, 0);

    const unknown = service.heartbeat(nodeA.id, {
      linkHealth: {
        available: true,
        links: [{ linkId: direct.id, status: 'unknown' }],
      },
    });
    assert.equal(unknown.versionId, null);
    assert.equal(service.getPathOptions(network.id, nodeA.id, nodeB.id)
      .paths.find((path) => path.id === directPath.id).available, false);

    const recovered = service.heartbeat(nodeA.id, {
      linkHealth: {
        available: true,
        links: [{ linkId: direct.id, status: 'reachable' }],
      },
    });
    assert.ok(recovered.versionId);
    const recoveredRow = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', recovered.versionId, nodeA.id,
    );
    const recoveredPolicy = JSON.parse(recoveredRow.config_json).multipathPolicies[0];
    assert.deepEqual(recoveredPolicy.paths.map((path) => path.weight), [3, 1]);
    assert.deepEqual(recoveredPolicy.paths.map((path) => path.effectiveWeight), [3, 1]);
    assert.deepEqual(recoveredPolicy.paths.map((path) => path.share), [0.75, 0.25]);
    assert.ok(recoveredPolicy.paths.every((path) => path.available));

    const failover = service.savePathPolicy(network.id, {
      sourceId: nodeA.id,
      targetId: nodeB.id,
      mode: 'failover',
      defaultPathId: options.paths[1].id,
    });
    assert.equal(failover.details.policy.mode, 'failover');
    assert.equal(failover.details.policy.defaultPathId, options.paths[1].id);
    assert.equal(failover.details.policy.paths.length, options.paths.length);
    const failoverRow = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', failover.version.id, nodeA.id,
    );
    const failoverConfig = JSON.parse(failoverRow.config_json);
    assert.equal(failoverConfig.multipathPolicies[0].selection, 'ordered-failover');
    assert.equal(failoverConfig.multipathPolicies[0].paths[0].isDefault, true);
    assert.equal(failoverConfig.routes.find((route) => route.targetNodeId === nodeB.id).viaNodeId, center.id);

    const storedFailover = service.listPathPolicies(network.id)[0];
    const incidentLinkIds = new Set(service.listLinks(network.id, true).filter((link) =>
      link.upstreamId === nodeA.id || link.downstreamId === nodeA.id).map((link) => link.id));
    const failedFirstHop = storedFailover.paths[0].linkIds.find((linkId) => incidentLinkIds.has(linkId));
    assert.ok(failedFirstHop);
    const switched = service.heartbeat(nodeA.id, {
      linkHealth: {
        available: true,
        links: [{ linkId: failedFirstHop, status: 'unreachable' }],
      },
    });
    assert.ok(switched.versionId);
    const rotated = service.getPathOptions(network.id, nodeA.id, nodeB.id);
    assert.equal(rotated.policy.defaultPathId, options.paths[0].id);
    assert.match(service.getConfiguration(switched.versionId).reason, /自动切换/);

    const removed = service.deletePathPolicy(network.id, nodeA.id, nodeB.id);
    assert.equal(removed.deleted, true);
    assert.equal(removed.details.policy, null);
  } finally { database.close(); }
});

test('删除节点前模拟剩余拓扑，失联时阻止删除，有替代链路时允许删除', () => {
  const { database, service, network, center } = fixture();
  try {
    const nodeA = registerPublicEdge(service, network, center, {
      name: '中继 A',
      controlEndpoint: 'http://192.168.60.10:18901',
      controlListenPort: 18901,
      dataEndpoint: '192.168.60.10:20901',
      dataListenPort: 20901,
      wgDataPublicKey: 'a'.repeat(44),
    }).node;
    const nodeB = registerActiveJoinNode(service, network, nodeA, {
      name: '下游 B',
      controlListenPort: 18902,
      dataListenPort: 20902,
      wgDataPublicKey: 'b'.repeat(44),
    }).node;

    const blocked = service.inspectNodeDeletion(nodeA.id);
    assert.equal(blocked.canDelete, false);
    assert.match(blocked.reason, /失联|不再全网可达/);
    assert.throws(() => service.deleteNode(nodeA.id), /失联|不再全网可达/);

    const replacement = service.createLinkValidation(network.id, {
      nodeAId: center.id,
      nodeBId: nodeB.id,
      nodeAAddress: '203.0.113.1',
    });
    for (const node of [center, nodeB]) {
      const prepare = service.claimCommand(node.id);
      if (prepare) service.completeCommand(node.id, prepare.id, { ok: true });
    }
    const probeB = service.claimCommand(nodeB.id);
    assert.ok(probeB);
    service.completeCommand(nodeB.id, probeB.id, { ok: true, remoteNodeId: center.id });
    assert.equal(service.claimCommand(center.id), null);
    assert.equal(service.listLinks(network.id).find((link) => link.id === replacement.id).validationStatus, 'active');
    const routeVersion = service.listConfigurations(network.id)[0];
    const routeRow = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', routeVersion.id, nodeB.id,
    );
    const control = JSON.parse(routeRow.config_json).control;
    assert.ok(control.routes.length >= 2);
    assert.ok(control.routes.every((route) => new Set(route.nodeIds).size === route.nodeIds.length));
    assert.ok(control.routes.every((route) => route.nodeIds.at(-1) === center.id && route.nodeIds.length <= 17));
    const safe = service.inspectNodeDeletion(nodeA.id);
    assert.equal(safe.canDelete, true);
    const deleted = service.deleteNode(nodeA.id);
    assert.equal(deleted.deleted, true);
    assert.throws(() => service.getNode(nodeA.id), /不存在/);
    assert.equal(service.getNode(nodeB.id).parentId, center.id);
    assert.equal(service.getTopology(network.id).validation.fullyReachable, true);
  } finally { database.close(); }
});
