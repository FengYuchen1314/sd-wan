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

test('双向探测只要一个方向成功即可建链，并使用数据库中的控制端口', () => {
  const { database, service, network, center } = fixture();
  try {
    const tokenA = service.createJoinToken(network.id, { parentId: center.id });
    const nodeA = service.registerAgent({
      token: tokenA.token,
      name: '单向节点 A',
      controlListenPort: 19001,
      dataListenPort: 21001,
      wgDataPublicKey: 'a'.repeat(44),
      dataEndpoint: '192.168.50.10:21001',
    }).node;
    const tokenB = service.createJoinToken(network.id, { parentId: center.id });
    const nodeB = service.registerAgent({
      token: tokenB.token,
      name: '单向节点 B',
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
    assert.equal(probeA.payload.remoteUrl, 'http://10.20.30.40:19002');
    assert.equal(probeB.payload.remoteUrl, 'http://192.168.50.10:19001');
    service.completeCommand(nodeA.id, probeA.id, { ok: false, error: 'A 无法主动访问 B' });
    assert.equal(service.listLinks(network.id).find((link) => link.id === candidate.id).validationStatus, 'probing');
    service.completeCommand(nodeB.id, probeB.id, { ok: true, remoteNodeId: nodeA.id });
    const active = service.listLinks(network.id).find((link) => link.id === candidate.id);
    assert.equal(active.validationStatus, 'active');
    assert.equal(active.validationProgress.successful, 1);
    assert.equal(active.validationProgress.failed, 1);
    assert.equal(active.probeDirections.upstreamToDownstream.status, 'unreachable');
    assert.equal(active.probeDirections.downstreamToUpstream.status, 'reachable');
  } finally { database.close(); }
});

test('新节点端口由本机安装决定，注册后保存并用于配置和手动连接', () => {
  const { database, service, network, center } = fixture();
  try {
    const tokenA = service.createJoinToken(network.id, { parentId: center.id });
    assert.doesNotMatch(tokenA.command, /--data-port/);
    const nodeA = service.registerAgent({
      token: tokenA.token,
      name: '端口节点 A',
      controlListenPort: 18991,
      dataListenPort: 19991,
      wgDataPublicKey: 'a'.repeat(44),
      dataEndpoint: '192.168.20.10:19991',
    }).node;
    const tokenB = service.createJoinToken(network.id, { parentId: center.id });
    assert.doesNotMatch(tokenB.command, /--data-port/);
    const nodeB = service.registerAgent({
      token: tokenB.token,
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
      nodeAId: nodeA.id,
      nodeBId: nodeB.id,
      nodeAAddress: '192.168.20.10',
      nodeBAddress: '192.168.20.11',
      nodeAPort: 21001,
      nodeBPort: 21002,
    });
    assert.equal(candidate.upstreamEndpoint, '192.168.20.10:21001');
    assert.equal(candidate.downstreamEndpoint, '192.168.20.11:21002');
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
    const tokenA = service.createJoinToken(network.id, { parentId: center.id });
    const nodeA = service.registerAgent({
      token: tokenA.token,
      name: '中继 A',
      controlEndpoint: 'http://192.168.60.10:18901',
      controlListenPort: 18901,
      dataEndpoint: '192.168.60.10:20901',
      dataListenPort: 20901,
      wgDataPublicKey: 'a'.repeat(44),
    }).node;
    const tokenB = service.createJoinToken(network.id, { parentId: nodeA.id });
    const nodeB = service.registerAgent({
      token: tokenB.token,
      name: '下游 B',
      controlEndpoint: 'http://192.168.60.11:18902',
      controlListenPort: 18902,
      dataEndpoint: '192.168.60.11:20902',
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
      nodeBAddress: '192.168.60.11',
    });
    for (const node of [center, nodeB]) {
      const prepare = service.claimCommand(node.id);
      service.completeCommand(node.id, prepare.id, { ok: true });
    }
    for (const node of [center, nodeB]) {
      const probe = service.claimCommand(node.id);
      service.completeCommand(node.id, probe.id, { ok: true });
    }
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
