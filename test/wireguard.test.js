import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildMultipathPlan, detectLocalNetworkConflicts, renderWireGuardConfig, WireGuardManager } from '../src/agent/wireguard.js';

test('渲染精确 AllowedIPs 的 WireGuard 数据配置', () => {
  const rendered = renderWireGuardConfig({
    address: '10.77.0.2/32', listenPort: 51820, mtu: 1380,
    peers: [{
      nodeId: 'parent', name: '上游', publicKey: 'a'.repeat(44), endpoint: '203.0.113.8:51820',
      allowedIps: ['10.77.0.1/32', '10.77.0.3/32'], persistentKeepalive: 25,
    }],
  }, 'b'.repeat(44));
  assert.match(rendered, /Address = 10\.77\.0\.2\/32/);
  assert.match(rendered, /Endpoint = 203\.0\.113\.8:51820/);
  assert.match(rendered, /AllowedIPs = 10\.77\.0\.1\/32, 10\.77\.0\.3\/32/);
  assert.doesNotMatch(rendered, /0\.0\.0\.0\/0/);
});

test('业务网段准备阶段检测本机接口和路由占用并忽略自身接口', () => {
  const conflicts = detectLocalNetworkConflicts('10.77.0.0/16', [
    { ifname: 'eth0', addr_info: [{ family: 'inet', local: '192.168.1.20', prefixlen: 24 }] },
    { ifname: 'pw-data', addr_info: [{ family: 'inet', local: '10.77.0.2', prefixlen: 32 }] },
  ], [
    { dst: '10.77.10.0/24', dev: 'eth1' },
    { dst: '10.77.0.3/32', dev: 'pw-data' },
  ]);
  assert.deepEqual(conflicts, [{ type: 'route', interface: 'eth1', cidr: '10.77.10.0/24' }]);
});

test('拒绝缺少公钥的 Peer 配置', () => {
  assert.throws(() => renderWireGuardConfig({
    address: '10.77.0.2/32', listenPort: 51820, mtu: 1380,
    peers: [{ nodeId: 'bad', publicKey: '', allowedIps: ['10.77.0.1/32'] }],
  }, 'b'.repeat(44)), /缺少 WireGuard 公钥/);
});

test('Agent 只接受带 PathWeaver 清单的私有 WireGuard 运行时', () => {
  const root = mkdtempSync(join(tmpdir(), 'pathweaver-wg-'));
  try {
    const runtimeDir = join(root, 'runtime');
    const binDir = join(runtimeDir, 'bin');
    mkdirSync(binDir, { recursive: true });
    writeFileSync(join(runtimeDir, 'runtime.json'), JSON.stringify({
      schemaVersion: 1,
      toolsVersion: 'test-version',
      managedBy: 'pathweaver',
    }));
    for (const name of ['wg', 'wg-quick']) {
      const filename = join(binDir, name);
      writeFileSync(filename, '#!/bin/sh\nexit 0\n');
      chmodSync(filename, 0o755);
    }
    const manager = new WireGuardManager({
      dataDir: join(root, 'data'),
      privateKey: 'b'.repeat(44),
      applyNetwork: false,
      runtimeDir,
    });
    assert.equal(manager.assertPrivateRuntime().toolsVersion, 'test-version');
    assert.equal(manager.wireguardDir, join(root, 'data', 'wireguard'));
    assert.equal(manager.commandEnvironment.PATHWEAVER_WG_QUICK_NO_AUTO_SU, '1');

    writeFileSync(join(runtimeDir, 'runtime.json'), JSON.stringify({ managedBy: 'system' }));
    assert.throws(() => manager.assertPrivateRuntime(), /私有 WireGuard 运行时缺失或清单无效/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('WireGuard 链路健康探测按 20 秒复用结果', async () => {
  const root = mkdtempSync(join(tmpdir(), 'pathweaver-health-'));
  try {
    const manager = new WireGuardManager({
      dataDir: root,
      privateKey: 'b'.repeat(44),
      applyNetwork: false,
    });
    assert.equal(manager.linkHealthProbeIntervalMs, 20_000);
    const first = await manager.linkHealth();
    const cached = await manager.linkHealth();
    assert.strictEqual(cached, first);

    manager.linkHealthCheckedAt -= 20_000;
    const refreshed = await manager.linkHealth();
    assert.notStrictEqual(refreshed, first);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('加权多路径策略编译为独立 IPIP 隧道和 Linux ECMP 路由', () => {
  const plan = buildMultipathPlan({
    data: { interfaceName: 'pw-data', mtu: 1380 },
    multipathPolicies: [{
      policyId: 'policy-a', targetNodeId: 'node-b', mode: 'weighted', routeCidrs: ['10.77.0.4/32', '10.77.0.8/32'],
      paths: [
        { pathId: 'path-1', available: true, effectiveWeight: 1000, localTunnelIp: '10.254.0.20', remoteTunnelIp: '10.254.0.21' },
        { pathId: 'path-2', available: true, effectiveWeight: 250, localTunnelIp: '10.254.0.22', remoteTunnelIp: '10.254.0.23' },
        { pathId: 'path-3', available: false, effectiveWeight: 0, localTunnelIp: '10.254.0.24', remoteTunnelIp: '10.254.0.25' },
      ],
    }],
  });
  assert.equal(plan.tunnels.length, 2);
  assert.deepEqual(plan.tunnels.map((tunnel) => tunnel.weight), [256, 64]);
  assert.equal(plan.routes.length, 2);
  assert.ok(plan.routes.every((route) => route.members.length === 2));
  assert.equal(new Set(plan.tunnels.map((tunnel) => tunnel.name)).size, 2);
  assert.ok(plan.tunnels.every((tunnel) => tunnel.name.length <= 15 && tunnel.mtu === 1360));
});

test('Linux 激活器实际创建路径隧道并安装加权 nexthop', async () => {
  const root = mkdtempSync(join(tmpdir(), 'pathweaver-ecmp-'));
  try {
    const manager = new WireGuardManager({ dataDir: root, privateKey: 'b'.repeat(44), applyNetwork: true });
    const calls = [];
    manager.runSystem = async (command, args) => { calls.push([command, ...args]); return { stdout: '', stderr: '' }; };
    manager.runIp = async (args) => { calls.push(['ip', ...args]); return { stdout: '', stderr: '' }; };
    const plan = await manager.applyMultipathPlan({
      data: { interfaceName: 'pw-data', mtu: 1380 },
      multipathPolicies: [{
        policyId: 'policy-live', targetNodeId: 'node-z', mode: 'weighted', routeCidrs: ['10.77.0.9/32'],
        paths: [
          { pathId: 'one', available: true, effectiveWeight: 3, localTunnelIp: '10.254.0.30', remoteTunnelIp: '10.254.0.31' },
          { pathId: 'two', available: true, effectiveWeight: 1, localTunnelIp: '10.254.0.32', remoteTunnelIp: '10.254.0.33' },
        ],
      }],
    });
    assert.equal(plan.tunnels.length, 2);
    assert.equal(calls.some((call) => call[0] === 'sysctl'), false);
    assert.equal(calls.filter((call) => call[0] === 'ip' && call[1] === 'tunnel' && call[2] === 'add').length, 2);
    const route = calls.find((call) => call[0] === 'ip' && call[1] === 'route' && call[2] === 'replace');
    assert.ok(route);
    assert.equal(route.filter((part) => part === 'nexthop').length, 2);
    assert.deepEqual(route.filter((part, index) => route[index - 1] === 'weight'), ['3', '1']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
