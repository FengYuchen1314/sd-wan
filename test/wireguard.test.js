import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { detectLocalNetworkConflicts, renderWireGuardConfig, WireGuardManager } from '../src/agent/wireguard.js';

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
