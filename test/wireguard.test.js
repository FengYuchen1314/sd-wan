import test from 'node:test';
import assert from 'node:assert/strict';
import { renderWireGuardConfig } from '../src/agent/wireguard.js';

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

test('拒绝缺少公钥的 Peer 配置', () => {
  assert.throws(() => renderWireGuardConfig({
    address: '10.77.0.2/32', listenPort: 51820, mtu: 1380,
    peers: [{ nodeId: 'bad', publicKey: '', allowedIps: ['10.77.0.1/32'] }],
  }, 'b'.repeat(44)), /缺少 WireGuard 公钥/);
});
