import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const installer = readFileSync(new URL('../scripts/install.sh', import.meta.url), 'utf8');

test('安装脚本无条件构建并启用 PathWeaver 私有 WireGuard 运行时', () => {
  assert.match(installer, /install_private_wireguard_runtime/);
  assert.match(installer, /artifacts\/wireguard\/wireguard-tools-/);
  assert.match(installer, /sha256sum -c/);
  assert.match(installer, /SDWAN_WIREGUARD_RUNTIME_DIR=/);
  assert.match(installer, /download_agent_source/);
  assert.match(installer, /SOURCE\/src\/agent/);
  assert.doesNotMatch(installer, /command -v wg(?:\s|$)/m);
});

test('统一对等节点安装不再要求选择中心或边缘，并为每台设备安装面板', () => {
  assert.doesNotMatch(installer, /choose_role/);
  assert.doesNotMatch(installer, /install_center|install_edge/);
  assert.match(installer, /install_node_bundle/);
  assert.match(installer, /install_node/);
  assert.match(installer, /choose_port "本机管理面板 TCP 端口" tcp 19773/);
  assert.match(installer, /choose_port "节点控制中继 TCP 端口" tcp 8790/);
  assert.match(installer, /choose_port "WireGuard UDP 端口" udp 19801/);
  assert.match(installer, /choose_panel_password/);
  assert.match(installer, /read -r -s first/);
  assert.match(installer, /SDWAN_PANEL_PASSWORD_HASH=/);
  assert.match(installer, /src\/peer\/server\.js/);
  assert.match(installer, /pathweaver-node\.service/);
});
