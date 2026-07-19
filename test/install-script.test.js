import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const installer = readFileSync(new URL('../scripts/install.sh', import.meta.url), 'utf8');
const uninstaller = readFileSync(new URL('../scripts/uninstall.sh', import.meta.url), 'utf8');
const bundleSource = readFileSync(new URL('../src/center/center-bundle.js', import.meta.url), 'utf8');
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

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
  assert.match(installer, /choose_distinct_tcp_port "节点控制中继 TCP 端口" 8790/);
  assert.match(installer, /net\.ipv4\.ip_forward=1/);
  assert.match(installer, /net\.ipv4\.conf\.all\.rp_filter=2/);
  assert.match(installer, /choose_port "WireGuard UDP 端口" udp 19801/);
  assert.match(installer, /choose_panel_password/);
  assert.match(installer, /read -r -s first/);
  assert.match(installer, /SDWAN_PANEL_PASSWORD_HASH=/);
  assert.match(installer, /src\/peer\/server\.js/);
  assert.match(installer, /pathweaver-node\.service/);
});

test('初始节点一键命令使用固定 GitHub 源，安装器自动补齐 Node.js 运行时', () => {
  assert.match(readme, /curl -fsSL https:\/\/raw\.githubusercontent\.com\/FengYuchen1314\/sd-wan\/main\/scripts\/install\.sh \| sudo bash -s -- --source https:\/\/raw\.githubusercontent\.com\/FengYuchen1314\/sd-wan\/main/);
  assert.match(installer, /ensure_node_runtime/);
  assert.match(installer, /https:\/\/nodejs\.org\/dist\/latest-v22\.x/);
  assert.match(installer, /node_runtime_supported/);
  assert.match(installer, /major === 22 && minor >= 5/);
  assert.match(installer, /sha256sum -c/);
  assert.match(installer, /node-v\[0-9\]/);
  assert.doesNotMatch(installer, /Install it before running this command/);
  assert.doesNotMatch(readme, /请先安装 Node\.js/);
  assert.match(installer, /command -v systemctl/);
  assert.match(installer, /EUID/);
  assert.match(installer, /choose_distinct_tcp_port "节点控制中继 TCP 端口" 8790 "\$RELAY_PORT" "\$PANEL_PORT"/);
});

test('安装时写入完全离线的本机卸载器，并区分保留数据与永久清除', () => {
  assert.match(installer, /install -m 0755 \/opt\/pathweaver\/current\/scripts\/uninstall\.sh \/usr\/local\/sbin\/pathweaver-uninstall/);
  assert.match(bundleSource, /scripts\/uninstall\.sh/);
  assert.match(installer, /sysctl\.previous/);
  assert.match(uninstaller, /systemctl disable --now pathweaver-agent\.service pathweaver-node\.service/);
  assert.match(uninstaller, /\/etc\/wireguard\/pw-data\.conf/);
  assert.match(uninstaller, /ip address del "\$local_ip\/32" dev lo/);
  assert.match(uninstaller, /if \[\[ "\$PURGE" -eq 1 \]\]/);
  assert.match(uninstaller, /rm -rf -- \/var\/lib\/pathweaver \/var\/lib\/pathweaver-agent/);
  assert.doesNotMatch(uninstaller, /curl|wget|github\.com/);
  assert.match(readme, /sudo pathweaver-uninstall/);
  assert.match(readme, /sudo pathweaver-uninstall --purge/);
});
