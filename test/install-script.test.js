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
  assert.match(readme, /curl -fsSL "https:\/\/raw\.githubusercontent\.com\/FengYuchen1314\/sd-wan\/main\/scripts\/install\.sh\?cache=\$\(date \+%s\)" \| sudo bash -s -- --source https:\/\/raw\.githubusercontent\.com\/FengYuchen1314\/sd-wan\/main/);
  assert.match(installer, /ensure_node_runtime/);
  assert.match(installer, /archive\/refs\/heads\/main\.tar\.gz\?cache=\$\(date \+%s\)/);
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
  assert.doesNotMatch(installer, /local[^\n]*candidate="\$supplied"/);
  assert.match(installer, /local label="\$1" start="\$2" supplied="\$3" reserved="\$4" selected candidate\n\s+candidate="\$supplied"/);
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

test('已安装节点支持无交互原地更新，并在服务异常时自动回滚', () => {
  assert.match(installer, /--update\) UPDATE_ONLY=1/);
  assert.match(installer, /if \[\[ "\$UPDATE_ONLY" -eq 1 \]\]; then\s+update_node/);
  assert.match(installer, /previous_release="\$\(readlink -f \/opt\/pathweaver\/current/);
  assert.match(installer, /systemctl restart "\$\{services\[@\]\}"/);
  assert.match(installer, /ln -sfn "\$previous_release" \/opt\/pathweaver\/current/);
  assert.match(installer, /services_healthy/);
  assert.match(installer, /patch_private_wireguard_runtime/);
  assert.match(installer, /PATHWEAVER_WG_QUICK_NO_AUTO_SU/);
  assert.match(installer, /\^\[\[:space:\]\]\*auto_su\[\[:space:\]\]\*\$/);
  assert.match(installer, /s\/auto_su\/\[\[ "\$\{PATHWEAVER_WG_QUICK_NO_AUTO_SU:-0\}" == "1" \]\] \|\| auto_su/);
  assert.match(readme, /--source https:\/\/raw\.githubusercontent\.com\/FengYuchen1314\/sd-wan\/main --update/);
  assert.match(readme, /数据库、节点密钥、面板端口、WireGuard 端口与当前网络配置/);
});

test('被认领节点安装结束时分别输出可复制的地址和控制端口', () => {
  assert.match(installer, /待认领节点 IP 或域名：\$REACHABLE_HOST/);
  assert.match(installer, /待认领节点控制端口：\$RELAY_PORT/);
  assert.doesNotMatch(installer, /填写待认领地址：http:\/\/\$endpoint_host:\$RELAY_PORT/);
});
