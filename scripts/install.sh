#!/usr/bin/env bash
set -euo pipefail

UPSTREAM=""
SOURCE="__PATHWEAVER_SOURCE__"
JOIN_TOKEN=""
CLAIM_TOKEN=""
PANEL_PORT=""
RELAY_PORT=""
DATA_PORT=""
REACHABLE_HOST=""
PUBLIC_ENDPOINT=""
REACHABILITY=""
PANEL_PASSWORD=""
UPDATE_ONLY=0
BUNDLE_FILE=""
WIREGUARD_TOOLS_VERSION="1.0.20260223"
WIREGUARD_TOOLS_SHA256="af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf"
WIREGUARD_RUNTIME_ROOT="/opt/pathweaver-agent/runtime"
WIREGUARD_RUNTIME_LINK="$WIREGUARD_RUNTIME_ROOT/wireguard-current"
NODE_DIST_BASE="${PATHWEAVER_NODE_DIST_BASE:-https://nodejs.org/dist/latest-v22.x}"
NODE_RUNTIME_ROOT="/opt/pathweaver/runtime"
NODE_RUNTIME_LINK="$NODE_RUNTIME_ROOT/node-current"
export PATH="$NODE_RUNTIME_LINK/bin:$PATH"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) shift 2 ;;
    --source) SOURCE="${2%/}"; shift 2 ;;
    --upstream) UPSTREAM="$2"; shift 2 ;;
    --join-token) JOIN_TOKEN="$2"; shift 2 ;;
    --claim-token) CLAIM_TOKEN="$2"; shift 2 ;;
    --panel-port) PANEL_PORT="$2"; shift 2 ;;
    --relay-port) RELAY_PORT="$2"; shift 2 ;;
    --data-port) DATA_PORT="$2"; shift 2 ;;
    --reachable-host) REACHABLE_HOST="$2"; shift 2 ;;
    --public-endpoint) PUBLIC_ENDPOINT="$2"; shift 2 ;;
    --reachability) REACHABILITY="$2"; shift 2 ;;
    --bundle-file) BUNDLE_FILE="$2"; shift 2 ;;
    --panel-password) PANEL_PASSWORD="$2"; shift 2 ;;
    --admin-token) PANEL_PASSWORD="$2"; shift 2 ;;
    --update) UPDATE_ONLY=1; shift ;;
    --listen) shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "请使用 root 运行，或通过 sudo 执行安装命令。" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "当前安装器要求使用 systemd 的 Linux 发行版。" >&2
  exit 1
fi
install_base_dependencies() {
  if command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1 &&
     command -v xz >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1; then return; fi
  echo "正在安装 PathWeaver 所需的基础工具……"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl tar xz-utils coreutils
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl tar xz coreutils
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl tar xz coreutils
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ca-certificates curl tar xz coreutils
  else
    echo "无法自动安装 curl、tar、xz 和 sha256sum：不支持当前 Linux 包管理器。" >&2
    exit 1
  fi
}

node_runtime_supported() {
  local executable="$1"
  [[ -x "$executable" ]] || return 1
  "$executable" -e '
const [major, minor] = process.versions.node.split(".").map(Number);
process.exit(major > 22 || (major === 22 && minor >= 5) ? 0 : 1);
' >/dev/null 2>&1
}

ensure_node_runtime() {
  if [[ -x "$NODE_RUNTIME_LINK/bin/node" ]] && node_runtime_supported "$NODE_RUNTIME_LINK/bin/node"; then
    echo "使用 PathWeaver 私有 Node.js：$($NODE_RUNTIME_LINK/bin/node --version) ($NODE_RUNTIME_LINK)"
    export PATH="$NODE_RUNTIME_LINK/bin:$PATH"
    hash -r
    return
  fi

  local current_node="" node_arch="" work_dir="" checksums="" archive_name="" expected_sha="" release_dir=""
  current_node="$(command -v node 2>/dev/null || true)"

  case "$(uname -m)" in
    x86_64|amd64) node_arch="x64" ;;
    aarch64|arm64) node_arch="arm64" ;;
    *) echo "无法自动安装 Node.js：暂不支持 CPU 架构 $(uname -m)，目前支持 x86_64 和 arm64。" >&2; exit 1 ;;
  esac

  if [[ -n "$current_node" ]]; then
    echo "检测到的 $($current_node --version 2>/dev/null || echo Node.js) 低于 22.5，正在安装 PathWeaver 私有运行时……"
  else
    echo "未检测到 Node.js，正在安装 PathWeaver 私有运行时……"
  fi
  work_dir="$(mktemp -d)"
  checksums="$work_dir/SHASUMS256.txt"
  curl --retry 3 --retry-delay 2 -fsSL "$NODE_DIST_BASE/SHASUMS256.txt" -o "$checksums"
  archive_name="$(awk '{print $2}' "$checksums" | grep -E "^node-v[0-9]+\.[0-9]+\.[0-9]+-linux-${node_arch}\.tar\.xz$" | head -n 1 || true)"
  if [[ -z "$archive_name" ]]; then
    rm -rf -- "$work_dir"
    echo "Node.js 下载清单中没有适用于 linux-$node_arch 的运行时。" >&2
    exit 1
  fi
  expected_sha="$(awk -v archive="$archive_name" '$2 == archive { print $1; exit }' "$checksums")"
  curl --retry 3 --retry-delay 2 -fsSL "$NODE_DIST_BASE/$archive_name" -o "$work_dir/$archive_name"
  echo "$expected_sha  $work_dir/$archive_name" | sha256sum -c -

  install -d -m 0755 "$NODE_RUNTIME_ROOT"
  release_dir="$NODE_RUNTIME_ROOT/${archive_name%.tar.xz}-$(date +%s)-$$"
  install -d -m 0755 "$release_dir"
  tar -xJf "$work_dir/$archive_name" -C "$release_dir" --strip-components=1
  if ! node_runtime_supported "$release_dir/bin/node"; then
    rm -rf -- "$release_dir" "$work_dir"
    echo "下载的 Node.js 运行时未通过最低版本检查。" >&2
    exit 1
  fi
  ln -sfn "$release_dir" "$NODE_RUNTIME_LINK"
  rm -rf -- "$work_dir"
  export PATH="$NODE_RUNTIME_LINK/bin:$PATH"
  hash -r
  echo "Node.js $($NODE_RUNTIME_LINK/bin/node --version) 已安装到 $NODE_RUNTIME_LINK。"
}

install_base_dependencies
ensure_node_runtime

TTY_DEVICE=""
if [[ -r /dev/tty && -w /dev/tty ]]; then TTY_DEVICE="/dev/tty"; fi

ask() {
  local prompt="$1" default_value="$2" answer=""
  if [[ -n "$TTY_DEVICE" ]]; then
    printf '%s [%s]: ' "$prompt" "$default_value" >"$TTY_DEVICE"
    IFS= read -r answer <"$TTY_DEVICE" || true
  fi
  printf '%s\n' "${answer:-$default_value}"
}

port_available() {
  node - "$1" "$2" <<'NODE'
const [kind, rawPort] = process.argv.slice(2);
const port = Number(rawPort);
if (!Number.isInteger(port) || port < 1 || port > 65535) process.exit(2);
const timeout = setTimeout(() => process.exit(2), 1500);
if (kind === 'udp') {
  const { createSocket } = require('node:dgram');
  const socket = createSocket('udp4');
  socket.once('error', (error) => process.exit(error.code === 'EADDRINUSE' || error.code === 'EACCES' ? 1 : 2));
  socket.once('listening', () => socket.close(() => { clearTimeout(timeout); process.exit(0); }));
  socket.bind({ port, address: '0.0.0.0', exclusive: true });
} else {
  const { createServer } = require('node:net');
  const server = createServer();
  server.once('error', (error) => process.exit(error.code === 'EADDRINUSE' || error.code === 'EACCES' ? 1 : 2));
  server.listen({ port, host: '0.0.0.0', exclusive: true }, () => server.close(() => { clearTimeout(timeout); process.exit(0); }));
}
NODE
}

find_available_port() {
  local kind="$1" port="$2"
  while [[ "$port" -le 65535 ]]; do
    if port_available "$kind" "$port"; then printf '%s\n' "$port"; return; fi
    port=$((port + 1))
  done
  echo "No available $kind port was found." >&2
  exit 1
}

choose_port() {
  local label="$1" kind="$2" start="$3" supplied="$4" suggested candidate
  suggested="$(find_available_port "$kind" "$start")"
  candidate="$supplied"
  while true; do
    if [[ -z "$candidate" ]]; then candidate="$(ask "$label，回车使用自动检测结果" "$suggested")"; fi
    if [[ ! "$candidate" =~ ^[0-9]+$ ]] || (( candidate < 1 || candidate > 65535 )); then
      echo "$label 必须是 1 到 65535 的整数，请重新输入。" >&2
    elif port_available "$kind" "$candidate"; then
      printf '%s\n' "$candidate"
      return
    else
      echo "$label $candidate 已被占用，请重新输入。" >&2
    fi
    if [[ -z "$TTY_DEVICE" ]]; then exit 2; fi
    candidate=""
  done
}

choose_distinct_tcp_port() {
  local label="$1" start="$2" supplied="$3" reserved="$4" selected candidate
  candidate="$supplied"
  if [[ "$start" == "$reserved" ]]; then start=$((start + 1)); fi
  while true; do
    selected="$(choose_port "$label" tcp "$start" "$candidate")"
    if [[ "$selected" != "$reserved" ]]; then printf '%s\n' "$selected"; return; fi
    echo "$label 不能与本机管理面板共用 TCP 端口 $reserved，请重新输入。" >&2
    if [[ -z "$TTY_DEVICE" ]]; then exit 2; fi
    candidate=""
  done
}

detect_reachable_host() {
  local detected
  detected="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  printf '%s\n' "${detected:-127.0.0.1}"
}

format_endpoint_host() {
  if [[ "$1" == *:* && "$1" != \[*\] ]]; then printf '[%s]' "$1"; else printf '%s' "$1"; fi
}

normalize_yes_no() {
  case "${1,,}" in
    y|yes|1|true|是|有) printf 'yes\n' ;;
    n|no|0|false|否|无|'') printf 'no\n' ;;
    *) return 1 ;;
  esac
}

normalize_reachability() {
  case "${1,,}" in
    public|y|yes|1|true|是|有|公网) printf 'public\n' ;;
    nat|n|no|0|false|否|无|纯nat) printf 'nat\n' ;;
    ix|交换|内网ix) printf 'ix\n' ;;
    *) return 1 ;;
  esac
}

choose_reachability() {
  local supplied="$1" answer=""
  while true; do
    answer="$supplied"
    if [[ -z "$answer" ]]; then
      answer="$(ask "本节点拨入类型：1=公网可拨入，2=纯 NAT（仅主动拨出），3=IX（填内网 IP，可接入新节点但不能后续建拓扑链路）" "2")"
    fi
    case "${answer,,}" in
      1) answer=public ;;
      2) answer=nat ;;
      3) answer=ix ;;
    esac
    if normalize_reachability "$answer"; then return; fi
    echo "请输入 1/public（公网）、2/nat（纯 NAT）或 3/ix（交换内网）。" >&2
    if [[ -z "$TTY_DEVICE" ]]; then exit 2; fi
    supplied=""
  done
}

install_wireguard_build_dependencies() {
  if command -v make >/dev/null 2>&1 && command -v cc >/dev/null 2>&1 &&
     command -v bash >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1 &&
     tar --help 2>&1 | grep -q -- '-J'; then return; fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential ca-certificates xz-utils iproute2
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc make bash ca-certificates coreutils xz iproute
  elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc make bash ca-certificates coreutils xz iproute
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache build-base bash ca-certificates coreutils xz iproute2
  else
    echo "Unsupported Linux distribution: cannot install the private WireGuard build dependencies." >&2
    exit 1
  fi
}

install_private_wireguard_runtime() {
  install_wireguard_build_dependencies
  local build_dir archive source_dir release_dir build_jobs
  build_dir="$(mktemp -d)"
  trap 'rm -rf -- "$build_dir"' RETURN
  archive="$build_dir/wireguard-tools.tar.xz"
  if ! curl -fsSL "$SOURCE/artifacts/wireguard/wireguard-tools-$WIREGUARD_TOOLS_VERSION.tar.xz" -o "$archive" 2>/dev/null; then
    rm -f -- "$archive"
    curl -fsSL "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-$WIREGUARD_TOOLS_VERSION.tar.xz" -o "$archive"
  fi
  echo "$WIREGUARD_TOOLS_SHA256  $archive" | sha256sum -c -
  tar -xJf "$archive" -C "$build_dir"
  source_dir="$(find "$build_dir" -mindepth 1 -maxdepth 1 -type d -name 'wireguard-tools-*' -print -quit)"
  if [[ -z "$source_dir" || ! -f "$source_dir/src/Makefile" ]]; then
    echo "The WireGuard tools source archive has an unexpected layout." >&2
    exit 1
  fi
  build_jobs="$(command -v nproc >/dev/null 2>&1 && nproc || echo 1)"
  make -C "$source_dir/src" -j"$build_jobs" wg
  install -d -m 0755 "$WIREGUARD_RUNTIME_ROOT"
  release_dir="$WIREGUARD_RUNTIME_ROOT/wireguard-$WIREGUARD_TOOLS_VERSION-$(date +%s)-$$"
  install -d -m 0755 "$release_dir/bin"
  install -m 0755 "$source_dir/src/wg" "$release_dir/bin/wg"
  install -m 0755 "$source_dir/src/wg-quick/linux.bash" "$release_dir/bin/wg-quick"
  if ! patch_private_wireguard_runtime "$release_dir/bin/wg-quick"; then
    rm -rf -- "$release_dir"
    exit 1
  fi
  cat >"$release_dir/runtime.json" <<EOF
{"schemaVersion":1,"toolsVersion":"$WIREGUARD_TOOLS_VERSION","installedAt":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","managedBy":"pathweaver"}
EOF
  "$release_dir/bin/wg" --version >/dev/null
  ln -sfn "$release_dir" "$WIREGUARD_RUNTIME_LINK"
  trap - RETURN
  rm -rf -- "$build_dir"
}

patch_private_wireguard_runtime() {
  local quick="${1:-$WIREGUARD_RUNTIME_LINK/bin/wg-quick}" call_count
  if [[ ! -f "$quick" ]]; then
    echo "PathWeaver 私有 wg-quick 不存在：$quick" >&2
    return 1
  fi
  if ! grep -q 'PATHWEAVER_WG_QUICK_NO_AUTO_SU' "$quick"; then
    call_count="$(grep -Ec '^[[:space:]]*auto_su[[:space:]]*$' "$quick" || true)"
    if [[ "$call_count" -lt 1 ]]; then
      echo "无法识别 PathWeaver 私有 wg-quick 的提权入口，拒绝修改。" >&2
      return 1
    fi
    sed -i '/^[[:space:]]*auto_su[[:space:]]*$/s/auto_su/[[ "${PATHWEAVER_WG_QUICK_NO_AUTO_SU:-0}" == "1" ]] || auto_su/' "$quick"
  fi
  if grep -Eq '^[[:space:]]*auto_su[[:space:]]*$' "$quick" ||
     ! grep -q 'PATHWEAVER_WG_QUICK_NO_AUTO_SU' "$quick"; then
    echo "PathWeaver 私有 wg-quick 提权入口修补后校验失败。" >&2
    return 1
  fi
  chmod 0755 "$quick"
}

download_agent_source() {
  local name="$1" destination="$2"
  if ! curl -fsSL "$SOURCE/artifacts/agent/$name" -o "$destination"; then
    rm -f -- "$destination"
    curl -fsSL "$SOURCE/src/agent/$name" -o "$destination"
  fi
}

choose_panel_password() {
  local first second
  if [[ -n "$PANEL_PASSWORD" ]]; then
    if (( ${#PANEL_PASSWORD} < 8 )); then echo "面板密码至少需要 8 个字符。" >&2; exit 2; fi
    return
  fi
  if [[ -z "$TTY_DEVICE" ]]; then
    echo "非交互安装必须通过 --panel-password 提供至少 8 个字符的面板密码。" >&2
    exit 2
  fi
  while true; do
    printf '请输入本机面板密码（至少 8 个字符）: ' >"$TTY_DEVICE"
    IFS= read -r -s first <"$TTY_DEVICE" || true
    printf '\n请再次输入面板密码: ' >"$TTY_DEVICE"
    IFS= read -r -s second <"$TTY_DEVICE" || true
    printf '\n' >"$TTY_DEVICE"
    if (( ${#first} < 8 )); then echo "面板密码至少需要 8 个字符，请重新输入。" >"$TTY_DEVICE"
    elif [[ "$first" != "$second" ]]; then echo "两次输入不一致，请重新输入。" >"$TTY_DEVICE"
    else PANEL_PASSWORD="$first"; return
    fi
  done
}

hash_panel_password() {
  local node_bin="$1"
  if [[ -z "$node_bin" || ! -x "$node_bin" ]]; then
    echo "未找到可用的 Node.js 运行时用于生成面板密码哈希。" >&2
    exit 1
  fi
  printf '%s' "$PANEL_PASSWORD" | "$node_bin" -e '
const { randomBytes, scryptSync } = require("node:crypto");
const chunks = [];
process.stdin.on("data", chunk => chunks.push(chunk));
process.stdin.on("end", () => {
  const password = Buffer.concat(chunks).toString("utf8");
  const salt = randomBytes(16);
  const digest = scryptSync(password, salt, 32);
  process.stdout.write(`scrypt-v1.${salt.toString("base64url")}.${digest.toString("base64url")}`);
});'
}

verify_panel_password_env() {
  local env_file="$1" node_bin="$2" password="$3"
  PANEL_PASSWORD="$password" PANEL_ENV_FILE="$env_file" "$node_bin" --input-type=module -e "
import { readFileSync } from 'node:fs';
import { verifyPanelPassword } from '/opt/pathweaver/current/src/core/password.js';
const match = readFileSync(process.env.PANEL_ENV_FILE, 'utf8').match(/^SDWAN_PANEL_PASSWORD_HASH=(.+)\$/m);
if (!match?.[1] || !verifyPanelPassword(process.env.PANEL_PASSWORD, match[1])) process.exit(1);
"
}

wait_for_panel_health() {
  local port="$1" attempt
  for attempt in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "面板服务未在 TCP ${port} 上响应。请检查：sudo systemctl status pathweaver-node；sudo journalctl -u pathweaver-node -n 50" >&2
  return 1
}

write_bootstrap_node_env() {
  local env_file="$1" password_hash="$2" endpoint="$3" panel_port="$4" data_port="$5"
  {
    printf 'SDWAN_PANEL_PASSWORD_HASH=%s\n' "$password_hash"
    printf 'SDWAN_PUBLIC_URL=http://%s:%s\n' "$endpoint" "$panel_port"
    printf 'SDWAN_DEFAULT_DATA_PORT=%s\n' "$data_port"
  } >"$env_file"
  chmod 0600 "$env_file"
}

write_peer_node_env() {
  local env_file="$1" password_hash="$2" proxy_token="$3"
  {
    printf 'SDWAN_PANEL_PASSWORD_HASH=%s\n' "$password_hash"
    printf 'SDWAN_PANEL_PROXY_TOKEN=%s\n' "$proxy_token"
  } >"$env_file"
  chmod 0600 "$env_file"
}

resolve_node_executable() {
  ensure_node_runtime
  if [[ -x "$NODE_RUNTIME_LINK/bin/node" ]] && node_runtime_supported "$NODE_RUNTIME_LINK/bin/node"; then
    printf '%s\n' "$NODE_RUNTIME_LINK/bin/node"
    return
  fi
  echo "PathWeaver 私有 Node.js 运行时不可用。" >&2
  exit 1
}

install_node_bundle() {
  local release bundle archive_root
  install -d -m 0755 /opt/pathweaver/releases
  release="/opt/pathweaver/releases/node-$(date +%s)-$$"
  install -d -m 0755 "$release"
  bundle="$(mktemp)"
  if [[ -n "$BUNDLE_FILE" ]]; then
    if [[ ! -r "$BUNDLE_FILE" ]]; then
      echo "指定的本地更新制品不可读：$BUNDLE_FILE" >&2
      exit 1
    fi
    cp -- "$BUNDLE_FILE" "$bundle"
    tar -tzf "$bundle" >/dev/null
    if tar -tzf "$bundle" | grep -qx 'package.json'; then
      tar -xzf "$bundle" -C "$release"
    else
      archive_root="$(tar -tzf "$bundle" | awk -F/ 'NR == 1 { root = $1 } END { print root }')"
      tar -xzf "$bundle" -C "$release" --strip-components=1 "$archive_root"
    fi
  elif curl -fsSL "$SOURCE/artifacts/center/pathweaver-center.tar.gz" -o "$bundle" 2>/dev/null; then
    tar -xzf "$bundle" -C "$release"
  else
    rm -f -- "$bundle"
    bundle="$(mktemp)"
    curl -fsSL "https://github.com/FengYuchen1314/sd-wan/archive/refs/heads/main.tar.gz?cache=$(date +%s)" -o "$bundle"
    archive_root="$(tar -tzf "$bundle" | awk -F/ 'NR == 1 { root = $1 } END { print root }')"
    tar -xzf "$bundle" -C "$release" --strip-components=1 "$archive_root"
  fi
  rm -f -- "$bundle"
  ln -sfn "$release" /opt/pathweaver/current
}

installed_services() {
  local service
  for service in pathweaver-agent.service pathweaver-node.service; do
    if [[ -f "/etc/systemd/system/$service" ]]; then printf '%s\n' "$service"; fi
  done
}

services_healthy() {
  local service
  for service in "$@"; do
    if ! systemctl is-active --quiet "$service"; then return 1; fi
  done
}

install_update_dispatcher() {
  if [[ ! -f /opt/pathweaver/current/scripts/apply-update-request.sh ]]; then
    echo "当前程序包缺少本机更新调度器。" >&2
    exit 1
  fi
  install -d -m 0755 /usr/local/libexec
  install -m 0755 /opt/pathweaver/current/scripts/apply-update-request.sh /usr/local/libexec/pathweaver-apply-update
  cat >/etc/systemd/system/pathweaver-update-apply.service <<'EOF'
[Unit]
Description=Apply a staged PathWeaver update
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/pathweaver-apply-update
EOF
  cat >/etc/systemd/system/pathweaver-update.path <<'EOF'
[Unit]
Description=Watch for PathWeaver control-plane update requests

[Path]
PathExists=/var/lib/pathweaver/update-request.json
PathChanged=/var/lib/pathweaver/update-request.json
PathModified=/var/lib/pathweaver/update-request.json
Unit=pathweaver-update-apply.service

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now pathweaver-update.path
  systemctl restart pathweaver-update.path || true
}

update_node() {
  local previous_release new_release
  local -a services=()
  previous_release="$(readlink -f /opt/pathweaver/current 2>/dev/null || true)"
  if [[ -z "$previous_release" || ! -d "$previous_release" || ! -f /etc/systemd/system/pathweaver-node.service ]]; then
    echo "未检测到完整的 PathWeaver 安装，请先执行初始节点或接入节点安装命令。" >&2
    exit 2
  fi
  mapfile -t services < <(installed_services)
  if [[ "${#services[@]}" -eq 0 ]]; then
    echo "未找到可更新的 PathWeaver systemd 服务。" >&2
    exit 2
  fi

  echo "正在下载并校验 PathWeaver 新版本……"
  install_node_bundle
  new_release="$(readlink -f /opt/pathweaver/current 2>/dev/null || true)"
  if [[ -z "$new_release" || ! -f "$new_release/package.json" ||
        ! -f "$new_release/scripts/install.sh" || ! -f "$new_release/scripts/update.sh" ||
        ! -f "$new_release/src/center/server.js" ]]; then
    ln -sfn "$previous_release" /opt/pathweaver/current
    echo "下载的版本不完整，已恢复旧版本，服务没有重启。" >&2
    exit 1
  fi
  install -m 0755 "$new_release/scripts/uninstall.sh" /usr/local/sbin/pathweaver-uninstall
  install -m 0755 "$new_release/scripts/update.sh" /usr/local/sbin/pathweaver-update
  install -m 0755 "$new_release/scripts/set-panel-password.sh" /usr/local/sbin/pathweaver-set-panel-password
  install_update_dispatcher
  if [[ -x "$WIREGUARD_RUNTIME_LINK/bin/wg-quick" ]]; then
    if ! patch_private_wireguard_runtime; then
      ln -sfn "$previous_release" /opt/pathweaver/current
      echo "私有 WireGuard 运行时修补失败，已恢复旧程序版本，服务没有重启。" >&2
      exit 1
    fi
  else
    echo "私有 WireGuard 运行时缺失，正在重新安装……"
    install_private_wireguard_runtime
  fi

  systemctl daemon-reload
  if ! systemctl restart "${services[@]}"; then
    ln -sfn "$previous_release" /opt/pathweaver/current
    systemctl daemon-reload
    systemctl restart "${services[@]}" || true
    echo "新版服务启动失败，已自动恢复旧版本。" >&2
    exit 1
  fi
  sleep 2
  if ! services_healthy "${services[@]}"; then
    ln -sfn "$previous_release" /opt/pathweaver/current
    systemctl daemon-reload
    systemctl restart "${services[@]}" || true
    echo "新版服务未保持运行，已自动恢复旧版本。" >&2
    exit 1
  fi

  echo "PathWeaver 已原地更新并重启。数据库、节点密钥、端口、密码和 WireGuard 配置均已保留。"
}

install_node() {
  local endpoint_host control_endpoint data_endpoint node_env panel_password_hash panel_proxy_token bootstrap reachability node_executable
  bootstrap=0
  if [[ -z "$JOIN_TOKEN" && -z "$CLAIM_TOKEN" && -z "$UPSTREAM" ]]; then bootstrap=1; fi
  if [[ "$bootstrap" -eq 0 && -z "$JOIN_TOKEN" && -z "$CLAIM_TOKEN" ]]; then
    echo "加入现有网络需要 --join-token 或 --claim-token。" >&2
    exit 2
  fi

  PANEL_PORT="$(choose_port "本机管理面板 TCP 端口" tcp 19773 "$PANEL_PORT")"
  if [[ "$bootstrap" -eq 1 || -n "$CLAIM_TOKEN" ]]; then
    reachability="public"
  else
    reachability="$(choose_reachability "${REACHABILITY:-$PUBLIC_ENDPOINT}")"
  fi
  if [[ "$bootstrap" -eq 0 ]]; then
    if [[ "$reachability" == "nat" ]]; then
      RELAY_PORT="${RELAY_PORT:-$(find_available_port tcp 8790)}"
    else
      RELAY_PORT="$(choose_distinct_tcp_port "节点控制中继 TCP 端口" 8790 "$RELAY_PORT" "$PANEL_PORT")"
    fi
  fi
  if [[ "$reachability" == "public" ]]; then
    DATA_PORT="$(choose_port "WireGuard UDP 公网监听端口" udp 19801 "$DATA_PORT")"
    REACHABLE_HOST="${REACHABLE_HOST:-$(ask "其他节点可访问本节点的公网 IP 或域名" "$(detect_reachable_host)")}"
  elif [[ "$reachability" == "ix" ]]; then
    DATA_PORT="$(choose_port "WireGuard UDP 内网监听端口" udp 19801 "$DATA_PORT")"
    REACHABLE_HOST="${REACHABLE_HOST:-$(ask "同 IX/内网其他节点可访问本节点的内网 IP" "$(detect_reachable_host)")}"
    echo "本节点按 IX 模式安装：将发布内网入口供新节点主动加入或认领；上行按 NAT，后续可主动连接有公网的节点。"
  else
    DATA_PORT="${DATA_PORT:-$(find_available_port udp 19801)}"
    REACHABLE_HOST="$(detect_reachable_host)"
    echo "本节点按纯 NAT 模式安装：WireGuard 本地端口已自动选择，不会发布给其他节点。"
  fi
  endpoint_host="$(format_endpoint_host "$REACHABLE_HOST")"
  choose_panel_password
  node_executable="$(resolve_node_executable)"
  panel_password_hash="$(hash_panel_password "$node_executable")"

  install_private_wireguard_runtime
  install_node_bundle
  install -m 0755 /opt/pathweaver/current/scripts/uninstall.sh /usr/local/sbin/pathweaver-uninstall
  install -m 0755 /opt/pathweaver/current/scripts/update.sh /usr/local/sbin/pathweaver-update
  install -m 0755 /opt/pathweaver/current/scripts/set-panel-password.sh /usr/local/sbin/pathweaver-set-panel-password
  if ! id pathweaver >/dev/null 2>&1; then useradd --system --home /var/lib/pathweaver --shell /usr/sbin/nologin pathweaver; fi
  install -d -o pathweaver -g pathweaver -m 0750 /var/lib/pathweaver
  install -d -m 0700 /var/lib/pathweaver-agent
  install -d -m 0750 /etc/pathweaver
  install -d -o pathweaver -g pathweaver -m 0750 /etc/wireguard
  install_update_dispatcher
  if [[ ! -f /etc/pathweaver/sysctl.previous ]]; then
    cat >/etc/pathweaver/sysctl.previous <<EOF
IP_FORWARD_PREVIOUS=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
RP_FILTER_ALL_PREVIOUS=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 0)
RP_FILTER_DEFAULT_PREVIOUS=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo 0)
EOF
    chmod 0600 /etc/pathweaver/sysctl.previous
  fi
  cat >/etc/sysctl.d/90-pathweaver.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
  sysctl --system >/dev/null
  node_env=/etc/pathweaver/node.env

  if [[ "$bootstrap" -eq 1 ]]; then
    write_bootstrap_node_env "$node_env" "$panel_password_hash" "$endpoint_host" "$PANEL_PORT" "$DATA_PORT"
    if ! verify_panel_password_env "$node_env" "$node_executable" "$PANEL_PASSWORD"; then
      echo "面板密码写入校验失败，请重新运行安装。" >&2
      exit 1
    fi
    cat >/etc/systemd/system/pathweaver-node.service <<EOF
[Unit]
Description=PathWeaver Peer Node and Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pathweaver
Group=pathweaver
WorkingDirectory=/opt/pathweaver/current
ExecStart=$node_executable /opt/pathweaver/current/src/center/server.js
Environment=NODE_ENV=production
Environment=SDWAN_HOST=0.0.0.0
Environment=SDWAN_PORT=$PANEL_PORT
Environment=SDWAN_DATA_DIR=/var/lib/pathweaver
Environment=SDWAN_APPLY_NETWORK=1
Environment=SDWAN_WIREGUARD_RUNTIME_DIR=$WIREGUARD_RUNTIME_LINK
Environment=SDWAN_WIREGUARD_DIR=/etc/wireguard
Environment=PATH=$NODE_RUNTIME_LINK/bin:$WIREGUARD_RUNTIME_LINK/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EnvironmentFile=$node_env
Restart=always
RestartSec=5
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now pathweaver-node
    wait_for_panel_health "$PANEL_PORT" || exit 1
  else
    panel_proxy_token="$("$node_executable" -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))")"
    control_endpoint=""
    data_endpoint=""
    if [[ "$reachability" == "public" || "$reachability" == "ix" ]]; then
      control_endpoint="http://$endpoint_host:$RELAY_PORT"
      data_endpoint="$endpoint_host:$DATA_PORT"
    fi
    write_peer_node_env "$node_env" "$panel_password_hash" "$panel_proxy_token"
    if ! verify_panel_password_env "$node_env" "$node_executable" "$PANEL_PASSWORD"; then
      echo "面板密码写入校验失败，请重新运行安装。" >&2
      exit 1
    fi
    ARGS=(--relay-port "$RELAY_PORT" --data-port "$DATA_PORT" --reachability "$reachability" --panel-proxy-token "$panel_proxy_token")
    if [[ -n "$control_endpoint" ]]; then ARGS+=(--control-endpoint "$control_endpoint"); fi
    if [[ -n "$data_endpoint" ]]; then ARGS+=(--data-endpoint "$data_endpoint"); fi
    if [[ -n "$UPSTREAM" ]]; then ARGS+=(--upstream "$UPSTREAM"); fi
    if [[ -n "$JOIN_TOKEN" ]]; then ARGS+=(--join-token "$JOIN_TOKEN"); fi
    if [[ -n "$CLAIM_TOKEN" ]]; then ARGS+=(--claim-token "$CLAIM_TOKEN" --listen); fi
    cat >/etc/systemd/system/pathweaver-agent.service <<EOF
[Unit]
Description=PathWeaver Peer Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/pathweaver/current
ExecStart=$node_executable /opt/pathweaver/current/src/agent/agent.js ${ARGS[*]}
Environment=SDWAN_APPLY_NETWORK=1
Environment=SDWAN_AGENT_DATA_DIR=/var/lib/pathweaver-agent
Environment=SDWAN_WIREGUARD_RUNTIME_DIR=$WIREGUARD_RUNTIME_LINK
Environment=PATH=$NODE_RUNTIME_LINK/bin:$WIREGUARD_RUNTIME_LINK/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Restart=always
RestartSec=5
NoNewPrivileges=false
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    cat >/etc/systemd/system/pathweaver-node.service <<EOF
[Unit]
Description=PathWeaver Peer Panel
After=network-online.target pathweaver-agent.service
Wants=network-online.target
Requires=pathweaver-agent.service

[Service]
Type=simple
User=pathweaver
Group=pathweaver
WorkingDirectory=/opt/pathweaver/current
ExecStart=$node_executable /opt/pathweaver/current/src/peer/server.js
Environment=NODE_ENV=production
Environment=SDWAN_PANEL_HOST=0.0.0.0
Environment=SDWAN_PANEL_PORT=$PANEL_PORT
Environment=SDWAN_AGENT_RELAY_URL=http://127.0.0.1:$RELAY_PORT
EnvironmentFile=$node_env
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now pathweaver-agent pathweaver-node
    wait_for_panel_health "$PANEL_PORT" || exit 1
  fi

  if [[ "$reachability" == "public" ]]; then
    echo "PathWeaver 节点已启动：面板 http://$endpoint_host:$PANEL_PORT，公网 WireGuard UDP $DATA_PORT。"
  elif [[ "$reachability" == "ix" ]]; then
    echo "PathWeaver 节点已启动：面板 http://$endpoint_host:$PANEL_PORT，IX 内网 WireGuard UDP $DATA_PORT（$endpoint_host）。"
  else
    echo "PathWeaver 节点已启动：面板 http://$endpoint_host:$PANEL_PORT；数据面仅主动拨出，不公开 WireGuard 端口。"
  fi
  echo "每台设备都使用自己的安装密码登录面板，配置通过现有无环控制路径实时保持一致。"
  if [[ -n "$CLAIM_TOKEN" ]]; then
    echo "待认领节点 IP 或域名：$REACHABLE_HOST"
    echo "待认领节点控制端口：$RELAY_PORT"
    echo "请把上面两项分别复制到已入网面板的认领表单。"
  fi
}

if [[ "$SOURCE" == "__PATHWEAVER_SOURCE__" ]]; then
  echo "安装源未设置；请使用任意已入网节点生成的命令，或传入 --source URL。" >&2
  exit 2
fi
if [[ "$UPDATE_ONLY" -eq 1 ]]; then
  update_node
else
  install_node
fi
