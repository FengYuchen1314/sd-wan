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
PANEL_PASSWORD=""
WIREGUARD_TOOLS_VERSION="1.0.20260223"
WIREGUARD_TOOLS_SHA256="af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf"
WIREGUARD_RUNTIME_ROOT="/opt/pathweaver-agent/runtime"
WIREGUARD_RUNTIME_LINK="$WIREGUARD_RUNTIME_ROOT/wireguard-current"

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
    --panel-password) PANEL_PASSWORD="$2"; shift 2 ;;
    --admin-token) PANEL_PASSWORD="$2"; shift 2 ;;
    --listen) shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 22.5+ is required. Install it before running this command." >&2
  exit 1
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [[ "$NODE_MAJOR" -lt 22 ]]; then
  echo "Node.js 22.5+ is required; found $(node --version)." >&2
  exit 1
fi

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

detect_reachable_host() {
  local detected
  detected="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  printf '%s\n' "${detected:-127.0.0.1}"
}

format_endpoint_host() {
  if [[ "$1" == *:* && "$1" != \[*\] ]]; then printf '[%s]' "$1"; else printf '%s' "$1"; fi
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
  if ! curl -fsSL "$SOURCE/artifacts/wireguard/wireguard-tools-$WIREGUARD_TOOLS_VERSION.tar.xz" -o "$archive"; then
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
  cat >"$release_dir/runtime.json" <<EOF
{"schemaVersion":1,"toolsVersion":"$WIREGUARD_TOOLS_VERSION","installedAt":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","managedBy":"pathweaver"}
EOF
  "$release_dir/bin/wg" --version >/dev/null
  ln -sfn "$release_dir" "$WIREGUARD_RUNTIME_LINK"
  trap - RETURN
  rm -rf -- "$build_dir"
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
  printf '%s' "$PANEL_PASSWORD" | node -e '
const { randomBytes, scryptSync } = require("node:crypto");
const chunks = [];
process.stdin.on("data", chunk => chunks.push(chunk));
process.stdin.on("end", () => {
  const password = Buffer.concat(chunks).toString("utf8");
  const salt = randomBytes(16);
  const digest = scryptSync(password, salt, 32);
  process.stdout.write(`scrypt-v1$${salt.toString("base64url")}$${digest.toString("base64url")}`);
});'
}

install_node_bundle() {
  local release bundle archive_root
  install -d -m 0755 /opt/pathweaver/releases
  release="/opt/pathweaver/releases/node-$(date +%s)-$$"
  install -d -m 0755 "$release"
  bundle="$(mktemp)"
  if curl -fsSL "$SOURCE/artifacts/center/pathweaver-center.tar.gz" -o "$bundle"; then
    tar -xzf "$bundle" -C "$release"
  else
    rm -f -- "$bundle"
    bundle="$(mktemp)"
    curl -fsSL "https://github.com/FengYuchen1314/sd-wan/archive/refs/heads/main.tar.gz" -o "$bundle"
    archive_root="$(tar -tzf "$bundle" | awk -F/ 'NR == 1 { root = $1 } END { print root }')"
    tar -xzf "$bundle" -C "$release" --strip-components=1 "$archive_root"
  fi
  rm -f -- "$bundle"
  ln -sfn "$release" /opt/pathweaver/current
}

install_node() {
  local endpoint_host control_endpoint data_endpoint node_env panel_password_hash panel_proxy_token bootstrap
  bootstrap=0
  if [[ -z "$JOIN_TOKEN" && -z "$CLAIM_TOKEN" && -z "$UPSTREAM" ]]; then bootstrap=1; fi
  if [[ "$bootstrap" -eq 0 && -z "$JOIN_TOKEN" && -z "$CLAIM_TOKEN" ]]; then
    echo "加入现有网络需要 --join-token 或 --claim-token。" >&2
    exit 2
  fi

  PANEL_PORT="$(choose_port "本机管理面板 TCP 端口" tcp 19773 "$PANEL_PORT")"
  if [[ "$bootstrap" -eq 0 ]]; then RELAY_PORT="$(choose_port "节点控制中继 TCP 端口" tcp 8790 "$RELAY_PORT")"; fi
  DATA_PORT="$(choose_port "WireGuard UDP 端口" udp 19801 "$DATA_PORT")"
  REACHABLE_HOST="${REACHABLE_HOST:-$(ask "其他节点可访问本节点的 IP 或域名" "$(detect_reachable_host)")}"
  endpoint_host="$(format_endpoint_host "$REACHABLE_HOST")"
  choose_panel_password
  panel_password_hash="$(hash_panel_password)"

  install_private_wireguard_runtime
  install_node_bundle
  if ! id pathweaver >/dev/null 2>&1; then useradd --system --home /var/lib/pathweaver --shell /usr/sbin/nologin pathweaver; fi
  install -d -o pathweaver -g pathweaver -m 0750 /var/lib/pathweaver
  install -d -m 0700 /var/lib/pathweaver-agent
  install -d -m 0750 /etc/pathweaver
  install -d -o pathweaver -g pathweaver -m 0750 /etc/wireguard
  node_env=/etc/pathweaver/node.env

  if [[ "$bootstrap" -eq 1 ]]; then
    cat >"$node_env" <<EOF
SDWAN_PANEL_PASSWORD_HASH=$panel_password_hash
SDWAN_PUBLIC_URL=http://$endpoint_host:$PANEL_PORT
SDWAN_DEFAULT_DATA_PORT=$DATA_PORT
EOF
    chmod 0600 "$node_env"
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
ExecStart=$(command -v node) /opt/pathweaver/current/src/center/server.js
Environment=NODE_ENV=production
Environment=SDWAN_HOST=0.0.0.0
Environment=SDWAN_PORT=$PANEL_PORT
Environment=SDWAN_DATA_DIR=/var/lib/pathweaver
Environment=SDWAN_APPLY_NETWORK=1
Environment=SDWAN_WIREGUARD_RUNTIME_DIR=$WIREGUARD_RUNTIME_LINK
Environment=SDWAN_WIREGUARD_DIR=/etc/wireguard
Environment=PATH=$WIREGUARD_RUNTIME_LINK/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
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
  else
    panel_proxy_token="$(node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))")"
    control_endpoint="http://$endpoint_host:$RELAY_PORT"
    data_endpoint="$endpoint_host:$DATA_PORT"
    cat >"$node_env" <<EOF
SDWAN_PANEL_PASSWORD_HASH=$panel_password_hash
SDWAN_PANEL_PROXY_TOKEN=$panel_proxy_token
EOF
    chmod 0600 "$node_env"
    ARGS=(--relay-port "$RELAY_PORT" --data-port "$DATA_PORT" --control-endpoint "$control_endpoint" --data-endpoint "$data_endpoint" --panel-proxy-token "$panel_proxy_token")
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
ExecStart=$(command -v node) /opt/pathweaver/current/src/agent/agent.js ${ARGS[*]}
Environment=SDWAN_APPLY_NETWORK=1
Environment=SDWAN_AGENT_DATA_DIR=/var/lib/pathweaver-agent
Environment=SDWAN_WIREGUARD_RUNTIME_DIR=$WIREGUARD_RUNTIME_LINK
Environment=PATH=$WIREGUARD_RUNTIME_LINK/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
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
ExecStart=$(command -v node) /opt/pathweaver/current/src/peer/server.js
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
  fi

  echo "PathWeaver 节点已启动：面板 http://$endpoint_host:$PANEL_PORT，WireGuard UDP $DATA_PORT。"
  echo "每台设备都使用自己的安装密码登录面板，配置通过现有无环控制路径实时保持一致。"
  if [[ -n "$CLAIM_TOKEN" ]]; then echo "请在任意已入网面板填写待认领地址：http://$endpoint_host:$RELAY_PORT"; fi
}

if [[ "$SOURCE" == "__PATHWEAVER_SOURCE__" ]]; then
  echo "安装源未设置；请使用任意已入网节点生成的命令，或传入 --source URL。" >&2
  exit 2
fi
install_node
