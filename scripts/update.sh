#!/usr/bin/env bash
set -uo pipefail

GITHUB_SOURCE="${PATHWEAVER_UPDATE_GITHUB_SOURCE:-https://raw.githubusercontent.com/FengYuchen1314/sd-wan/main}"
GITHUB_BUNDLE_URL="${PATHWEAVER_UPDATE_GITHUB_BUNDLE_URL:-https://github.com/FengYuchen1314/sd-wan/archive/refs/heads/main.tar.gz}"
EXPLICIT_SOURCE=""
NODE_BINARY=""
declare -a UPDATE_SOURCES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) EXPLICIT_SOURCE="${2%/}"; shift 2 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 && "${PATHWEAVER_UPDATE_DRY_RUN:-0}" != 1 ]]; then
  echo "请使用 root 运行，或通过 sudo 执行更新命令。" >&2
  exit 1
fi

if [[ -n "${PATHWEAVER_UPDATE_NODE:-}" && -x "$PATHWEAVER_UPDATE_NODE" ]]; then
  NODE_BINARY="$PATHWEAVER_UPDATE_NODE"
elif [[ -x /opt/pathweaver/runtime/node-current/bin/node ]]; then
  NODE_BINARY=/opt/pathweaver/runtime/node-current/bin/node
elif command -v node >/dev/null 2>&1; then
  NODE_BINARY="$(command -v node)"
else
  echo "PathWeaver Node.js 运行时不存在，无法读取已保存的节点地址。" >&2
  exit 1
fi

normalize_source() {
  "$NODE_BINARY" - "$1" <<'NODE'
const raw = String(process.argv[2] || '').trim();
try {
  const url = new URL(raw);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.origin === 'null') process.exit(1);
  url.search = '';
  url.hash = '';
  url.pathname = url.pathname.replace(/\/+$/, '');
  process.stdout.write(url.href.replace(/\/$/, ''));
} catch {
  process.exit(1);
}
NODE
}

add_source() {
  local normalized existing
  normalized="$(normalize_source "$1" 2>/dev/null || true)"
  [[ -n "$normalized" ]] || return
  for existing in "${UPDATE_SOURCES[@]}"; do
    [[ "$existing" == "$normalized" ]] && return
  done
  UPDATE_SOURCES+=("$normalized")
}

discover_agent_sources() {
  local state_file="${PATHWEAVER_UPDATE_AGENT_STATE:-/var/lib/pathweaver-agent/state.json}"
  [[ -r "$state_file" ]] || return
  "$NODE_BINARY" - "$state_file" <<'NODE' 2>/dev/null || true
const { readFileSync } = require('node:fs');
const state = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const values = [state.upstream, ...Object.values(state.controlForwarders || {})];
for (const value of values) {
  try {
    const url = new URL(String(value || ''));
    if (['http:', 'https:'].includes(url.protocol) && !url.username && !url.password) console.log(url.origin);
  } catch {}
}
NODE
}

discover_center_sources() {
  local database_file="${PATHWEAVER_UPDATE_DATABASE:-/var/lib/pathweaver/pathweaver.db}"
  [[ -r "$database_file" ]] || return
  "$NODE_BINARY" --no-warnings - "$database_file" <<'NODE' 2>/dev/null || true
const { DatabaseSync } = require('node:sqlite');
const database = new DatabaseSync(process.argv[2], { readOnly: true });
const rows = database.prepare(`
  SELECT control_endpoint, control_ip, control_listen_port
  FROM nodes
  WHERE is_center = 0 AND can_relay = 1
  ORDER BY CASE status WHEN 'online' THEN 0 ELSE 1 END, last_seen DESC
`).all();
for (const row of rows) {
  if (row.control_endpoint) {
    console.log(row.control_endpoint);
  } else if (row.control_ip) {
    const host = String(row.control_ip).includes(':') ? `[${row.control_ip}]` : row.control_ip;
    console.log(`http://${host}:${Number(row.control_listen_port || 8790)}`);
  }
}
database.close();
NODE
}

[[ -n "$EXPLICIT_SOURCE" ]] && add_source "$EXPLICIT_SOURCE"
add_source "$GITHUB_SOURCE"
while IFS= read -r candidate; do add_source "$candidate"; done < <(discover_agent_sources)
while IFS= read -r candidate; do add_source "$candidate"; done < <(discover_center_sources)

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

for source in "${UPDATE_SOURCES[@]}"; do
  installer="$work_dir/install.sh"
  rm -f -- "$installer"
  if [[ "$source" == "$GITHUB_SOURCE" ]]; then
    installer_url="$source/scripts/install.sh?cache=$(date +%s)"
    bundle_url="$GITHUB_BUNDLE_URL?cache=$(date +%s)"
  else
    installer_url="$source/install.sh"
    bundle_url="$source/artifacts/center/pathweaver-center.tar.gz"
  fi

  echo "正在探测更新源：$source"
  if ! curl --connect-timeout 4 --max-time 20 --retry 1 -fsSL "$installer_url" -o "$installer" 2>/dev/null; then
    echo "更新源不可达，尝试下一台节点。"
    continue
  fi
  if ! curl --connect-timeout 4 --max-time 20 --retry 1 -fsSL --range 0-0 "$bundle_url" -o /dev/null 2>/dev/null; then
    echo "更新源无法提供完整程序制品，尝试下一台节点。"
    continue
  fi
  if [[ "${PATHWEAVER_UPDATE_DRY_RUN:-0}" == 1 ]]; then
    echo "DRY_RUN_SOURCE=$source"
    exit 0
  fi
  if bash "$installer" --source "$source" --update; then
    echo "PathWeaver 已从 $source 完成更新。"
    exit 0
  fi
  echo "从 $source 更新失败，已保留或恢复原版本；继续尝试下一台节点。" >&2
done

echo "更新失败：GitHub 与所有已保存的可达节点均无法提供有效更新。" >&2
exit 1
