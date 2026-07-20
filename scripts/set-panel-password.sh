#!/usr/bin/env bash
set -euo pipefail

NODE_ENV_FILE="/etc/pathweaver/node.env"
ROOT="/opt/pathweaver/current"
NODE_BINARY=""

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "请使用 root 运行，或通过 sudo 执行。" >&2
  exit 1
fi
if [[ -x /opt/pathweaver/runtime/node-current/bin/node ]]; then
  NODE_BINARY=/opt/pathweaver/runtime/node-current/bin/node
elif command -v node >/dev/null 2>&1; then
  NODE_BINARY="$(command -v node)"
else
  echo "未找到 Node.js 运行时。" >&2
  exit 1
fi
if [[ ! -f "$ROOT/src/core/password.js" ]]; then
  echo "未找到 PathWeaver 程序目录：$ROOT" >&2
  exit 1
fi

TTY_DEVICE=""
if [[ -r /dev/tty && -w /dev/tty ]]; then TTY_DEVICE="/dev/tty"; fi

read_password() {
  local prompt="$1" answer=""
  if [[ -z "$TTY_DEVICE" ]]; then
    echo "请在交互式终端中运行此命令。" >&2
    exit 2
  fi
  while true; do
    printf '%s' "$prompt" >"$TTY_DEVICE"
    IFS= read -r -s answer <"$TTY_DEVICE" || true
    printf '\n' >"$TTY_DEVICE"
    if (( ${#answer} < 8 )); then
      echo "面板密码至少需要 8 个字符，请重新输入。" >"$TTY_DEVICE"
      continue
    fi
    printf '%s\n' "$answer"
    return
  done
}

first="$(read_password "请输入新的面板密码（至少 8 个字符）: ")"
second="$(read_password "请再次输入面板密码: ")"
if [[ "$first" != "$second" ]]; then
  echo "两次输入不一致。" >&2
  exit 2
fi

HASH="$(
  cd "$ROOT"
  printf '%s' "$first" | "$NODE_BINARY" --input-type=module -e "
import { hashPanelPassword } from './src/core/password.js';
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
process.stdout.write(hashPanelPassword(Buffer.concat(chunks).toString('utf8')));
"
)"

install -d -m 0750 /etc/pathweaver
temp="$(mktemp)"
if [[ -f "$NODE_ENV_FILE" ]]; then
  grep -v '^SDWAN_PANEL_PASSWORD_HASH=' "$NODE_ENV_FILE" >"$temp" || true
else
  : >"$temp"
fi
printf 'SDWAN_PANEL_PASSWORD_HASH=%s\n' "$HASH" >>"$temp"
install -m 0600 "$temp" "$NODE_ENV_FILE"
rm -f -- "$temp"

services=()
for service in pathweaver-node.service pathweaver-agent.service; do
  if [[ -f "/etc/systemd/system/$service" ]]; then services+=("${service%.service}"); fi
done
systemctl daemon-reload
if ((${#services[@]})); then
  systemctl restart "${services[@]}"
fi

echo "面板密码已更新，请使用新密码重新登录面板。"
