#!/usr/bin/env bash
set -euo pipefail

PURGE=0

usage() {
  cat <<'EOF'
PathWeaver 本机卸载器

用法：
  pathweaver-uninstall           移除服务、程序和运行时，保留数据库与节点密钥
  pathweaver-uninstall --purge   同时永久删除本机数据库、节点身份和缓存
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "请使用 root 运行，或通过 sudo 执行卸载命令。" >&2
  exit 1
fi

echo "正在停止 PathWeaver 服务……"
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now pathweaver-agent.service pathweaver-node.service >/dev/null 2>&1 || true
fi

WIREGUARD_QUICK="/opt/pathweaver-agent/runtime/wireguard-current/bin/wg-quick"
if [[ ! -x "$WIREGUARD_QUICK" ]] && command -v wg-quick >/dev/null 2>&1; then
  WIREGUARD_QUICK="$(command -v wg-quick)"
fi

shopt -s nullglob
for config in /etc/wireguard/pw-data.conf /etc/wireguard/pw-??????????.conf; do
  name="$(basename "$config")"
  if [[ ! "$name" =~ ^pw-(data|[0-9a-f]{10})\.conf$ ]]; then continue; fi
  if [[ -x "$WIREGUARD_QUICK" ]]; then "$WIREGUARD_QUICK" down "$config" >/dev/null 2>&1 || true; fi
  rm -f -- "$config"
done
shopt -u nullglob

if command -v ip >/dev/null 2>&1; then
  while IFS= read -r tunnel; do
    tunnel="${tunnel%%@*}"
    if [[ "$tunnel" =~ ^pwm[0-9a-f]{11}$ ]]; then
      local_ip="$(ip -d link show dev "$tunnel" 2>/dev/null | sed -n 's/.* local \([0-9.]*\) .*/\1/p' | head -n 1)"
      ip link delete dev "$tunnel" >/dev/null 2>&1 || true
      if [[ "$local_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        ip address del "$local_ip/32" dev lo >/dev/null 2>&1 || true
      fi
    fi
  done < <(ip -o link show type ipip 2>/dev/null | awk -F': ' '{print $2}')
fi

rm -f -- /etc/systemd/system/pathweaver-agent.service /etc/systemd/system/pathweaver-node.service
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl reset-failed pathweaver-agent.service pathweaver-node.service >/dev/null 2>&1 || true
fi

rm -f -- /etc/sysctl.d/90-pathweaver.conf
if [[ -f /etc/pathweaver/sysctl.previous ]]; then
  # 该文件由安装器以 root:root 0600 创建，只包含三个数字变量。
  # shellcheck disable=SC1091
  source /etc/pathweaver/sysctl.previous
  [[ "${IP_FORWARD_PREVIOUS:-}" =~ ^[0-9]+$ ]] && sysctl -w "net.ipv4.ip_forward=$IP_FORWARD_PREVIOUS" >/dev/null 2>&1 || true
  [[ "${RP_FILTER_ALL_PREVIOUS:-}" =~ ^[0-9]+$ ]] && sysctl -w "net.ipv4.conf.all.rp_filter=$RP_FILTER_ALL_PREVIOUS" >/dev/null 2>&1 || true
  [[ "${RP_FILTER_DEFAULT_PREVIOUS:-}" =~ ^[0-9]+$ ]] && sysctl -w "net.ipv4.conf.default.rp_filter=$RP_FILTER_DEFAULT_PREVIOUS" >/dev/null 2>&1 || true
fi

rm -f -- /etc/pathweaver/node.env /etc/pathweaver/sysctl.previous
rmdir /etc/pathweaver >/dev/null 2>&1 || true
rm -rf -- /opt/pathweaver /opt/pathweaver-agent

if [[ "$PURGE" -eq 1 ]]; then
  rm -rf -- /var/lib/pathweaver /var/lib/pathweaver-agent
  if id pathweaver >/dev/null 2>&1; then userdel pathweaver >/dev/null 2>&1 || true; fi
  rm -f -- /usr/local/sbin/pathweaver-uninstall
  echo "PathWeaver 已完全卸载，本机数据库、节点身份和缓存已永久删除。"
else
  echo "PathWeaver 已卸载。以下本机数据已保留，可供重新安装恢复："
  echo "  /var/lib/pathweaver"
  echo "  /var/lib/pathweaver-agent"
  echo "如需永久清除，请在确认不再需要恢复后运行：sudo pathweaver-uninstall --purge"
fi
