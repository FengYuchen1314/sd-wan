#!/usr/bin/env bash
set -euo pipefail

UPSTREAM=""
SOURCE="__PATHWEAVER_SOURCE__"
JOIN_TOKEN=""
CLAIM_TOKEN=""
LISTEN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upstream) UPSTREAM="$2"; shift 2 ;;
    --join-token) JOIN_TOKEN="$2"; shift 2 ;;
    --claim-token) CLAIM_TOKEN="$2"; shift 2 ;;
    --listen) LISTEN="--listen"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$UPSTREAM" && -z "$CLAIM_TOKEN" ]]; then
  echo "--upstream is required (the selected center or edge relay URL)" >&2
  exit 2
fi
if [[ -z "$JOIN_TOKEN" && -z "$CLAIM_TOKEN" ]]; then
  echo "--join-token or --claim-token is required" >&2
  exit 2
fi
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 22.5+ is required. Install it before running this command." >&2
  exit 1
fi

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [[ "$NODE_MAJOR" -lt 22 ]]; then
  echo "Node.js 22.5+ is required; found $(node --version)." >&2
  exit 1
fi

install -d -m 0755 /opt/pathweaver-agent
install -d -m 0700 /var/lib/pathweaver-agent
curl -fsSL "$SOURCE/artifacts/agent/agent.js" -o /opt/pathweaver-agent/agent.js
curl -fsSL "$SOURCE/artifacts/agent/wireguard.js" -o /opt/pathweaver-agent/wireguard.js
cat >/opt/pathweaver-agent/package.json <<'EOF'
{"type":"module","private":true}
EOF

ARGS=()
if [[ -n "$UPSTREAM" ]]; then ARGS+=(--upstream "$UPSTREAM"); fi
if [[ -n "$JOIN_TOKEN" ]]; then ARGS+=(--join-token "$JOIN_TOKEN"); fi
if [[ -n "$CLAIM_TOKEN" ]]; then ARGS+=(--claim-token "$CLAIM_TOKEN"); fi
if [[ -n "$LISTEN" || -n "$CLAIM_TOKEN" ]]; then ARGS+=(--listen); fi

cat >/etc/systemd/system/pathweaver-agent.service <<EOF
[Unit]
Description=PathWeaver SD-WAN Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(command -v node) /opt/pathweaver-agent/agent.js ${ARGS[*]}
Environment=SDWAN_APPLY_NETWORK=1
Environment=SDWAN_AGENT_DATA_DIR=/var/lib/pathweaver-agent
Restart=always
RestartSec=5
NoNewPrivileges=false
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now pathweaver-agent
echo "PathWeaver Agent installed and started."
