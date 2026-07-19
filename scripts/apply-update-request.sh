#!/usr/bin/env bash
set -uo pipefail

REQUEST_FILE="${PATHWEAVER_UPDATE_REQUEST_FILE:-/var/lib/pathweaver/update-request.json}"
STAGING_ROOT="${PATHWEAVER_UPDATE_STAGING_DIR:-/var/lib/pathweaver/update-staging}"
MARKER_FILE="${PATHWEAVER_UPDATE_APPLIED_FILE:-/var/lib/pathweaver/update-applied.json}"
NODE_BINARY="${PATHWEAVER_UPDATE_NODE:-/opt/pathweaver/runtime/node-current/bin/node}"

[[ -r "$REQUEST_FILE" ]] || exit 0
if [[ ! -x "$NODE_BINARY" ]]; then NODE_BINARY="$(command -v node 2>/dev/null || true)"; fi
if [[ -z "$NODE_BINARY" ]]; then echo "PathWeaver 更新请求缺少 Node.js 运行时。" >&2; exit 1; fi

ROLLOUT_ID="$($NODE_BINARY - "$REQUEST_FILE" <<'NODE'
const { readFileSync } = require('node:fs');
const value = JSON.parse(readFileSync(process.argv[2], 'utf8'));
if (!/^[0-9a-f-]{36}$/i.test(String(value.rolloutId || ''))) process.exit(2);
process.stdout.write(value.rolloutId);
NODE
)" || { echo "PathWeaver 更新请求格式无效。" >&2; exit 1; }

STAGING_DIR="$STAGING_ROOT/$ROLLOUT_ID"
INSTALLER_FILE="$STAGING_DIR/install.sh"
BUNDLE_FILE="$STAGING_DIR/pathweaver.tar.gz"
if [[ ! -f "$INSTALLER_FILE" || -L "$INSTALLER_FILE" || ! -f "$BUNDLE_FILE" || -L "$BUNDLE_FILE" ]]; then
  echo "PathWeaver 更新请求缺少安装器或制品。" >&2
  exit 1
fi

EXPECTED_SHA="$($NODE_BINARY - "$REQUEST_FILE" <<'NODE'
const { readFileSync } = require('node:fs');
const value = JSON.parse(readFileSync(process.argv[2], 'utf8'));
if (!/^[0-9a-f]{64}$/i.test(String(value.bundleSha256 || ''))) process.exit(2);
process.stdout.write(value.bundleSha256.toLowerCase());
NODE
)" || { echo "PathWeaver 更新摘要无效。" >&2; exit 1; }
ACTUAL_SHA="$(sha256sum "$BUNDLE_FILE" | awk '{print $1}')"
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
  echo "PathWeaver 更新制品摘要不一致。" >&2
  exit 1
fi

rm -f -- "$REQUEST_FILE"
sleep 4
ERROR_FILE="$(mktemp)"
if bash "$INSTALLER_FILE" \
  --source 'https://raw.githubusercontent.com/FengYuchen1314/sd-wan/main' \
  --bundle-file "$BUNDLE_FILE" --update 2> >(tee "$ERROR_FILE" >&2); then
  "$NODE_BINARY" - "$MARKER_FILE" "$ROLLOUT_ID" <<'NODE'
const { mkdirSync, renameSync, writeFileSync } = require('node:fs');
const { dirname } = require('node:path');
const [filename, rolloutId] = process.argv.slice(2);
mkdirSync(dirname(filename), { recursive: true });
const temporary = `${filename}.tmp`;
writeFileSync(temporary, `${JSON.stringify({ rolloutId, ok: true, appliedAt: new Date().toISOString() })}\n`, { mode: 0o600 });
renameSync(temporary, filename);
NODE
  rm -f -- "$ERROR_FILE"
  exit 0
fi

UPDATE_ERROR="$(tail -n 8 "$ERROR_FILE" | tr '\n' ' ' | cut -c1-1000)"
rm -f -- "$ERROR_FILE"
"$NODE_BINARY" - "$MARKER_FILE" "$ROLLOUT_ID" "$UPDATE_ERROR" <<'NODE'
const { mkdirSync, renameSync, writeFileSync } = require('node:fs');
const { dirname } = require('node:path');
const [filename, rolloutId, error] = process.argv.slice(2);
mkdirSync(dirname(filename), { recursive: true });
const temporary = `${filename}.tmp`;
writeFileSync(temporary, `${JSON.stringify({ rolloutId, ok: false, error: error || '本机更新失败', appliedAt: new Date().toISOString() })}\n`, { mode: 0o600 });
renameSync(temporary, filename);
NODE
exit 1
