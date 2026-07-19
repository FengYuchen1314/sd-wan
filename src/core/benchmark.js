import { createHash, timingSafeEqual } from 'node:crypto';

export const DEFAULT_BENCHMARK_BYTES = 2 * 1024 * 1024;
export const MAX_BENCHMARK_BYTES = 4 * 1024 * 1024;

function hashToken(value) {
  return createHash('sha256').update(String(value || '')).digest();
}

function tokenMatches(value, expectedHex) {
  const actual = hashToken(value);
  const expected = Buffer.from(String(expectedHex || ''), 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function normalizeBytes(value) {
  const bytes = Number(value || DEFAULT_BENCHMARK_BYTES);
  if (!Number.isInteger(bytes) || bytes < 64 * 1024 || bytes > MAX_BENCHMARK_BYTES) {
    throw new Error('测速数据量必须在 64 KiB 到 4 MiB 之间');
  }
  return bytes;
}

export function prepareBenchmark(store, payload) {
  const itemId = String(payload.itemId || '');
  const token = String(payload.token || '');
  const expiresAt = String(payload.expiresAt || '');
  if (!itemId || !token || !expiresAt || expiresAt <= new Date().toISOString()) {
    throw new Error('测速准备参数无效或已经过期');
  }
  store[itemId] = {
    tokenHash: hashToken(token).toString('hex'),
    expiresAt,
    bytes: normalizeBytes(payload.bytes),
  };
  return { ok: true, prepared: true, itemId };
}

async function fetchChecked(url, options, expectedNodeId) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(20_000) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `测速目标返回 HTTP ${response.status}`);
  if (result.nodeId !== expectedNodeId) throw new Error('测速目标节点身份与预期不一致');
  return result;
}

export async function executeBenchmark(payload) {
  const itemId = String(payload.itemId || '');
  const expectedNodeId = String(payload.expectedNodeId || '');
  const bytes = normalizeBytes(payload.bytes);
  const remote = new URL(`/agent/v1/benchmark/${encodeURIComponent(itemId)}`, `${String(payload.remoteUrl || '').replace(/\/$/, '')}/`);
  const headers = { 'X-PathWeaver-Benchmark-Token': String(payload.token || '') };
  const samples = [];
  for (let index = 0; index < 5; index += 1) {
    const started = performance.now();
    await fetchChecked(`${remote}?mode=latency`, { method: 'POST', headers, body: Buffer.alloc(0) }, expectedNodeId);
    samples.push(performance.now() - started);
  }
  const uploadStarted = performance.now();
  const uploaded = await fetchChecked(`${remote}?mode=upload`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/octet-stream', 'Content-Length': String(bytes) },
    body: Buffer.alloc(bytes, 0x5a),
  }, expectedNodeId);
  const durationMs = Math.max(1, performance.now() - uploadStarted);
  if (Number(uploaded.bytes) !== bytes) throw new Error('测速目标接收的数据量不完整');
  const sorted = [...samples].sort((a, b) => a - b);
  const latencyMs = samples.reduce((total, value) => total + value, 0) / samples.length;
  return {
    ok: true,
    latencyMs: Number(latencyMs.toFixed(2)),
    latencyMinMs: Number(sorted[0].toFixed(2)),
    latencyP95Ms: Number(sorted[sorted.length - 1].toFixed(2)),
    bandwidthMbps: Number(((bytes * 8) / durationMs / 1000).toFixed(2)),
    bytes,
    durationMs: Number(durationMs.toFixed(2)),
    measuredAt: new Date().toISOString(),
  };
}

export async function handleBenchmarkRequest(req, res, pathname, url, store, nodeId) {
  const match = pathname.match(/^\/agent\/v1\/benchmark\/([^/]+)$/);
  if (!match || req.method !== 'POST') return false;
  const itemId = decodeURIComponent(match[1]);
  const pending = store[itemId];
  const token = req.headers['x-pathweaver-benchmark-token'];
  if (!pending || pending.expiresAt <= new Date().toISOString() || !tokenMatches(token, pending.tokenHash)) {
    res.writeHead(401, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ error: '测速凭据无效或已过期' }));
    return true;
  }
  const mode = url.searchParams.get('mode');
  let length = 0;
  const limit = mode === 'upload' ? MAX_BENCHMARK_BYTES : 1024;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > limit) throw new Error('测速请求超过数据量上限');
  }
  if (mode === 'upload' && length !== pending.bytes) throw new Error('测速上传数据量与计划不一致');
  if (!['latency', 'upload'].includes(mode)) throw new Error('测速模式无效');
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ ok: true, nodeId, bytes: length, receivedAt: new Date().toISOString() }));
  return true;
}
