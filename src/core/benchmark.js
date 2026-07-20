import { createHash, timingSafeEqual } from 'node:crypto';

export const LATENCY_WARMUP_SAMPLES = 2;
export const LATENCY_MEASUREMENT_SAMPLES = 8;
export const LATENCY_TOTAL_SAMPLES = LATENCY_WARMUP_SAMPLES + LATENCY_MEASUREMENT_SAMPLES;

function hashToken(value) {
  return createHash('sha256').update(String(value || '')).digest();
}

function tokenMatches(value, expectedHex) {
  const actual = hashToken(value);
  const expected = Buffer.from(String(expectedHex || ''), 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function summarizeLatencySamples(samples) {
  const measured = samples.slice(LATENCY_WARMUP_SAMPLES);
  if (measured.length < 3) throw new Error('延迟采样不足');
  const sorted = [...measured].sort((left, right) => left - right);
  const trimmed = sorted.length >= 5 ? sorted.slice(1, -1) : sorted;
  const latencyMs = trimmed.reduce((total, value) => total + value, 0) / trimmed.length;
  const p95Index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
  return {
    latencyMs: Number(latencyMs.toFixed(2)),
    latencyMinMs: Number(sorted[0].toFixed(2)),
    latencyP95Ms: Number(sorted[p95Index].toFixed(2)),
    sampleCount: measured.length,
    measuredAt: new Date().toISOString(),
  };
}

export function prepareBenchmark(store, payload) {
  const itemId = String(payload.itemId || '');
  const token = String(payload.token || '');
  const expiresAt = String(payload.expiresAt || '');
  if (!itemId || !token || !expiresAt || expiresAt <= new Date().toISOString()) {
    throw new Error('延迟探测准备参数无效或已经过期');
  }
  store[itemId] = {
    tokenHash: hashToken(token).toString('hex'),
    expiresAt,
  };
  return { ok: true, prepared: true, itemId };
}

async function fetchChecked(url, options, expectedNodeId) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(20_000) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `延迟探测目标返回 HTTP ${response.status}`);
  if (result.nodeId !== expectedNodeId) throw new Error('延迟探测目标节点身份与预期不一致');
  return result;
}

export async function executeBenchmark(payload) {
  const itemId = String(payload.itemId || '');
  const expectedNodeId = String(payload.expectedNodeId || '');
  const remote = new URL(`/agent/v1/benchmark/${encodeURIComponent(itemId)}`, `${String(payload.remoteUrl || '').replace(/\/$/, '')}/`);
  const headers = { 'X-PathWeaver-Benchmark-Token': String(payload.token || '') };
  const samples = [];
  for (let index = 0; index < LATENCY_TOTAL_SAMPLES; index += 1) {
    const started = performance.now();
    await fetchChecked(`${remote}?mode=latency`, { method: 'POST', headers, body: Buffer.alloc(0) }, expectedNodeId);
    samples.push(performance.now() - started);
  }
  return {
    ok: true,
    ...summarizeLatencySamples(samples),
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
    res.end(JSON.stringify({ error: '延迟探测凭据无效或已过期' }));
    return true;
  }
  if (url.searchParams.get('mode') !== 'latency') {
    res.writeHead(400, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ error: '延迟探测模式无效' }));
    return true;
  }
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 1024) throw new Error('延迟探测请求超过数据量上限');
  }
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ ok: true, nodeId, receivedAt: new Date().toISOString() }));
  return true;
}
