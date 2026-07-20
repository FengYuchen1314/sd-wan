import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import {
  executeBenchmark,
  handleBenchmarkRequest,
  LATENCY_TOTAL_SAMPLES,
  prepareBenchmark,
  summarizeLatencySamples,
} from '../src/core/benchmark.js';

test('summarizeLatencySamples 丢弃预热样本并对剩余采样做截尾平均', () => {
  const result = summarizeLatencySamples([40, 35, 20, 21, 22, 23, 24, 25, 26, 27]);
  assert.equal(result.sampleCount, 8);
  assert.equal(result.latencyMinMs, 20);
  assert.equal(result.latencyP95Ms, 27);
  assert.ok(result.latencyMs >= 21 && result.latencyMs <= 25);
});

test('相邻链路延迟探测通过一次性凭据测量多次往返 RTT', async () => {
  const store = {};
  const itemId = 'benchmark-link-1';
  const token = 'benchmark-secret';
  prepareBenchmark(store, {
    itemId, token,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      if (await handleBenchmarkRequest(req, res, url.pathname, url, store, 'target-node')) return;
      res.writeHead(404).end();
    } catch (error) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const result = await executeBenchmark({
      itemId, token,
      remoteUrl: `http://127.0.0.1:${server.address().port}`,
      expectedNodeId: 'target-node',
    });
    assert.equal(result.ok, true);
    assert.equal(result.sampleCount, LATENCY_TOTAL_SAMPLES - 2);
    assert.ok(result.latencyMs >= 0);
    assert.ok(result.latencyP95Ms >= result.latencyMinMs);
    assert.equal(result.bandwidthMbps, undefined);
  } finally {
    server.close();
    await once(server, 'close');
  }
});
