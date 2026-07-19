import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { executeBenchmark, handleBenchmarkRequest, prepareBenchmark } from '../src/core/benchmark.js';

test('链路测速通过一次性凭据测量五次往返延迟和受控上传带宽', async () => {
  const store = {};
  const itemId = 'benchmark-link-1';
  const token = 'benchmark-secret';
  prepareBenchmark(store, {
    itemId, token, bytes: 128 * 1024,
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
      itemId, token, bytes: 128 * 1024,
      remoteUrl: `http://127.0.0.1:${server.address().port}`,
      expectedNodeId: 'target-node',
    });
    assert.equal(result.ok, true);
    assert.equal(result.bytes, 128 * 1024);
    assert.ok(result.latencyMs >= 0);
    assert.ok(result.latencyP95Ms >= result.latencyMinMs);
    assert.ok(result.bandwidthMbps > 0);
  } finally {
    server.close();
    await once(server, 'close');
  }
});
