import test from 'node:test';
import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import {
  acceptProbeEnvelope,
  extendRelayTrace,
  selectAvailableTcpPort,
  selectAvailableUdpPort,
} from '../src/agent/runtime.js';

test('Agent 从首选端口向后选择可用 UDP 端口，并严格拒绝被占用的手动端口', async () => {
  const occupiedSocket = createSocket('udp4');
  await new Promise((resolve, reject) => {
    occupiedSocket.once('error', reject);
    occupiedSocket.bind({ port: 0, address: '127.0.0.1', exclusive: true }, resolve);
  });
  const occupiedPort = occupiedSocket.address().port;
  try {
    await assert.rejects(
      selectAvailableUdpPort({ preferred: occupiedPort, strict: true, host: '127.0.0.1' }),
      /已被占用或不可用/,
    );
    const selected = await selectAvailableUdpPort({
      preferred: occupiedPort,
      host: '127.0.0.1',
      searchSpan: 128,
    });
    assert.ok(selected > occupiedPort);
  } finally {
    occupiedSocket.close();
  }
});

test('Agent 控制中继端口同样支持自动选择和严格占用检查', async () => {
  const occupiedServer = (await import('node:net')).createServer();
  await new Promise((resolve, reject) => {
    occupiedServer.once('error', reject);
    occupiedServer.listen({ port: 0, host: '127.0.0.1', exclusive: true }, resolve);
  });
  const occupiedPort = occupiedServer.address().port;
  try {
    await assert.rejects(
      selectAvailableTcpPort({ preferred: occupiedPort, strict: true, host: '127.0.0.1' }),
      /已被占用或不可用/,
    );
    const selected = await selectAvailableTcpPort({ preferred: occupiedPort, host: '127.0.0.1', searchSpan: 128 });
    assert.ok(selected > occupiedPort);
  } finally {
    occupiedServer.close();
  }
});

test('链路探测和控制中继都用轨迹与跳数上限阻断环路', () => {
  const accepted = acceptProbeEnvelope({
    probeId: 'probe-1',
    trace: ['node-a'],
    remainingHops: 4,
  }, 'node-b');
  assert.deepEqual(accepted.trace, ['node-a', 'node-b']);
  assert.equal(accepted.remainingHops, 3);
  assert.throws(() => acceptProbeEnvelope({
    probeId: 'probe-loop',
    trace: ['node-a', 'node-b'],
    remainingHops: 3,
  }, 'node-a'), /探测环路/);
  assert.throws(() => acceptProbeEnvelope({
    probeId: 'probe-limit',
    trace: ['node-a'],
    remainingHops: 0,
  }, 'node-b'), /跳数/);
  assert.equal(extendRelayTrace('node-a,node-b', 'node-c'), 'node-a,node-b,node-c');
  assert.throws(() => extendRelayTrace('node-a,node-b', 'node-a'), /中继环路/);
});
