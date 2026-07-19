import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const reservedPorts = new Set();

async function availablePort() {
  while (true) {
    const server = createServer();
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const port = server.address().port;
    await new Promise((resolveClose) => server.close(resolveClose));
    if (!reservedPorts.has(port)) {
      reservedPorts.add(port);
      return port;
    }
  }
}

async function waitFor(check, label, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) { lastError = error; }
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error(`${label}未在预期时间内完成${lastError ? `：${lastError.message}` : ''}`);
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer dev-admin-token',
      ...(options.headers || {}),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function readState(directory) {
  const filename = join(directory, 'state.json');
  return existsSync(filename) ? JSON.parse(readFileSync(filename, 'utf8')) : null;
}

test('三节点在初始协调节点失联后由最新副本多数派自动接管', { timeout: 30_000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'pathweaver-election-'));
  const centerDirectory = join(root, 'center');
  const edgeBDirectory = join(root, 'edge-b');
  const edgeCDirectory = join(root, 'edge-c');
  const centerPort = await availablePort();
  const edgeBPort = await availablePort();
  const edgeCPort = await availablePort();
  const edgeBDataPort = await availablePort();
  const edgeCDataPort = await availablePort();
  const centerUrl = `http://127.0.0.1:${centerPort}`;
  const processes = [];
  let center;
  try {
    const commonEnvironment = {
      ...process.env,
      NODE_NO_WARNINGS: '1',
      SDWAN_COORDINATOR_LEASE_MS: '1000',
      SDWAN_COORDINATOR_HEARTBEAT_INTERVAL_MS: '250',
      SDWAN_POLL_INTERVAL: '100',
      SDWAN_RUNTIME_SWEEP_INTERVAL_MS: '100',
    };
    center = spawn(process.execPath, [resolve('src/center/server.js')], {
      cwd: resolve('.'),
      stdio: 'ignore',
      env: {
        ...commonEnvironment,
        SDWAN_HOST: '127.0.0.1',
        SDWAN_PORT: String(centerPort),
        SDWAN_PUBLIC_URL: centerUrl,
        SDWAN_DATA_DIR: centerDirectory,
      },
    });
    processes.push(center);
    await waitFor(async () => (await fetch(`${centerUrl}/healthz`).catch(() => null))?.ok, '初始协调服务启动');
    const dashboard = await requestJson(`${centerUrl}/api/v1/dashboard`);
    const networkId = dashboard.networks[0].id;
    let topology = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/topology`);
    const initialId = topology.nodes[0].id;

    const tokenB = await waitFor(() => requestJson(`${centerUrl}/api/v1/networks/${networkId}/join-tokens`, {
      method: 'POST', body: JSON.stringify({ parentId: initialId }),
    }), '第二节点加入令牌');
    const edgeB = spawn(process.execPath, [resolve('src/agent/agent.js'),
      '--name', '选民-B', '--upstream', centerUrl, '--join-token', tokenB.token,
      '--relay-port', String(edgeBPort), '--data-port', String(edgeBDataPort),
      '--control-endpoint', `http://127.0.0.1:${edgeBPort}`,
      '--data-endpoint', `127.0.0.1:${edgeBDataPort}`,
    ], { cwd: resolve('.'), stdio: 'ignore', env: { ...commonEnvironment, SDWAN_AGENT_DATA_DIR: edgeBDirectory } });
    processes.push(edgeB);
    const nodeB = await waitFor(async () => {
      topology = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/topology`);
      return topology.nodes.find((node) => node.name === '选民-B');
    }, '第二节点注册');
    await waitFor(async () => {
      const result = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/configurations`);
      return result.configurations[0]?.status === 'active';
    }, '双节点配置激活');

    const tokenC = await waitFor(() => requestJson(`${centerUrl}/api/v1/networks/${networkId}/join-tokens`, {
      method: 'POST', body: JSON.stringify({ parentId: nodeB.id }),
    }), '第三节点加入令牌');
    const edgeC = spawn(process.execPath, [resolve('src/agent/agent.js'),
      '--name', '选民-C', '--upstream', `http://127.0.0.1:${edgeBPort}`, '--join-token', tokenC.token,
      '--relay-port', String(edgeCPort), '--data-port', String(edgeCDataPort),
      '--control-endpoint', `http://127.0.0.1:${edgeCPort}`,
      '--data-endpoint', `127.0.0.1:${edgeCDataPort}`,
    ], { cwd: resolve('.'), stdio: 'ignore', env: { ...commonEnvironment, SDWAN_AGENT_DATA_DIR: edgeCDirectory } });
    processes.push(edgeC);
    await waitFor(async () => {
      topology = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/topology`);
      return topology.nodes.find((node) => node.name === '选民-C');
    }, '第三节点经父节点注册');
    await waitFor(async () => {
      const result = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/configurations`);
      return result.configurations[0]?.status === 'active' && existsSync(join(edgeBDirectory, 'coordinator-replica.json')) && existsSync(join(edgeCDirectory, 'coordinator-replica.json'));
    }, '三节点配置和协调副本同步');

    center.kill();
    await once(center, 'exit');
    const elected = await waitFor(async () => {
      const states = [readState(edgeBDirectory), readState(edgeCDirectory)].filter(Boolean);
      const winner = states.find((state) =>
        state.nodeId && state.coordinatorElection?.leaderId === state.nodeId && Number(state.coordinatorPort) > 0);
      if (!winner) return null;
      const health = await fetch(`http://127.0.0.1:${winner.coordinatorPort}/healthz`).catch(() => null);
      return health?.ok ? { winner, states } : null;
    }, '多数派选出并启动新协调节点', 12_000);
    assert.notEqual(elected.winner.nodeId, initialId);
    assert.equal(elected.winner.coordinatorElection.term > 1, true);
    await waitFor(() => {
      const states = [readState(edgeBDirectory), readState(edgeCDirectory)].filter(Boolean);
      const following = states.length === 2 && states.every((state) => state.coordinatorElection?.leaderId === elected.winner.nodeId);
      if (!following) throw new Error(JSON.stringify(states.map((state) => ({
        nodeId: state.nodeId,
        election: state.coordinatorElection,
        cluster: state.controlCluster,
      }))));
      return true;
    }, '其余选民跟随新协调节点');
  } finally {
    for (const processHandle of processes.reverse()) {
      if (processHandle.exitCode === null) processHandle.kill();
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 500));
    rmSync(root, { recursive: true, force: true });
  }
});
