import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

function seedAgentState(directory, input) {
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'state.json'), JSON.stringify({
    schemaVersion: 1,
    name: input.name,
    nodeId: input.nodeId,
    networkId: input.networkId,
    credential: input.credential,
    upstream: input.upstream,
    controlListenPort: input.relayPort,
    dataListenPort: input.dataPort,
    controlEndpoint: `http://127.0.0.1:${input.relayPort}`,
    dataEndpoint: `127.0.0.1:${input.dataPort}`,
    reachabilityType: 'public',
    hasPublicEndpoint: true,
    controlKeys: input.keys.control,
    dataKeys: input.keys.data,
    currentVersion: 0,
    preparedVersion: 0,
    managedChildren: {},
  }));
}

async function registerPublicEdge({
  centerUrl, networkId, parentId, name, relayPort, dataPort, directory, upstreamUrl, keys,
}) {
  const token = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/join-tokens`, {
    method: 'POST',
    body: JSON.stringify({ parentId, mode: 'passive' }),
  });
  const registered = await fetch(`${centerUrl}/agent/v1/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: token.token,
      passive: true,
      name,
      controlEndpoint: `http://127.0.0.1:${relayPort}`,
      controlListenPort: relayPort,
      dataEndpoint: `127.0.0.1:${dataPort}`,
      dataListenPort: dataPort,
      wgControlPublicKey: keys.control.publicKey,
      wgDataPublicKey: keys.data.publicKey,
    }),
  }).then(async (response) => {
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    return body;
  });
  seedAgentState(directory, {
    name,
    nodeId: registered.node.id,
    networkId,
    credential: registered.credential,
    upstream: upstreamUrl,
    relayPort,
    dataPort,
    keys,
  });
  return registered.node;
}

test('三节点在初始协调节点失联后由其余选民自动接管', { timeout: 60_000 }, async () => {
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
        SDWAN_ADMIN_TOKEN: 'dev-admin-token',
      },
    });
    processes.push(center);
    await waitFor(async () => (await fetch(`${centerUrl}/healthz`).catch(() => null))?.ok, '初始协调服务启动');
    const dashboard = await requestJson(`${centerUrl}/api/v1/dashboard`);
    const networkId = dashboard.networks[0].id;
    let topology = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/topology`);
    const initialId = topology.nodes[0].id;

    const keysB = {
      control: { privateKey: `${'a'.repeat(43)}=`, publicKey: `${'A'.repeat(43)}=` },
      data: { privateKey: `${'b'.repeat(43)}=`, publicKey: `${'B'.repeat(43)}=` },
    };
    const nodeB = await registerPublicEdge({
      centerUrl,
      networkId,
      parentId: initialId,
      name: '选民-B',
      relayPort: edgeBPort,
      dataPort: edgeBDataPort,
      directory: edgeBDirectory,
      upstreamUrl: centerUrl,
      keys: keysB,
    });
    const edgeB = spawn(process.execPath, [resolve('src/agent/agent.js'),
      '--name', '选民-B', '--upstream', centerUrl,
      '--relay-port', String(edgeBPort), '--data-port', String(edgeBDataPort),
      '--control-endpoint', `http://127.0.0.1:${edgeBPort}`,
      '--data-endpoint', `127.0.0.1:${edgeBDataPort}`,
    ], { cwd: resolve('.'), stdio: 'ignore', env: { ...commonEnvironment, SDWAN_AGENT_DATA_DIR: edgeBDirectory } });
    processes.push(edgeB);
    await waitFor(async () => {
      topology = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/topology`);
      return topology.nodes.find((node) => node.id === nodeB.id);
    }, '第二节点注册');
    await waitFor(async () => {
      const result = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/configurations`);
      return result.configurations[0]?.status === 'active';
    }, '双节点配置激活');

    const edgeBUrl = `http://127.0.0.1:${edgeBPort}`;
    const relayedInstallerResponse = await fetch(
      `${edgeBUrl}/install.sh?source=${encodeURIComponent(edgeBUrl)}`,
    );
    assert.equal(relayedInstallerResponse.status, 200);
    const relayedInstaller = await relayedInstallerResponse.text();
    assert.ok(relayedInstaller.includes(`SOURCE="${edgeBUrl}"`));

    const keysC = {
      control: { privateKey: `${'c'.repeat(43)}=`, publicKey: `${'C'.repeat(43)}=` },
      data: { privateKey: `${'d'.repeat(43)}=`, publicKey: `${'D'.repeat(43)}=` },
    };
    const nodeC = await registerPublicEdge({
      centerUrl,
      networkId,
      parentId: nodeB.id,
      name: '选民-C',
      relayPort: edgeCPort,
      dataPort: edgeCDataPort,
      directory: edgeCDirectory,
      upstreamUrl: edgeBUrl,
      keys: keysC,
    });
    const edgeC = spawn(process.execPath, [resolve('src/agent/agent.js'),
      '--name', '选民-C', '--upstream', edgeBUrl,
      '--relay-port', String(edgeCPort), '--data-port', String(edgeCDataPort),
      '--control-endpoint', `http://127.0.0.1:${edgeCPort}`,
      '--data-endpoint', `127.0.0.1:${edgeCDataPort}`,
    ], { cwd: resolve('.'), stdio: 'ignore', env: { ...commonEnvironment, SDWAN_AGENT_DATA_DIR: edgeCDirectory } });
    processes.push(edgeC);
    await waitFor(async () => {
      topology = await requestJson(`${centerUrl}/api/v1/networks/${networkId}/topology`);
      return topology.nodes.find((node) => node.id === nodeC.id);
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
    }, '选民选出并启动新协调节点', 20_000);
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
