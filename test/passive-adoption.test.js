import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Database } from '../src/center/database.js';
import { CenterManagedNodes } from '../src/center/managed-nodes.js';
import { ControlService } from '../src/center/service.js';

async function availableTcpPort() {
  const server = createServer();
  await new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const port = server.address().port;
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

async function availableUdpPort() {
  const socket = createSocket('udp4');
  await new Promise((resolveBind, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', resolveBind);
  });
  const port = socket.address().port;
  await new Promise((resolveClose) => socket.close(resolveClose));
  return port;
}

async function waitForHealth(url) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(`${url}/healthz`);
      if (response.ok) return await response.json();
    } catch {}
    await delay(50);
  }
  throw new Error('被动 Agent 未在预期时间内启动');
}

async function waitFor(check, label) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await check();
    if (result) return result;
    await delay(50);
  }
  throw new Error(`${label}未在预期时间内完成`);
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
}

async function startAgentApi(service) {
  const server = createHttpServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const send = (status, body) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(body === undefined || body === null ? '' : JSON.stringify(body));
    };
    try {
      if (req.method === 'POST' && url.pathname === '/agent/v1/register') {
        return send(201, service.registerAgent(await readJson(req)));
      }
      const credential = String(req.headers.authorization || '').replace(/^Bearer /, '');
      const node = service.authenticateAgent(credential);
      if (!node) return send(401, { error: '节点凭据无效' });
      if (req.method === 'POST' && url.pathname === '/agent/v1/heartbeat') {
        return send(200, service.heartbeat(node.id, await readJson(req)));
      }
      if (req.method === 'GET' && url.pathname === '/agent/v1/config') {
        const desired = service.getDesiredConfig(node.id, Number(url.searchParams.get('currentVersion') || 0));
        return desired ? send(200, desired) : send(204);
      }
      const report = url.pathname.match(/^\/agent\/v1\/config\/([^/]+)\/report$/);
      if (req.method === 'POST' && report) {
        const input = await readJson(req);
        return send(200, service.reportConfig(node.id, report[1], input.phase, input.error));
      }
      if (req.method === 'GET' && url.pathname === '/agent/v1/commands/next') {
        const command = service.claimCommand(node.id);
        return command ? send(200, command) : send(204);
      }
      const complete = url.pathname.match(/^\/agent\/v1\/commands\/([^/]+)\/complete$/);
      if (req.method === 'POST' && complete) {
        return send(200, service.completeCommand(node.id, complete[1], await readJson(req)));
      }
      return send(404, { error: '接口不存在' });
    } catch (error) {
      return send(400, { error: error.message });
    }
  });
  await new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

test('认领登记成功后即使目标确认暂时失败也返回成功并保留后台代理', async () => {
  const database = new Database(':memory:');
  let targetServer;
  try {
    const service = new ControlService(database, { publicUrl: 'http://center.example:8787' });
    const network = service.createNetwork({
      name: '认领确认恢复测试', dataCidr: '10.122.0.0/24', controlCidr: '10.123.0.0/24', listenPort: 19801, mtu: 1380,
    });
    const center = service.listNodes(network.id)[0];
    const token = service.createJoinToken(network.id, { parentId: center.id, mode: 'passive' });
    targetServer = createHttpServer(async (req, res) => {
      if (req.method === 'POST' && req.url === '/agent/v1/adopt') {
        await readJson(req);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          ok: true,
          agent: {
            name: '确认暂时失败的节点',
            agentVersion: '0.1.0',
            wgControlPublicKey: 'c'.repeat(44),
            wgDataPublicKey: 'd'.repeat(44),
            controlListenPort: 8790,
            dataListenPort: 19801,
          },
        }));
      }
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: '模拟目标确认响应丢失' }));
    });
    await new Promise((resolveListen, reject) => {
      targetServer.once('error', reject);
      targetServer.listen(0, '127.0.0.1', resolveListen);
    });
    const targetUrl = `http://127.0.0.1:${targetServer.address().port}`;
    const manager = new CenterManagedNodes(service);
    const result = await manager.adopt(center.id, { targetUrl, claimToken: token.token });
    assert.equal(result.ok, true);
    assert.equal(result.targetConfirmationPending, true);
    assert.match(result.warning, /后台重试/);
    assert.equal(service.listNodes(network.id).some((node) => node.id === result.node.id), true);
    assert.equal(manager.proxies().some((proxy) => proxy.nodeId === result.node.id), true);
  } finally {
    if (targetServer) await new Promise((resolveClose) => targetServer.close(resolveClose));
    database.close();
  }
});

test('严格单向认领由中心主动连接目标并代理配置，目标不会反向设置上游', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'pathweaver-passive-'));
  const database = new Database(':memory:');
  const relayPort = await availableTcpPort();
  const dataPort = await availableUdpPort();
  const panelProxyToken = 'passive-panel-proxy-token';
  let processHandle;
  let descendantProcess;
  try {
    const service = new ControlService(database, { publicUrl: 'http://center.example:8787' });
    const network = service.createNetwork({
      name: '单向认领测试', dataCidr: '10.120.0.0/24', controlCidr: '10.121.0.0/24', listenPort: 19801, mtu: 1380,
    });
    const center = service.listNodes(network.id)[0];
    const token = service.createJoinToken(network.id, { parentId: center.id, mode: 'passive' });
    const targetUrl = `http://127.0.0.1:${relayPort}`;
    processHandle = spawn(process.execPath, [
      resolve('src/agent/agent.js'),
      '--claim-token', token.token,
      '--relay-port', String(relayPort),
      '--data-port', String(dataPort),
      '--control-endpoint', targetUrl,
      '--data-endpoint', `127.0.0.1:${dataPort}`,
      '--panel-proxy-token', panelProxyToken,
      '--listen',
    ], {
      cwd: resolve('.'),
      env: { ...process.env, SDWAN_AGENT_DATA_DIR: directory, SDWAN_POLL_INTERVAL: '100' },
      stdio: 'ignore',
    });
    await waitForHealth(targetUrl);

    const manager = new CenterManagedNodes(service, {
      panelProxy: async (input) => ({
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: Buffer.from(JSON.stringify({ path: input.path, synchronized: true })).toString('base64'),
      }),
    });
    const adopted = await manager.adopt(center.id, { targetUrl, claimToken: token.token });
    assert.equal(adopted.node.parentId, center.id);
    assert.equal(adopted.node.controlEndpoint, targetUrl);
    assert.equal(adopted.node.dataEndpoint, `127.0.0.1:${dataPort}`);

    const stateAfterAdoption = JSON.parse(readFileSync(join(directory, 'state.json'), 'utf8'));
    assert.equal(stateAfterAdoption.upstream, null);
    assert.equal(stateAfterAdoption.credential, undefined);
    assert.equal(stateAfterAdoption.managedByParent, true);
    assert.equal(stateAfterAdoption.nodeId, adopted.node.id);

    await manager.tick();
    assert.equal(service.getConfiguration(adopted.versionId).status, 'activating');
    await manager.tick();
    assert.equal(service.getConfiguration(adopted.versionId).status, 'active');
    const activeState = JSON.parse(readFileSync(join(directory, 'state.json'), 'utf8'));
    assert.equal(activeState.currentVersion > 0, true);

    const panelResponsePromise = fetch(`${targetUrl}/peer/v1/panel-proxy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${panelProxyToken}` },
      body: JSON.stringify({ method: 'GET', path: '/api/v1/dashboard', body: '' }),
    });
    await delay(25);
    await manager.tick();
    const panelResponse = await panelResponsePromise;
    assert.equal(panelResponse.status, 200);
    const panelEnvelope = await panelResponse.json();
    assert.deepEqual(JSON.parse(Buffer.from(panelEnvelope.body, 'base64').toString('utf8')), {
      path: '/api/v1/dashboard', synchronized: true,
    });

    const link = service.listLinks(network.id, true).find((item) => item.downstreamId === adopted.node.id);
    assert.equal(link.upstreamEndpoint, '');
    assert.equal(link.downstreamEndpoint, `127.0.0.1:${dataPort}`);
    const childConfig = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?', adopted.versionId, adopted.node.id,
    );
    assert.equal(JSON.parse(childConfig.config_json).data.peers[0].endpoint, null);
    assert.equal(JSON.parse(childConfig.config_json).data.peers[0].endpointMode, 'dynamic-learn');

    const descendantDirectory = join(directory, 'descendant-agent');
    const descendantRelayPort = await availableTcpPort();
    const descendantDataPort = await availableUdpPort();
    const descendantToken = service.createJoinToken(network.id, { parentId: adopted.node.id, mode: 'passive' });
    const descendantUrl = `http://127.0.0.1:${descendantRelayPort}`;
    descendantProcess = spawn(process.execPath, [
      resolve('src/agent/agent.js'),
      '--name', '中心二级被动节点',
      '--claim-token', descendantToken.token,
      '--relay-port', String(descendantRelayPort),
      '--data-port', String(descendantDataPort),
      '--control-endpoint', descendantUrl,
      '--data-endpoint', `127.0.0.1:${descendantDataPort}`,
      '--listen',
    ], {
      cwd: resolve('.'),
      env: { ...process.env, SDWAN_AGENT_DATA_DIR: descendantDirectory, SDWAN_POLL_INTERVAL: '100' },
      stdio: 'ignore',
    });
    await waitForHealth(descendantUrl);
    service.enqueueCommand(adopted.node.id, 'adopt-node', {
      targetUrl: descendantUrl,
      claimToken: descendantToken.token,
    });
    const descendant = await waitFor(async () => {
      await manager.tick();
      return service.listNodes(network.id).find((node) => node.name === '中心二级被动节点');
    }, '中心二级被动节点认领');
    await waitFor(async () => {
      await manager.tick();
      return service.listConfigurations(network.id)[0]?.status === 'active';
    }, '中心二级代理配置激活');
    assert.deepEqual(manager.proxies().find((proxy) => proxy.nodeId === descendant.id).relayPath, [adopted.node.id]);
    assert.equal(JSON.parse(readFileSync(join(descendantDirectory, 'state.json'), 'utf8')).upstream, null);
  } finally {
    if (processHandle && !processHandle.killed) processHandle.kill();
    if (descendantProcess && !descendantProcess.killed) descendantProcess.kill();
    database.close();
    await delay(50);
    rmSync(directory, { recursive: true, force: true });
  }
});

test('普通边缘父节点可代理严格单向子节点的注册、心跳和配置发布', async () => {
  const root = mkdtempSync(join(tmpdir(), 'pathweaver-edge-proxy-'));
  const parentDirectory = join(root, 'parent');
  const targetDirectory = join(root, 'target');
  const descendantDirectory = join(root, 'descendant');
  const database = new Database(':memory:');
  const processes = [];
  let apiServer;
  try {
    const service = new ControlService(database, { publicUrl: 'http://center.example:8787' });
    const network = service.createNetwork({
      name: '边缘代理测试', dataCidr: '10.130.0.0/24', controlCidr: '10.131.0.0/24', listenPort: 19801, mtu: 1380,
    });
    const center = service.listNodes(network.id)[0];
    const apiRuntime = await startAgentApi(service);
    apiServer = apiRuntime.server;

    const parentRelayPort = await availableTcpPort();
    const parentDataPort = await availableUdpPort();
    const parentUrl = `http://127.0.0.1:${parentRelayPort}`;
    const parentClaim = service.createJoinToken(network.id, { parentId: center.id, mode: 'passive' });
    const parentKeys = {
      control: { privateKey: `${'a'.repeat(43)}=`, publicKey: `${'A'.repeat(43)}=` },
      data: { privateKey: `${'b'.repeat(43)}=`, publicKey: `${'B'.repeat(43)}=` },
    };
    const parentRegistered = service.registerAgent({
      token: parentClaim.token,
      passive: true,
      name: '代理边缘节点',
      controlEndpoint: parentUrl,
      controlListenPort: parentRelayPort,
      dataEndpoint: `127.0.0.1:${parentDataPort}`,
      dataListenPort: parentDataPort,
      wgControlPublicKey: parentKeys.control.publicKey,
      wgDataPublicKey: parentKeys.data.publicKey,
    });
    const parent = parentRegistered.node;
    mkdirSync(parentDirectory, { recursive: true });
    writeFileSync(join(parentDirectory, 'state.json'), JSON.stringify({
      schemaVersion: 1,
      name: '代理边缘节点',
      nodeId: parent.id,
      networkId: network.id,
      credential: parentRegistered.credential,
      upstream: apiRuntime.url,
      controlListenPort: parentRelayPort,
      dataListenPort: parentDataPort,
      controlEndpoint: parentUrl,
      dataEndpoint: `127.0.0.1:${parentDataPort}`,
      reachabilityType: 'public',
      hasPublicEndpoint: true,
      controlKeys: parentKeys.control,
      dataKeys: parentKeys.data,
      currentVersion: 0,
      preparedVersion: 0,
      managedChildren: {},
    }));
    processes.push(spawn(process.execPath, [
      resolve('src/agent/agent.js'),
      '--name', '代理边缘节点',
      '--upstream', apiRuntime.url,
      '--relay-port', String(parentRelayPort),
      '--data-port', String(parentDataPort),
      '--control-endpoint', parentUrl,
      '--data-endpoint', `127.0.0.1:${parentDataPort}`,
    ], {
      cwd: resolve('.'),
      env: { ...process.env, SDWAN_AGENT_DATA_DIR: parentDirectory, SDWAN_POLL_INTERVAL: '100' },
      stdio: 'ignore',
    }));
    await waitForHealth(parentUrl);

    const targetRelayPort = await availableTcpPort();
    const targetDataPort = await availableUdpPort();
    const claim = service.createJoinToken(network.id, { parentId: parent.id, mode: 'passive' });
    const targetUrl = `http://127.0.0.1:${targetRelayPort}`;
    processes.push(spawn(process.execPath, [
      resolve('src/agent/agent.js'),
      '--name', '严格单向子节点',
      '--claim-token', claim.token,
      '--relay-port', String(targetRelayPort),
      '--data-port', String(targetDataPort),
      '--control-endpoint', targetUrl,
      '--data-endpoint', `127.0.0.1:${targetDataPort}`,
      '--listen',
    ], {
      cwd: resolve('.'),
      env: { ...process.env, SDWAN_AGENT_DATA_DIR: targetDirectory, SDWAN_POLL_INTERVAL: '100' },
      stdio: 'ignore',
    }));
    await waitForHealth(targetUrl);
    service.enqueueCommand(parent.id, 'adopt-node', { targetUrl, claimToken: claim.token });

    const target = await waitFor(
      () => service.listNodes(network.id).find((node) => node.name === '严格单向子节点'),
      '单向子节点认领',
    );
    await waitFor(
      () => service.listConfigurations(network.id)[0]?.status === 'active',
      '代理配置激活',
    );
    const targetState = JSON.parse(readFileSync(join(targetDirectory, 'state.json'), 'utf8'));
    const parentState = JSON.parse(readFileSync(join(parentDirectory, 'state.json'), 'utf8'));
    assert.equal(targetState.upstream, null);
    assert.equal(targetState.credential, undefined);
    assert.equal(targetState.currentVersion > 0, true);
    assert.equal(parentState.managedChildren[target.id].targetUrl, targetUrl);
    assert.equal(parentState.managedChildren[target.id].credential.startsWith('pwn_'), true);
    assert.equal(service.getNode(target.id).status, 'online');

    const descendantRelayPort = await availableTcpPort();
    const descendantDataPort = await availableUdpPort();
    const descendantClaim = service.createJoinToken(network.id, { parentId: target.id, mode: 'passive' });
    const descendantUrl = `http://127.0.0.1:${descendantRelayPort}`;
    processes.push(spawn(process.execPath, [
      resolve('src/agent/agent.js'),
      '--name', '二级单向子节点',
      '--claim-token', descendantClaim.token,
      '--relay-port', String(descendantRelayPort),
      '--data-port', String(descendantDataPort),
      '--control-endpoint', descendantUrl,
      '--data-endpoint', `127.0.0.1:${descendantDataPort}`,
      '--listen',
    ], {
      cwd: resolve('.'),
      env: { ...process.env, SDWAN_AGENT_DATA_DIR: descendantDirectory, SDWAN_POLL_INTERVAL: '100' },
      stdio: 'ignore',
    }));
    await waitForHealth(descendantUrl);
    service.enqueueCommand(target.id, 'adopt-node', { targetUrl: descendantUrl, claimToken: descendantClaim.token });
    const descendant = await waitFor(
      () => service.listNodes(network.id).find((node) => node.name === '二级单向子节点'),
      '二级单向子节点认领',
    );
    await waitFor(
      () => service.listConfigurations(network.id)[0]?.status === 'active',
      '二级代理配置激活',
    );
    const descendantState = JSON.parse(readFileSync(join(descendantDirectory, 'state.json'), 'utf8'));
    const refreshedTargetState = JSON.parse(readFileSync(join(targetDirectory, 'state.json'), 'utf8'));
    const refreshedParentState = JSON.parse(readFileSync(join(parentDirectory, 'state.json'), 'utf8'));
    assert.equal(descendantState.upstream, null);
    assert.equal(descendantState.currentVersion > 0, true);
    assert.equal(refreshedTargetState.managedChildren[descendant.id].targetUrl, descendantUrl);
    assert.deepEqual(refreshedParentState.managedChildren[descendant.id].relayPath, [target.id]);
  } finally {
    for (const child of processes) if (!child.killed) child.kill();
    if (apiServer) await new Promise((resolveClose) => apiServer.close(resolveClose));
    database.close();
    await delay(100);
    rmSync(root, { recursive: true, force: true });
  }
});
