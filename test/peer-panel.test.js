import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { hashPanelPassword } from '../src/core/password.js';

async function availablePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPanel(url, child) {
  let lastError;
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`面板进程提前退出：${child.exitCode}`);
    try {
      const response = await fetch(`${url}/healthz`);
      if (response.ok) return;
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw lastError || new Error('等待面板启动超时');
}

test('每个节点的本机面板校验安装密码并通过 Agent 实时访问统一配置', async () => {
  const proxyToken = 'local-panel-proxy-token';
  const fakeAgent = createServer(async (req, res) => {
    assert.equal(req.url, '/peer/v1/panel-proxy');
    assert.equal(req.headers.authorization, `Bearer ${proxyToken}`);
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert.equal(input.method, 'GET');
    assert.equal(input.path, '/api/v1/dashboard');
    const payload = Buffer.from(JSON.stringify({ networks: [{ id: 'shared-network' }], synchronized: true }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 200, contentType: 'application/json; charset=utf-8', body: payload.toString('base64') }));
  });
  fakeAgent.listen(0, '127.0.0.1');
  await once(fakeAgent, 'listening');
  const panelPort = await availablePort();
  const agentPort = fakeAgent.address().port;
  const panelUrl = `http://127.0.0.1:${panelPort}`;
  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/peer/server.js', import.meta.url))], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NODE_ENV: 'production',
      SDWAN_PANEL_HOST: '127.0.0.1',
      SDWAN_PANEL_PORT: String(panelPort),
      SDWAN_AGENT_RELAY_URL: `http://127.0.0.1:${agentPort}`,
      SDWAN_PANEL_PASSWORD_HASH: hashPanelPassword('node-panel-password'),
      SDWAN_PANEL_PROXY_TOKEN: proxyToken,
    },
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  try {
    await waitForPanel(panelUrl, child);
    const denied = await fetch(`${panelUrl}/api/v1/dashboard`, { headers: { Authorization: 'Bearer wrong-password' } });
    assert.equal(denied.status, 401);

    const response = await fetch(`${panelUrl}/api/v1/dashboard`, {
      headers: { Authorization: 'Bearer node-panel-password' },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { networks: [{ id: 'shared-network' }], synchronized: true });

    const status = await fetch(`${panelUrl}/api/v1/panel-status`, {
      headers: { Authorization: 'Bearer node-panel-password' },
    });
    assert.equal((await status.json()).syncMode, 'quorum-replicated-control-proxy');
  } finally {
    const exitPromise = child.exitCode === null ? once(child, 'exit') : Promise.resolve();
    child.kill();
    await exitPromise.catch(() => {});
    await new Promise((resolve) => fakeAgent.close(resolve));
    assert.equal(stderr, '');
  }
});
