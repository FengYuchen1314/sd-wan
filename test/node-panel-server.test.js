import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { hashPanelPassword } from '../src/core/password.js';

async function availablePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

async function waitForHealth(baseUrl, child) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`节点服务提前退出：${child.exitCode}`);
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  }
  throw new Error('等待节点服务启动超时');
}

function jsonHeaders(credential) {
  return { 'Content-Type': 'application/json', ...(credential ? { Authorization: `Bearer ${credential}` } : {}) };
}

test('配置节点使用安装密码登录，并接受已注册节点的面板实时代理', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'pathweaver-node-panel-'));
  const port = await availablePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const password = 'coordinator-panel-password';
  const child = spawn(process.execPath, [resolve('src/center/server.js')], {
    cwd: resolve('.'),
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NODE_ENV: 'production',
      SDWAN_HOST: '127.0.0.1',
      SDWAN_PORT: String(port),
      SDWAN_PUBLIC_URL: baseUrl,
      SDWAN_DATA_DIR: dataDir,
      SDWAN_PANEL_PASSWORD_HASH: hashPanelPassword(password),
      SDWAN_RUNTIME_SWEEP_INTERVAL_MS: '100',
      NODE_NO_WARNINGS: '1',
    },
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  try {
    await waitForHealth(baseUrl, child);
    const denied = await fetch(`${baseUrl}/api/v1/dashboard`, { headers: jsonHeaders('wrong-password') });
    assert.equal(denied.status, 401);

    const dashboardResponse = await fetch(`${baseUrl}/api/v1/dashboard`, { headers: jsonHeaders(password) });
    assert.equal(dashboardResponse.status, 200);
    const dashboard = await dashboardResponse.json();
    const networkId = dashboard.networks[0].id;
    const topology = await fetch(`${baseUrl}/api/v1/networks/${networkId}/topology`, {
      headers: jsonHeaders(password),
    }).then((response) => response.json());
    assert.equal(topology.nodes[0].name, '初始节点');

    const enrollment = await fetch(`${baseUrl}/api/v1/networks/${networkId}/join-tokens`, {
      method: 'POST',
      headers: jsonHeaders(password),
      body: JSON.stringify({ parentId: topology.nodes[0].id }),
    }).then((response) => response.json());
    const registered = await fetch(`${baseUrl}/agent/v1/register`, {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({ token: enrollment.token, name: '面板代理节点', wgDataPublicKey: 'a'.repeat(44) }),
    }).then((response) => response.json());

    const proxyResponse = await fetch(`${baseUrl}/agent/v1/panel-proxy`, {
      method: 'POST',
      headers: jsonHeaders(registered.credential),
      body: JSON.stringify({ method: 'GET', path: '/api/v1/dashboard', body: '' }),
    });
    assert.equal(proxyResponse.status, 200);
    const envelope = await proxyResponse.json();
    assert.equal(envelope.status, 200);
    assert.equal(JSON.parse(Buffer.from(envelope.body, 'base64').toString('utf8')).networks[0].id, networkId);

    const installerResponse = await fetch(`${baseUrl}/install.sh?source=${encodeURIComponent('http://edge.example/$(touch injected)')}`);
    assert.equal(installerResponse.status, 200);
    const installer = await installerResponse.text();
    assert.match(installer, /SOURCE="http:\/\/edge\.example"/);
    assert.doesNotMatch(installer, /touch injected/);
  } finally {
    const exitPromise = child.exitCode === null ? once(child, 'exit') : Promise.resolve();
    child.kill();
    await exitPromise.catch(() => {});
    rmSync(dataDir, { recursive: true, force: true });
    assert.equal(stderr, '');
  }
});
