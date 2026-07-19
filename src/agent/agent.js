import { createHash, generateKeyPairSync, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import {
  acceptProbeEnvelope,
  DEFAULT_DATA_PORT,
  extendRelayTrace,
  MAX_PROBE_HOPS,
  normalizeDataPort,
  selectAvailableTcpPort,
  selectAvailableUdpPort,
} from './runtime.js';
import { WireGuardManager } from './wireguard.js';

const args = parseArgs(process.argv.slice(2));
const dataDir = resolve(process.env.SDWAN_AGENT_DATA_DIR || (process.platform === 'linux' ? '/var/lib/pathweaver-agent' : './data/agent'));
const stateFile = join(dataDir, 'state.json');
const applyNetwork = process.env.SDWAN_APPLY_NETWORK === '1' && process.platform === 'linux';
const pollInterval = Number(process.env.SDWAN_POLL_INTERVAL || 5000);
mkdirSync(dataDir, { recursive: true });

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 1) {
    const current = values[index];
    if (!current.startsWith('--')) continue;
    const key = current.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    const next = values[index + 1];
    if (!next || next.startsWith('--')) result[key] = true;
    else {
      result[key] = next;
      index += 1;
    }
  }
  return result;
}

function atomicJson(filename, value) {
  const temporary = `${filename}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, filename);
}

function keyPair() {
  const pair = generateKeyPairSync('x25519');
  const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' });
  return {
    privateKey: privateDer.subarray(privateDer.length - 32).toString('base64'),
    publicKey: publicDer.subarray(publicDer.length - 32).toString('base64'),
  };
}

function loadState() {
  if (!existsSync(stateFile)) {
    return {
      schemaVersion: 1,
      name: args.name || hostname(),
      upstream: args.upstream || process.env.SDWAN_UPSTREAM || null,
      joinToken: args.joinToken || process.env.SDWAN_JOIN_TOKEN || null,
      claimTokenHash: args.claimToken ? createHash('sha256').update(args.claimToken).digest('hex') : null,
      controlKeys: keyPair(),
      dataKeys: keyPair(),
      currentVersion: 0,
      preparedVersion: 0,
    };
  }
  return JSON.parse(readFileSync(stateFile, 'utf8'));
}

let state = loadState();
const pendingPanelRequests = new Map();
state.agentInstanceId ||= `agent-${randomBytes(12).toString('hex')}`;
state.managedChildren ||= {};
if (args.panelProxyToken || process.env.SDWAN_PANEL_PROXY_TOKEN) {
  state.panelProxyTokenHash = createHash('sha256')
    .update(String(args.panelProxyToken || process.env.SDWAN_PANEL_PROXY_TOKEN))
    .digest('hex');
}
state.controlEndpoint ||= args.controlEndpoint || process.env.SDWAN_CONTROL_ENDPOINT || null;
state.dataEndpoint ||= args.dataEndpoint || process.env.SDWAN_DATA_ENDPOINT || null;
const explicitRelayPort = args.relayPort ?? process.env.SDWAN_RELAY_PORT;
if (explicitRelayPort !== undefined && explicitRelayPort !== null && explicitRelayPort !== '') {
  state.controlListenPort = await selectAvailableTcpPort({ preferred: explicitRelayPort, strict: true });
} else if (!state.controlListenPort) {
  state.controlListenPort = await selectAvailableTcpPort({ preferred: 8790 });
}
const explicitDataPort = args.dataPort ?? process.env.SDWAN_DATA_PORT;
if (explicitDataPort !== undefined && explicitDataPort !== null && explicitDataPort !== '') {
  const requestedPort = normalizeDataPort(explicitDataPort);
  if (state.dataListenPort !== requestedPort || !state.nodeId) {
    state.dataListenPort = await selectAvailableUdpPort({ preferred: requestedPort, strict: true });
  }
} else if (!state.dataListenPort) {
  state.dataListenPort = await selectAvailableUdpPort({ preferred: DEFAULT_DATA_PORT });
}
atomicJson(stateFile, state);
const listenAddress = process.env.SDWAN_AGENT_LISTEN || `0.0.0.0:${state.controlListenPort}`;

function safeEqualHash(token, expectedHash) {
  const actual = createHash('sha256').update(String(token ?? '')).digest();
  const expected = Buffer.from(String(expectedHash ?? ''), 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function bearerToken(req) {
  const authorization = String(req.headers.authorization || '');
  return authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
}

function requireParentSession(req) {
  if (!state.parentSessionHash || !safeEqualHash(bearerToken(req), state.parentSessionHash)) {
    const error = new Error('父节点管理会话无效');
    error.statusCode = 401;
    throw error;
  }
}

function requireLocalPanel(req) {
  const address = String(req.socket.remoteAddress || '');
  if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(address)) {
    const error = new Error('面板代理只接受本机请求');
    error.statusCode = 403;
    throw error;
  }
  if (!state.panelProxyTokenHash || !safeEqualHash(bearerToken(req), state.panelProxyTokenHash)) {
    const error = new Error('本机面板代理凭据无效');
    error.statusCode = 401;
    throw error;
  }
}

function shuffled(values) {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const other = randomInt(index + 1);
    [result[index], result[other]] = [result[other], result[index]];
  }
  return result;
}

function normalizeControlUrl(value) {
  const parsed = new URL(String(value || ''));
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('控制路径只支持 HTTP 或 HTTPS');
  parsed.pathname = '/';
  parsed.search = '';
  parsed.hash = '';
  return parsed.href.replace(/\/$/, '');
}

function decodeControlRoute(value) {
  if (!value) return [];
  let route;
  try { route = JSON.parse(Buffer.from(String(value), 'base64url').toString('utf8')); }
  catch { throw new Error('控制路径编码无效'); }
  if (!Array.isArray(route) || route.length > MAX_PROBE_HOPS) throw new Error('控制路径长度无效或超过上限');
  const seen = new Set();
  return route.map((hop) => {
    const nodeId = String(hop?.nodeId || '').trim();
    if (!nodeId || seen.has(nodeId)) throw new Error('控制路径包含空节点或环路');
    seen.add(nodeId);
    return { nodeId, url: normalizeControlUrl(hop.url) };
  });
}

function encodeControlRoute(route) {
  return Buffer.from(JSON.stringify(route), 'utf8').toString('base64url');
}

function controlCandidates() {
  const candidates = [];
  for (const route of shuffled(state.controlRoutes || [])) {
    if (!Array.isArray(route.hops) || !route.hops.length || route.hops.length > MAX_PROBE_HOPS) continue;
    if (new Set(route.nodeIds || []).size !== (route.nodeIds || []).length) continue;
    const [first, ...remaining] = route.hops;
    try {
      const firstUrl = normalizeControlUrl(first.url);
      if (state.controlForwarders?.[first.nodeId] !== firstUrl) continue;
      candidates.push({ id: route.id, baseUrl: firstUrl, remaining });
    } catch {}
  }
  if (state.upstream) {
    const fallback = normalizeControlUrl(state.upstream);
    if (!candidates.some((candidate) => candidate.baseUrl === fallback && candidate.remaining.length === 0)) {
      candidates.push({ id: 'initial-upstream', baseUrl: fallback, remaining: [] });
    }
  }
  return candidates;
}

async function api(pathname, options = {}) {
  const { credential = state.credential, timeout = 20_000, ...requestOptions } = options;
  const candidates = controlCandidates();
  if (!candidates.length) throw new Error('Agent 尚未设置可用的中心控制路径');
  const failures = [];
  const deadline = Date.now() + timeout;
  for (const candidate of candidates) {
    const remainingTime = deadline - Date.now();
    if (remainingTime <= 0) break;
    try {
      const headers = { 'Content-Type': 'application/json', ...(options.headers ?? {}) };
      if (credential) headers.Authorization = `Bearer ${credential}`;
      if (candidate.remaining.length) headers['X-PathWeaver-Control-Route'] = encodeControlRoute(candidate.remaining);
      if (state.nodeId || state.agentInstanceId) headers['X-PathWeaver-Relay-Trace'] = state.nodeId || state.agentInstanceId;
      const response = await fetch(new URL(pathname, `${candidate.baseUrl}/`), {
        ...requestOptions,
        headers,
        signal: AbortSignal.timeout(Math.max(250, Math.min(5_000, remainingTime))),
      });
      if (response.status === 204) return null;
      const contentType = response.headers.get('content-type') ?? '';
      const body = contentType.includes('json') ? await response.json() : await response.text();
      if (!response.ok) {
        if (response.status < 500) throw Object.assign(new Error(body?.error || `上游返回 HTTP ${response.status}`), { terminal: true });
        throw new Error(body?.error || `控制路径返回 HTTP ${response.status}`);
      }
      return body;
    } catch (error) {
      if (error.terminal) throw error;
      failures.push(`${candidate.id}: ${error.message}`);
    }
  }
  throw new Error(`所有无环控制路径均不可用：${failures.join('；')}`);
}

async function register({ passive = false } = {}) {
  if (state.credential || !state.joinToken || !state.upstream) return;
  const result = await api('/agent/v1/register', {
    method: 'POST',
    body: JSON.stringify({
      token: state.joinToken,
      passive,
      name: state.name,
      agentVersion: '0.1.0',
      wgControlPublicKey: state.controlKeys.publicKey,
      wgDataPublicKey: state.dataKeys.publicKey,
      controlEndpoint: state.controlEndpoint,
      controlListenPort: state.controlListenPort,
      dataEndpoint: state.dataEndpoint,
      dataListenPort: state.dataListenPort,
    }),
  });
  state = {
    ...state,
    nodeId: result.node.id,
    credential: result.credential,
    joinToken: null,
    networkId: result.node.networkId,
  };
  atomicJson(stateFile, state);
  console.log(`节点 ${result.node.name} 已注册，业务地址 ${result.node.dataIp}`);
}

const wireguard = new WireGuardManager({
  dataDir,
  privateKey: state.dataKeys.privateKey,
  applyNetwork,
});

async function applyDesiredConfig(desired) {
  if (!desired) return null;
  if (desired.phase === 'prepare' && state.preparedVersion !== desired.version) {
    try {
      await wireguard.prepare(desired.version, desired.config);
      state.preparedVersion = desired.version;
      atomicJson(stateFile, state);
      return { versionId: desired.versionId, phase: 'prepared' };
    } catch (error) {
      return { versionId: desired.versionId, phase: 'prepared', error: error.message };
    }
  }
  if (desired.phase === 'activate' && state.currentVersion !== desired.version) {
    try {
      if (state.preparedVersion !== desired.version) await wireguard.prepare(desired.version, desired.config);
      await wireguard.activate(desired.version);
      state.currentVersion = desired.version;
      state.preparedVersion = desired.version;
      state.controlRoutes = Array.isArray(desired.config?.control?.routes) ? desired.config.control.routes : [];
      state.controlForwarders = Object.fromEntries(Object.entries(desired.config?.control?.forwarders || {}).map(
        ([nodeId, url]) => [nodeId, normalizeControlUrl(url)],
      ));
      atomicJson(stateFile, state);
      return { versionId: desired.versionId, phase: 'activated' };
    } catch (error) {
      return { versionId: desired.versionId, phase: 'activated', error: error.message };
    }
  }
  return null;
}

async function syncConfig() {
  const desired = await api(`/agent/v1/config?currentVersion=${state.currentVersion}`);
  const report = await applyDesiredConfig(desired);
  if (report) {
    await api(`/agent/v1/config/${report.versionId}/report`, {
      method: 'POST', body: JSON.stringify({ phase: report.phase, error: report.error }),
    });
  }
}

async function requestManagedTarget(child, pathname, options = {}) {
  const url = new URL(pathname, `${child.targetUrl.replace(/\/$/, '')}/`);
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${child.sessionToken}`,
      ...(options.headers ?? {}),
    },
    signal: AbortSignal.timeout(options.timeout ?? 20_000),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `被认领节点返回 HTTP ${response.status}`);
  return body;
}

async function requestManagedChild(child, pathname, options = {}) {
  const route = Array.isArray(child.relayPath) ? child.relayPath : [];
  if (!route.length) return requestManagedTarget(child, pathname, options);
  const firstRelay = state.managedChildren[route[0]];
  if (!firstRelay || (firstRelay.relayPath?.length ?? 0) > 0) throw new Error('被认领节点的代理路径无效');
  return requestManagedTarget(firstRelay, '/agent/v1/managed/relay', {
    method: 'POST',
    timeout: options.timeout ?? 30_000,
    body: JSON.stringify({
      path: route.slice(1),
      childNodeId: child.nodeId,
      pathname,
      request: {
        method: options.method || 'GET',
        body: options.body,
        timeout: options.timeout,
      },
    }),
  });
}

async function beginTargetAdoption(payload) {
  const sessionToken = `pws_${randomBytes(32).toString('base64url')}`;
  const targetUrl = String(payload.targetUrl || '').replace(/\/$/, '');
  const response = await fetch(new URL('/agent/v1/adopt', `${targetUrl}/`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ claimToken: payload.claimToken, sessionToken }),
    signal: AbortSignal.timeout(20_000),
  });
  const descriptor = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(descriptor.error || `目标返回 HTTP ${response.status}`);
  const reachedTarget = new URL(`${targetUrl}/`);
  const reachedHost = reachedTarget.hostname.includes(':') ? `[${reachedTarget.hostname}]` : reachedTarget.hostname;
  descriptor.agent.controlEndpoint = targetUrl;
  descriptor.agent.controlListenPort = Number(reachedTarget.port || 80);
  descriptor.agent.dataEndpoint = `${reachedHost}:${descriptor.agent.dataListenPort}`;
  return { targetUrl, sessionToken, claimToken: payload.claimToken, agent: descriptor.agent };
}

async function finishLocalAdoption(context, registered, credential = null) {
  const child = {
    nodeId: registered.node.id,
    targetUrl: context.targetUrl,
    sessionToken: context.sessionToken,
    credential,
    node: registered.node,
    relayPath: [],
  };
  state.managedChildren[registered.node.id] = child;
  atomicJson(stateFile, state);
  await requestManagedTarget(child, '/agent/v1/adopt/complete', {
    method: 'POST',
    body: JSON.stringify({ node: registered.node }),
  });
  return child;
}

async function adoptTarget(payload) {
  const context = await beginTargetAdoption(payload);
  if (!state.upstream || !state.credential) {
    if (!state.managedByParent) throw new Error('当前节点没有可用的中心控制代理，不能完成认领');
    return { ok: true, delegatedAdoption: context };
  }
  const registered = await api('/agent/v1/register', {
    method: 'POST',
    credential: null,
    body: JSON.stringify({
      token: context.claimToken,
      passive: true,
      ...context.agent,
    }),
  });
  await finishLocalAdoption(context, registered, registered.credential);
  return { ok: true, nodeId: registered.node.id, node: registered.node };
}

async function runCommand(command) {
  let result;
  try {
    if (command.type === 'adopt-node') {
      result = await adoptTarget(command.payload);
    } else if (command.type === 'prepare-link-probe') {
      state.pendingLinkProbes = state.pendingLinkProbes || {};
      state.pendingLinkProbes[command.payload.validationId] = {
        tokenHash: createHash('sha256').update(command.payload.token).digest('hex'),
        expiresAt: command.payload.expiresAt,
      };
      atomicJson(stateFile, state);
      result = { ok: true, prepared: true };
    } else if (command.type === 'execute-link-probe') {
      const probeId = String(command.payload.probeId || `probe-${randomBytes(16).toString('hex')}`);
      const maxHops = Math.min(MAX_PROBE_HOPS, Math.max(1, Number(command.payload.maxHops) || MAX_PROBE_HOPS));
      const response = await fetch(
        new URL(`/agent/v1/link-probe/${command.payload.validationId}`, command.payload.remoteUrl),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: command.payload.token,
            probeId,
            trace: [state.nodeId || state.agentInstanceId],
            remainingHops: maxHops - 1,
          }),
          signal: AbortSignal.timeout(12_000),
        },
      );
      const probe = await response.json();
      if (!response.ok) throw new Error(probe.error || `探测返回 HTTP ${response.status}`);
      if (probe.nodeId !== command.payload.expectedNodeId) throw new Error('目标节点身份与预期不一致');
      result = {
        ok: true,
        probeId,
        remoteNodeId: probe.nodeId,
        trace: probe.trace,
        reachedAt: new Date().toISOString(),
      };
    } else if (command.type === 'probe') {
      result = { ok: true, nodeId: state.nodeId, time: new Date().toISOString() };
    } else {
      throw new Error(`不允许执行命令 ${command.type}`);
    }
  } catch (error) {
    result = { ok: false, error: error.message };
  }
  return result;
}

async function executeCommand(command) {
  const result = await runCommand(command);
  await api(`/agent/v1/commands/${command.id}/complete`, { method: 'POST', body: JSON.stringify(result) });
}

async function syncManagedChild(child) {
  const health = await requestManagedChild(child, '/healthz', { method: 'GET', timeout: 10_000 });
  const panelRequests = await requestManagedChild(child, '/agent/v1/managed/panel-requests', {
    method: 'GET', timeout: 10_000,
  }).catch(() => ({ requests: [] }));
  for (const request of panelRequests.requests ?? []) {
    let result;
    try {
      result = await api('/agent/v1/panel-proxy', {
        method: 'POST',
        credential: child.credential,
        body: JSON.stringify(request.input),
      });
    } catch (error) {
      const payload = Buffer.from(JSON.stringify({ error: error.message }), 'utf8').toString('base64');
      result = { status: error.statusCode || 502, contentType: 'application/json; charset=utf-8', body: payload };
    }
    await requestManagedChild(child, '/agent/v1/managed/panel-results', {
      method: 'POST',
      body: JSON.stringify({ id: request.id, result }),
      timeout: 10_000,
    });
  }
  await api('/agent/v1/heartbeat', {
    method: 'POST',
    credential: child.credential,
    body: JSON.stringify({
      agentVersion: child.node.agentVersion || '0.1.0',
      controlEndpoint: child.node.controlEndpoint,
      controlListenPort: child.node.controlListenPort,
      dataEndpoint: child.node.dataEndpoint,
      dataListenPort: child.node.dataListenPort,
      linkHealth: health.linkHealth,
    }),
  });
  const desired = await api(`/agent/v1/config?currentVersion=${Number(child.currentVersion || 0)}`, {
    credential: child.credential,
  });
  const command = await api('/agent/v1/commands/next', { credential: child.credential });
  const result = await requestManagedChild(child, '/agent/v1/managed/tick', {
    method: 'POST',
    body: JSON.stringify({ node: child.node, desired, command }),
    timeout: 30_000,
  });
  if (result.currentVersion !== undefined) {
    child.currentVersion = Number(result.currentVersion);
    atomicJson(stateFile, state);
  }
  if (result.configReport) {
    await api(`/agent/v1/config/${result.configReport.versionId}/report`, {
      method: 'POST',
      credential: child.credential,
      body: JSON.stringify({ phase: result.configReport.phase, error: result.configReport.error }),
    });
  }
  if (command && result.commandResult) {
    let commandResult = result.commandResult;
    if (commandResult.delegatedAdoption) {
      const context = commandResult.delegatedAdoption;
      const registered = await api('/agent/v1/register', {
        method: 'POST',
        credential: null,
        body: JSON.stringify({ token: context.claimToken, passive: true, ...context.agent }),
      });
      const descendant = {
        nodeId: registered.node.id,
        targetUrl: context.targetUrl,
        sessionToken: context.sessionToken,
        credential: registered.credential,
        node: registered.node,
        relayPath: [...(child.relayPath || []), child.nodeId],
      };
      state.managedChildren[registered.node.id] = descendant;
      atomicJson(stateFile, state);
      await requestManagedChild(child, '/agent/v1/managed/adoption-complete', {
        method: 'POST',
        body: JSON.stringify({ context, node: registered.node }),
      });
      commandResult = { ok: true, nodeId: registered.node.id, node: registered.node };
    }
    await api(`/agent/v1/commands/${command.id}/complete`, {
      method: 'POST',
      credential: child.credential,
      body: JSON.stringify(commandResult),
    });
  }
}

async function tick() {
  if (!state.credential) return;
  const linkHealth = await wireguard.linkHealth().catch((error) => ({
    available: false,
    checkedAt: new Date().toISOString(),
    error: error.message,
    links: [],
    failedLinkIds: [],
  }));
  await api('/agent/v1/heartbeat', {
    method: 'POST',
    body: JSON.stringify({
      agentVersion: '0.1.0',
      controlEndpoint: state.controlEndpoint,
      controlListenPort: state.controlListenPort,
      dataEndpoint: state.dataEndpoint,
      dataListenPort: state.dataListenPort,
      linkHealth,
    }),
  });
  await syncConfig();
  const command = await api('/agent/v1/commands/next');
  if (command) await executeCommand(command);
  for (const child of Object.values(state.managedChildren)) {
    await syncManagedChild(child).catch((error) => console.error(`被认领节点 ${child.nodeId} 同步失败：`, error.message));
  }
}

async function proxy(req, res) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const relayTrace = extendRelayTrace(
    req.headers['x-pathweaver-relay-trace'],
    state.nodeId || state.agentInstanceId,
  );
  const remaining = decodeControlRoute(req.headers['x-pathweaver-control-route']);
  let targetUrl = state.upstream ? normalizeControlUrl(state.upstream) : null;
  if (remaining.length) {
    const [next, ...rest] = remaining;
    const visited = new Set(relayTrace.split(',').filter(Boolean));
    if (visited.has(next.nodeId)) throw new Error('控制路径检测到重复节点，已阻断环路');
    const allowedUrl = state.controlForwarders?.[next.nodeId];
    if (!allowedUrl || normalizeControlUrl(next.url) !== allowedUrl) {
      throw new Error('控制路径下一跳不属于当前已验证邻接');
    }
    targetUrl = allowedUrl;
    remaining.splice(0, remaining.length, ...rest);
  }
  if (!targetUrl) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: '中继节点没有可用的下一跳控制路径' }));
  }
  const upstream = await fetch(new URL(req.url, `${targetUrl}/`), {
    method: req.method,
    headers: {
      ...(req.headers.authorization ? { Authorization: req.headers.authorization } : {}),
      ...(req.headers['content-type'] ? { 'Content-Type': req.headers['content-type'] } : {}),
      'X-PathWeaver-Relay-Trace': relayTrace,
      ...(remaining.length ? { 'X-PathWeaver-Control-Route': encodeControlRoute(remaining) } : {}),
    },
    body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks),
    signal: AbortSignal.timeout(30_000),
  });
  res.writeHead(upstream.status, {
    'Content-Type': upstream.headers.get('content-type') || 'application/octet-stream',
    'Cache-Control': upstream.headers.get('cache-control') || 'no-store',
  });
  res.end(Buffer.from(await upstream.arrayBuffer()));
}

const [listenHost, listenPortText] = listenAddress.split(':');
const relayServer = createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/healthz') {
      const linkHealth = await wireguard.linkHealth().catch((error) => ({
        available: false,
        checkedAt: new Date().toISOString(),
        error: error.message,
        links: [],
        failedLinkIds: [],
      }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'ok',
        nodeId: state.nodeId ?? null,
        controlListenPort: state.controlListenPort,
        dataListenPort: state.dataListenPort,
        wireGuardRuntime: wireguard.runtimeInfo(),
        linkHealth,
      }));
    }
    if (req.method === 'POST' && req.url === '/peer/v1/panel-proxy') {
      requireLocalPanel(req);
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const method = String(input.method || 'GET').toUpperCase();
      const parsedPath = new URL(String(input.path || ''), 'http://pathweaver.local');
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) || !parsedPath.pathname.startsWith('/api/v1/')) {
        throw new Error('面板代理请求方法或路径无效');
      }
      const request = {
        method,
        path: `${parsedPath.pathname}${parsedPath.search}`,
        contentType: String(input.contentType || 'application/json'),
        body: String(input.body || ''),
      };
      const result = state.managedByParent
        ? await new Promise((resolve, reject) => {
          const id = `panel-${randomBytes(12).toString('hex')}`;
          const timeout = setTimeout(() => {
            pendingPanelRequests.delete(id);
            reject(new Error('等待管理父节点同步面板请求超时'));
          }, 30_000);
          pendingPanelRequests.set(id, {
            input: request,
            createdAt: Date.now(),
            claimedAt: 0,
            resolve: (value) => { clearTimeout(timeout); resolve(value); },
          });
        })
        : await api('/agent/v1/panel-proxy', { method: 'POST', body: JSON.stringify(request) });
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify(result));
    }
    if (req.method === 'POST' && req.url === '/agent/v1/adopt') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (state.nodeId || state.managedByParent) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: '节点已经被认领' }));
      }
      if (!state.claimTokenHash || !safeEqualHash(input.claimToken, state.claimTokenHash)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: '认领令牌无效' }));
      }
      if (!input.sessionToken) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: '缺少父节点管理会话' }));
      }
      state.parentSessionHash = createHash('sha256').update(input.sessionToken).digest('hex');
      atomicJson(stateFile, state);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        ok: true,
        agent: {
          name: state.name,
          agentVersion: '0.1.0',
          wgControlPublicKey: state.controlKeys.publicKey,
          wgDataPublicKey: state.dataKeys.publicKey,
          controlEndpoint: state.controlEndpoint,
          controlListenPort: state.controlListenPort,
          dataEndpoint: state.dataEndpoint,
          dataListenPort: state.dataListenPort,
        },
      }));
    }
    if (req.method === 'POST' && req.url === '/agent/v1/adopt/complete') {
      requireParentSession(req);
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!input.node?.id || !input.node?.networkId) throw new Error('认领结果缺少节点身份');
      state.nodeId = input.node.id;
      state.networkId = input.node.networkId;
      state.name = input.node.name || state.name;
      state.managedByParent = true;
      state.claimTokenHash = null;
      atomicJson(stateFile, state);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, nodeId: state.nodeId }));
    }
    if (req.method === 'POST' && req.url === '/agent/v1/managed/adoption-complete') {
      requireParentSession(req);
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!input.context?.targetUrl || !input.node?.id) throw new Error('代理认领结果不完整');
      await finishLocalAdoption(input.context, { node: input.node });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, nodeId: input.node.id }));
    }
    if (req.method === 'GET' && req.url === '/agent/v1/managed/panel-requests') {
      requireParentSession(req);
      const claimedBefore = Date.now() - 10_000;
      const requests = [];
      for (const [id, pending] of pendingPanelRequests) {
        if (pending.claimedAt > claimedBefore) continue;
        pending.claimedAt = Date.now();
        requests.push({ id, input: pending.input });
      }
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify({ requests }));
    }
    if (req.method === 'POST' && req.url === '/agent/v1/managed/panel-results') {
      requireParentSession(req);
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const pending = pendingPanelRequests.get(String(input.id || ''));
      if (!pending) throw new Error('面板同步请求不存在或已经超时');
      pendingPanelRequests.delete(input.id);
      pending.resolve(input.result);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true }));
    }
    if (req.method === 'POST' && req.url === '/agent/v1/managed/relay') {
      requireParentSession(req);
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const route = Array.isArray(input.path) ? input.path : [];
      let result;
      if (route.length) {
        const nextRelay = state.managedChildren[route[0]];
        if (!nextRelay) throw new Error('下一段代理节点不存在');
        result = await requestManagedTarget(nextRelay, '/agent/v1/managed/relay', {
          method: 'POST',
          timeout: input.request?.timeout ?? 30_000,
          body: JSON.stringify({ ...input, path: route.slice(1) }),
        });
      } else {
        const child = state.managedChildren[input.childNodeId];
        if (!child) throw new Error('代理目标节点不存在');
        result = await requestManagedTarget(child, input.pathname, {
          method: input.request?.method || 'GET',
          body: input.request?.body,
          timeout: input.request?.timeout,
        });
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(result));
    }
    if (req.method === 'POST' && req.url === '/agent/v1/managed/tick') {
      requireParentSession(req);
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (input.node?.id && !state.nodeId) {
        state.nodeId = input.node.id;
        state.networkId = input.node.networkId;
        state.name = input.node.name || state.name;
        state.managedByParent = true;
        state.claimTokenHash = null;
        atomicJson(stateFile, state);
      }
      const configReport = await applyDesiredConfig(input.desired);
      const commandResult = input.command ? await runCommand(input.command) : null;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        ok: true,
        nodeId: state.nodeId,
        currentVersion: state.currentVersion,
        preparedVersion: state.preparedVersion,
        configReport,
        commandResult,
      }));
    }
    const linkProbeMatch = req.url.match(/^\/agent\/v1\/link-probe\/([^/?]+)$/);
    if (req.method === 'POST' && linkProbeMatch) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const pending = state.pendingLinkProbes?.[decodeURIComponent(linkProbeMatch[1])];
      if (!pending || pending.expiresAt <= new Date().toISOString() || !safeEqualHash(input.token, pending.tokenHash)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: '链路探测凭据无效或已过期' }));
      }
      const accepted = acceptProbeEnvelope(input, state.nodeId || state.agentInstanceId);
      pending.seenProbeIds ||= [];
      if (pending.seenProbeIds.includes(accepted.probeId)) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: '重复的链路探测请求已被拒绝' }));
      }
      pending.seenProbeIds = [...pending.seenProbeIds.slice(-63), accepted.probeId];
      atomicJson(stateFile, state);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        ok: true,
        nodeId: state.nodeId,
        probeId: accepted.probeId,
        trace: accepted.trace,
        remainingHops: accepted.remainingHops,
        reachedAt: new Date().toISOString(),
      }));
    }
    if (req.url.startsWith('/agent/v1/') || req.url === '/install.sh' || req.url.startsWith('/artifacts/')) {
      return await proxy(req, res);
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: '资源不存在' }));
  } catch (error) {
    res.writeHead(error.statusCode || 502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: error.message }));
  }
});

relayServer.listen(Number(listenPortText || 8790), listenHost || '0.0.0.0', async () => {
  console.log(`PathWeaver agent relay listening on ${listenAddress}`);
  try {
    await register({ passive: Boolean(args.listen) });
  } catch (error) {
    console.error('首次注册失败，将继续重试：', error.message);
  }
  setInterval(() => tick().catch((error) => console.error('同步失败：', error.message)), pollInterval);
  tick().catch((error) => console.error('首次同步失败：', error.message));
});
