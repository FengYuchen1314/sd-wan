import { createHash, generateKeyPairSync, randomBytes, timingSafeEqual } from 'node:crypto';
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
  selectAvailableUdpPort,
} from './runtime.js';
import { WireGuardManager } from './wireguard.js';

const args = parseArgs(process.argv.slice(2));
const dataDir = resolve(process.env.SDWAN_AGENT_DATA_DIR || (process.platform === 'linux' ? '/var/lib/pathweaver-agent' : './data/agent'));
const stateFile = join(dataDir, 'state.json');
const listenAddress = process.env.SDWAN_AGENT_LISTEN || '0.0.0.0:8790';
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
state.agentInstanceId ||= `agent-${randomBytes(12).toString('hex')}`;
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

function safeEqualHash(token, expectedHash) {
  const actual = createHash('sha256').update(String(token ?? '')).digest();
  const expected = Buffer.from(String(expectedHash ?? ''), 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

async function api(pathname, options = {}) {
  if (!state.upstream) throw new Error('Agent 尚未设置上游地址');
  const url = new URL(pathname, `${state.upstream.replace(/\/$/, '')}/`);
  const headers = { 'Content-Type': 'application/json', ...(options.headers ?? {}) };
  if (state.credential) headers.Authorization = `Bearer ${state.credential}`;
  const response = await fetch(url, { ...options, headers, signal: AbortSignal.timeout(options.timeout ?? 20_000) });
  if (response.status === 204) return null;
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(body?.error || `上游返回 HTTP ${response.status}`);
  return body;
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
      controlEndpoint: args.controlEndpoint || null,
      dataEndpoint: args.dataEndpoint || null,
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

async function syncConfig() {
  const desired = await api(`/agent/v1/config?currentVersion=${state.currentVersion}`);
  if (!desired) return;
  if (desired.phase === 'prepare' && state.preparedVersion !== desired.version) {
    try {
      await wireguard.prepare(desired.version, desired.config);
      state.preparedVersion = desired.version;
      atomicJson(stateFile, state);
      await api(`/agent/v1/config/${desired.versionId}/report`, {
        method: 'POST', body: JSON.stringify({ phase: 'prepared' }),
      });
    } catch (error) {
      await api(`/agent/v1/config/${desired.versionId}/report`, {
        method: 'POST', body: JSON.stringify({ phase: 'prepared', error: error.message }),
      });
    }
  }
  if (desired.phase === 'activate' && state.currentVersion !== desired.version) {
    try {
      if (state.preparedVersion !== desired.version) await wireguard.prepare(desired.version, desired.config);
      await wireguard.activate(desired.version);
      state.currentVersion = desired.version;
      state.preparedVersion = desired.version;
      atomicJson(stateFile, state);
      await api(`/agent/v1/config/${desired.versionId}/report`, {
        method: 'POST', body: JSON.stringify({ phase: 'activated' }),
      });
    } catch (error) {
      await api(`/agent/v1/config/${desired.versionId}/report`, {
        method: 'POST', body: JSON.stringify({ phase: 'activated', error: error.message }),
      });
    }
  }
}

async function executeCommand(command) {
  let result;
  try {
    if (command.type === 'adopt-node') {
      const response = await fetch(new URL('/agent/v1/adopt', command.payload.targetUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          claimToken: command.payload.claimToken,
          joinToken: command.payload.joinToken || command.payload.claimToken,
          upstream: command.payload.upstream || command.payload.relayUrl,
        }),
        signal: AbortSignal.timeout(20_000),
      });
      if (!response.ok) throw new Error((await response.json()).error || `HTTP ${response.status}`);
      result = { ok: true, response: await response.json() };
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
  await api(`/agent/v1/commands/${command.id}/complete`, { method: 'POST', body: JSON.stringify(result) });
}

async function tick() {
  if (!state.credential) return;
  await api('/agent/v1/heartbeat', {
    method: 'POST',
    body: JSON.stringify({ agentVersion: '0.1.0', dataListenPort: state.dataListenPort }),
  });
  await syncConfig();
  const command = await api('/agent/v1/commands/next');
  if (command) await executeCommand(command);
}

async function proxy(req, res) {
  if (!state.upstream) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: '中继节点未设置上游' }));
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const relayTrace = extendRelayTrace(
    req.headers['x-pathweaver-relay-trace'],
    state.nodeId || state.agentInstanceId,
  );
  const upstream = await fetch(new URL(req.url, `${state.upstream.replace(/\/$/, '')}/`), {
    method: req.method,
    headers: {
      ...(req.headers.authorization ? { Authorization: req.headers.authorization } : {}),
      ...(req.headers['content-type'] ? { 'Content-Type': req.headers['content-type'] } : {}),
      'X-PathWeaver-Relay-Trace': relayTrace,
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
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'ok', nodeId: state.nodeId ?? null }));
    }
    if (req.method === 'POST' && req.url === '/agent/v1/adopt') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!state.claimTokenHash || !safeEqualHash(input.claimToken, state.claimTokenHash)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: '认领令牌无效' }));
      }
      state.upstream = input.upstream;
      state.joinToken = input.joinToken;
      atomicJson(stateFile, state);
      await register({ passive: true });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, nodeId: state.nodeId }));
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
    res.writeHead(502, { 'Content-Type': 'application/json' });
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
