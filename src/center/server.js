import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { extname, isAbsolute, join, normalize, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Database } from './database.js';
import { createCenterBundle } from './center-bundle.js';
import { CenterDataPlane } from './data-plane.js';
import { CenterManagedNodes } from './managed-nodes.js';
import { ControlService } from './service.js';
import { WireGuardArtifactStore, wireGuardRuntimeManifest } from './wireguard-artifacts.js';
import { CoordinatorElection } from '../core/coordinator.js';
import { verifyPanelPassword } from '../core/password.js';

const rootDir = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const publicDir = join(rootDir, 'public');
const dataDir = process.env.SDWAN_DATA_DIR || join(rootDir, 'data');
const port = Number(process.env.SDWAN_PORT || 19773);
const host = process.env.SDWAN_HOST || '0.0.0.0';
const publicUrl = process.env.SDWAN_PUBLIC_URL || `http://127.0.0.1:${port}`;
const defaultDataPort = Number(process.env.SDWAN_DEFAULT_DATA_PORT || 19801);
const adminPasswordHash = process.env.SDWAN_PANEL_PASSWORD_HASH || '';
const adminToken = process.env.SDWAN_ADMIN_TOKEN || (process.env.NODE_ENV === 'production' ? '' : 'dev-admin-token');
const nodeOfflineAfterMs = Number(process.env.SDWAN_NODE_OFFLINE_AFTER_MS || 20_000);
const configuredSweepIntervalMs = Number(process.env.SDWAN_RUNTIME_SWEEP_INTERVAL_MS || 5_000);
const runtimeSweepIntervalMs = Number.isFinite(configuredSweepIntervalMs) && configuredSweepIntervalMs > 0
  ? configuredSweepIntervalMs
  : 5_000;
const coordinatorOnly = process.env.SDWAN_COORDINATOR_ONLY === '1';
const externalCoordinator = process.env.SDWAN_EXTERNAL_COORDINATOR === '1';
const promotedNodeId = process.env.SDWAN_PROMOTE_NODE_ID || null;
const promotedTerm = Number(process.env.SDWAN_COORDINATOR_TERM || 0);
const coordinatorLeaseMs = Math.max(1_000, Number(process.env.SDWAN_COORDINATOR_LEASE_MS || 12_000));
const coordinatorHeartbeatIntervalMs = Math.max(250, Number(process.env.SDWAN_COORDINATOR_HEARTBEAT_INTERVAL_MS || 4_000));

if (!adminToken && !adminPasswordHash) {
  throw new Error('生产环境必须设置面板密码哈希');
}

const database = new Database(join(dataDir, 'pathweaver.db'));
const service = new ControlService(database, {
  publicUrl,
  nodeOfflineAfterMs,
  defaultDataPort,
  manageLocalCenters: !coordinatorOnly,
  maintainLocalCenters: !coordinatorOnly,
});
const wireGuardArtifacts = new WireGuardArtifactStore(join(dataDir, 'artifacts', 'wireguard'));
service.ensureDefaultNetwork();
const endpointSemanticMigration = service.ensureEndpointSemanticConfigurations();
for (const failure of endpointSemanticMigration.errors) {
  console.warn(`WireGuard NAT 拨号方向迁移失败 (${failure.networkId})：${failure.error}`);
}
if (promotedNodeId) service.promoteCoordinator(promotedNodeId, promotedTerm);
const centerDataPlane = new CenterDataPlane(service, {
  dataDir,
  applyNetwork: !coordinatorOnly && process.env.SDWAN_APPLY_NETWORK === '1' && process.platform === 'linux',
  wireguardDir: process.env.SDWAN_WIREGUARD_DIR || (process.platform === 'linux' ? '/etc/wireguard' : undefined),
  runtimeDir: process.env.SDWAN_WIREGUARD_RUNTIME_DIR,
});
if (!coordinatorOnly) void centerDataPlane.tick().catch((error) => console.error('center data plane reconciliation failed:', error));
const centerDataPlaneSweep = setInterval(() => {
  if (!coordinatorOnly) void centerDataPlane.tick().catch((error) => console.error('center data plane reconciliation failed:', error));
}, Math.max(1_000, runtimeSweepIntervalMs));
centerDataPlaneSweep.unref();
const centerManagedNodes = new CenterManagedNodes(service, { panelProxy: dispatchPanelEnvelope });
if (!coordinatorOnly) void centerManagedNodes.tick().catch((error) => console.error('center managed-node reconciliation failed:', error));
const centerManagedNodesSweep = setInterval(() => {
  if (!coordinatorOnly) void centerManagedNodes.tick().catch((error) => console.error('center managed-node reconciliation failed:', error));
}, Math.max(1_000, runtimeSweepIntervalMs));
centerManagedNodesSweep.unref();
const runtimeSweep = setInterval(() => {
  void (async () => {
    try {
      if (localIsFollower()) return;
      const beforeRevision = clusterRevision();
      const memberships = clusterMemberships();
      service.reconcileRuntimeState();
      if (clusterRevision() > beforeRevision) await replicateSnapshot(memberships);
    } catch (error) {
      console.error(`[${new Date().toISOString()}] runtime state sweep failed:`, error);
    }
  })();
}, Math.max(1_000, runtimeSweepIntervalMs));
runtimeSweep.unref();

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.sh': 'text/x-shellscript; charset=utf-8',
};

function send(res, status, body, headers = {}) {
  const payload = body === undefined || body === null
    ? ''
    : Buffer.isBuffer(body) || typeof body === 'string'
      ? body
      : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': typeof body === 'object' && !Buffer.isBuffer(body) ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    ...headers,
  });
  res.end(payload);
}

async function readJson(req, maxBytes = 1_048_576) {
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > maxBytes) throw new Error(`请求内容超过 ${Math.ceil(maxBytes / 1_048_576)} MiB 限制`);
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new Error('请求 JSON 格式无效');
  }
}

const coordinatorElections = new Map();
const coordinatorLeases = new Map();
let lastReplicatedRevision = 0;

function localNodeId(networkId) {
  if (promotedNodeId) {
    try {
      const node = service.getNode(promotedNodeId);
      if (node.networkId === networkId) return promotedNodeId;
    } catch {}
  }
  return service.listNodes(networkId).find((node) => node.isCenter)?.id || null;
}

function electionFor(networkId) {
  const cluster = service.getClusterState(networkId);
  const nodeId = localNodeId(networkId);
  let election = coordinatorElections.get(networkId);
  if (!election) {
    election = new CoordinatorElection({
      nodeId,
      term: cluster.term,
      votedFor: cluster.votedFor,
      leaderId: cluster.coordinatorNodeId,
      snapshotRevision: cluster.revision,
    });
    coordinatorElections.set(networkId, election);
  } else {
    election.nodeId = nodeId;
    election.observeCluster(cluster);
  }
  const voters = service.clusterVoterIds(networkId);
  if (cluster.coordinatorNodeId === nodeId && voters.length === 1 && voters[0] === nodeId) {
    election.noteLeader({
      term: cluster.term,
      leaderId: nodeId,
      revision: cluster.revision,
      leaseMs: coordinatorLeaseMs,
    });
    coordinatorLeases.set(networkId, election.leaseUntil);
  }
  return election;
}

function allClusterRuntimes() {
  return service.listNetworks().map((network) => service.getClusterRuntime(network.id, localNodeId(network.id)));
}

function decodeControlRoute(value) {
  if (!value) return [];
  let route;
  try { route = JSON.parse(Buffer.from(String(value), 'base64url').toString('utf8')); }
  catch { throw new Error('控制路径编码无效'); }
  if (!Array.isArray(route) || route.length > 16) throw new Error('控制路径超过 16 跳上限');
  const seen = new Set();
  return route.map((hop) => {
    const nodeId = String(hop?.nodeId || '');
    const url = String(hop?.url || '');
    if (!nodeId || !url || seen.has(nodeId)) throw new Error('控制路径包含空节点或环路');
    seen.add(nodeId);
    return { nodeId, url };
  });
}

function encodeControlRoute(route) {
  return Buffer.from(JSON.stringify(route), 'utf8').toString('base64url');
}

async function requestPeer(networkId, targetId, pathname, payload, timeout = 8_000) {
  const runtime = service.getClusterRuntime(networkId, localNodeId(networkId));
  const routes = runtime.control.routesByTarget?.[targetId] || [];
  const failures = [];
  for (const route of routes) {
    if (!route.hops?.length || route.hops.length > 16) continue;
    const [first, ...remaining] = route.hops;
    if (runtime.control.forwarders?.[first.nodeId] !== first.url) continue;
    try {
      const response = await fetch(new URL(pathname, `${first.url.replace(/\/$/, '')}/`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${runtime.cluster.electionSecret}`,
          'X-PathWeaver-Relay-Trace': localNodeId(networkId),
          ...(remaining.length ? { 'X-PathWeaver-Control-Route': encodeControlRoute(remaining) } : {}),
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeout),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || `节点返回 HTTP ${response.status}`);
      return body;
    } catch (error) {
      failures.push(`${route.id}: ${error.message}`);
    }
  }
  throw new Error(`到选民 ${targetId} 的无环路径均不可用：${failures.join('；')}`);
}

function requireClusterSecret(req, networkId) {
  const cluster = service.getClusterState(networkId);
  if (!secretMatches(bearer(req), cluster.electionSecret)) {
    const error = new Error('协调节点间凭据无效');
    error.statusCode = 401;
    throw error;
  }
  return cluster;
}

function requireCoordinatorWrite() {
  for (const runtime of allClusterRuntimes()) {
    const localId = localNodeId(runtime.cluster.networkId);
    if (runtime.cluster.coordinatorNodeId !== localId) {
      const error = new Error('本节点当前不是配置协调节点，请通过已选出的协调节点重试');
      error.statusCode = 503;
      throw error;
    }
    if (!externalCoordinator && Number(coordinatorLeases.get(runtime.cluster.networkId) || 0) <= Date.now()) {
      const error = new Error('配置协调节点尚未取得多数派租约，暂时拒绝写入以避免双主');
      error.statusCode = 503;
      throw error;
    }
  }
}

function coordinatorWriteStatus() {
  try {
    requireCoordinatorWrite();
    return { writable: true, reason: null };
  } catch (error) {
    return { writable: false, reason: error.message };
  }
}

function clusterRevision() {
  return Math.max(0, ...service.listNetworks().map((network) => service.getClusterState(network.id).revision));
}

function clusterMemberships() {
  return service.listNetworks().map((network) => ({
    networkId: network.id,
    voterIds: service.clusterVoterIds(network.id),
    localNodeId: localNodeId(network.id),
  }));
}

async function replicateSnapshot(memberships) {
  const snapshot = database.exportSnapshot();
  for (const membership of memberships) {
    const quorum = Math.floor(Math.max(1, membership.voterIds.length) / 2) + 1;
    let acknowledgements = membership.voterIds.includes(membership.localNodeId) ? 1 : 0;
    const responses = await Promise.all(membership.voterIds
      .filter((id) => id !== membership.localNodeId)
      .map((id) => requestPeer(membership.networkId, id, '/peer/v1/replica/install', {
        networkId: membership.networkId,
        snapshot,
      }, 15_000).catch(() => null)));
    acknowledgements += responses.filter((response) => response?.ok).length;
    if (acknowledgements < quorum) {
      const error = new Error(`配置快照只同步到 ${acknowledgements}/${membership.voterIds.length} 个选民，未达到多数派`);
      error.statusCode = 503;
      throw error;
    }
  }
  lastReplicatedRevision = Math.max(lastReplicatedRevision, Number(snapshot.revision || 0));
  return snapshot.revision;
}

async function coordinatorHeartbeatTick() {
  for (const runtime of allClusterRuntimes()) {
    const networkId = runtime.cluster.networkId;
    const localId = localNodeId(networkId);
    const election = electionFor(networkId);
    if (runtime.cluster.coordinatorNodeId !== localId) continue;
    const quorum = election.quorum(runtime.voterIds.length);
    let acknowledgements = runtime.voterIds.includes(localId) ? 1 : 0;
    const heartbeat = {
      networkId,
      term: runtime.cluster.term,
      leaderId: localId,
      revision: runtime.cluster.revision,
      leaseMs: coordinatorLeaseMs,
    };
    const responses = await Promise.all(runtime.voterIds.filter((id) => id !== localId).map((id) =>
      requestPeer(networkId, id, '/peer/v1/election/heartbeat', heartbeat).catch(() => null)));
    for (const response of responses) {
      if (response?.accepted) acknowledgements += 1;
      if (Number(response?.term || 0) > election.term && response?.leaderId) {
        election.noteLeader({ term: response.term, leaderId: response.leaderId, revision: response.revision });
        service.observeCoordinator(networkId, {
          coordinatorNodeId: response.leaderId,
          term: response.term,
          revision: response.revision,
        });
      }
    }
    if (acknowledgements >= quorum) {
      election.noteLeader(heartbeat);
      coordinatorLeases.set(networkId, election.leaseUntil);
    }
  }
  if (!localIsFollower() && clusterRevision() > lastReplicatedRevision) {
    await replicateSnapshot(clusterMemberships());
  }
}

for (const network of service.listNetworks()) electionFor(network.id);
void coordinatorHeartbeatTick().catch((error) => console.error('coordinator heartbeat failed:', error.message));
const coordinatorHeartbeatSweep = setInterval(() => {
  void coordinatorHeartbeatTick().catch((error) => console.error('coordinator heartbeat failed:', error.message));
}, coordinatorHeartbeatIntervalMs);
coordinatorHeartbeatSweep.unref();

function bearer(req) {
  const authorization = req.headers.authorization ?? '';
  return authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
}

function secretMatches(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function requireAdmin(req) {
  const credential = bearer(req);
  const tokenValid = adminToken && secretMatches(credential, adminToken);
  if (!tokenValid && !verifyPanelPassword(credential, adminPasswordHash)) {
    const error = new Error('面板密码无效');
    error.statusCode = 401;
    throw error;
  }
}

function requireAgent(req) {
  const node = service.authenticateAgent(bearer(req));
  if (!node) {
    const error = new Error('节点凭据无效');
    error.statusCode = 401;
    throw error;
  }
  return node;
}

function match(pathname, pattern) {
  const names = [];
  const expression = pattern.replace(/:([A-Za-z]+)/g, (_, name) => {
    names.push(name);
    return '([^/]+)';
  });
  const result = pathname.match(new RegExp(`^${expression}$`));
  if (!result) return null;
  return Object.fromEntries(names.map((name, index) => [name, decodeURIComponent(result[index + 1])]));
}

function serveStatic(pathname, res) {
  const requested = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
  const filename = resolve(publicDir, normalize(requested));
  const relativeName = relative(publicDir, filename);
  if (relativeName.startsWith('..') || isAbsolute(relativeName)) return false;
  try {
    if (!statSync(filename).isFile()) return false;
    const content = readFileSync(filename);
    send(res, 200, content, {
      'Content-Type': mimeTypes[extname(filename)] || 'application/octet-stream',
      'Cache-Control': ['.html', '.css', '.js'].includes(extname(filename)) ? 'no-cache' : 'public, max-age=300',
    });
    return true;
  } catch {
    return false;
  }
}

async function proxyPanelToCoordinator(req, res) {
  const network = service.listNetworks()[0];
  if (!network) return false;
  const cluster = service.getClusterState(network.id);
  if (cluster.coordinatorNodeId === localNodeId(network.id)) return false;
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 1_048_576) throw new Error('面板代理请求超过 1 MiB 限制');
    chunks.push(chunk);
  }
  const envelope = await requestPeer(network.id, cluster.coordinatorNodeId, '/peer/v1/coordinator-panel', {
    networkId: network.id,
    request: {
      method: req.method,
      path: req.url,
      contentType: req.headers['content-type'] || 'application/json',
      body: Buffer.concat(chunks).toString('base64'),
    },
  }, 30_000);
  send(res, Number(envelope.status || 502), Buffer.from(String(envelope.body || ''), 'base64'), {
    'Content-Type': envelope.contentType || 'application/json; charset=utf-8',
  });
  return true;
}

async function handleAdmin(req, res, pathname, url, authenticated = false) {
  if (!authenticated) requireAdmin(req);
  if (!authenticated && await proxyPanelToCoordinator(req, res)) return;
  if (req.method === 'GET' && pathname === '/api/v1/panel-status') {
    const writeStatus = coordinatorWriteStatus();
    return send(res, 200, {
      synchronized: writeStatus.writable,
      writable: writeStatus.writable,
      syncMode: 'quorum-replicated-control-state',
      panelPort: port,
      message: writeStatus.writable
        ? '面板通过无环控制路径读写当前协调节点；成功写入已同步到选民多数派'
        : writeStatus.reason,
    });
  }
  if (req.method === 'GET' && pathname === '/api/v1/dashboard') {
    return send(res, 200, service.dashboard());
  }
  if (req.method === 'GET' && pathname === '/api/v1/networks') {
    return send(res, 200, { networks: service.listNetworks() });
  }
  if (req.method === 'POST' && pathname === '/api/v1/networks') {
    return send(res, 201, service.createNetwork(await readJson(req)));
  }

  let params = match(pathname, '/api/v1/networks/:id');
  if (req.method === 'PATCH' && params) return send(res, 200, service.updateNetwork(params.id, await readJson(req)));

  params = match(pathname, '/api/v1/networks/:id/data-cidr-preview');
  if (req.method === 'GET' && params) {
    return send(res, 200, { preview: true, ...service.planDataCidrChange(params.id, { dataCidr: url.searchParams.get('dataCidr') }) });
  }

  params = match(pathname, '/api/v1/networks/:id/nodes');
  if (req.method === 'GET' && params) return send(res, 200, { nodes: service.listNodes(params.id) });

  params = match(pathname, '/api/v1/networks/:id/topology');
  if (req.method === 'GET' && params) return send(res, 200, service.getTopology(params.id));
  if (req.method === 'PUT' && params) {
    const input = await readJson(req);
    return send(res, 200, service.replaceTopology(params.id, input.links));
  }

  params = match(pathname, '/api/v1/networks/:id/links');
  if (req.method === 'POST' && params) {
    return send(res, 202, service.createLinkValidation(params.id, await readJson(req)));
  }

  params = match(pathname, '/api/v1/networks/:id/path-options');
  if (req.method === 'GET' && params) {
    return send(res, 200, service.getPathOptions(
      params.id,
      url.searchParams.get('sourceId'),
      url.searchParams.get('targetId'),
    ));
  }

  params = match(pathname, '/api/v1/networks/:id/path-policies');
  if (req.method === 'PUT' && params) {
    return send(res, 200, service.savePathPolicy(params.id, await readJson(req)));
  }
  if (req.method === 'DELETE' && params) {
    return send(res, 200, service.deletePathPolicy(
      params.id,
      url.searchParams.get('sourceId'),
      url.searchParams.get('targetId'),
    ));
  }

  params = match(pathname, '/api/v1/networks/:id/join-tokens');
  if (req.method === 'POST' && params) return send(res, 201, service.createJoinToken(params.id, await readJson(req)));

  params = match(pathname, '/api/v1/networks/:id/configurations');
  if (req.method === 'GET' && params) {
    return send(res, 200, { configurations: service.listConfigurations(params.id, Number(url.searchParams.get('limit') || 20)) });
  }

  params = match(pathname, '/api/v1/nodes/:id');
  if (req.method === 'PATCH' && params) return send(res, 200, service.updateNode(params.id, await readJson(req)));
  if (req.method === 'DELETE' && params) return send(res, 200, service.deleteNode(params.id));

  params = match(pathname, '/api/v1/nodes/:id/deletion-impact');
  if (req.method === 'GET' && params) {
    const { compiled, ...impact } = service.inspectNodeDeletion(params.id);
    return send(res, 200, impact);
  }

  params = match(pathname, '/api/v1/nodes/:id/commands');
  if (req.method === 'POST' && params) {
    const input = await readJson(req);
    const node = service.getNode(params.id);
    if (node.isCenter && input.type === 'adopt-node') {
      return send(res, 201, await centerManagedNodes.adopt(node.id, input.payload || {}));
    }
    return send(res, 201, service.enqueueCommand(params.id, input.type, input.payload));
  }

  params = match(pathname, '/api/v1/configurations/:id');
  if (req.method === 'GET' && params) return send(res, 200, service.getConfiguration(params.id));

  return send(res, 404, { error: '接口不存在' });
}

async function dispatchPanelEnvelope(input) {
  const method = String(input.method || 'GET').toUpperCase();
  const nestedUrl = new URL(String(input.path || ''), publicUrl);
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) || !nestedUrl.pathname.startsWith('/api/v1/')) {
    throw new Error('面板代理请求方法或路径无效');
  }
  const body = Buffer.from(String(input.body || ''), 'base64');
  if (body.length > 1_048_576) throw new Error('面板代理请求超过 1 MiB 限制');
  const nestedReq = Readable.from(body.length ? [body] : []);
  nestedReq.method = method;
  nestedReq.headers = { 'content-type': String(input.contentType || 'application/json') };
  const captured = await new Promise((resolve, reject) => {
    let status = 200;
    let headers = {};
    const nestedRes = {
      writeHead(nextStatus, nextHeaders = {}) {
        status = Number(nextStatus);
        headers = nextHeaders;
      },
      end(payload = '') {
        resolve({ status, headers, payload: Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload)) });
      },
    };
    Promise.resolve(handleAdmin(nestedReq, nestedRes, nestedUrl.pathname, nestedUrl, true)).catch(reject);
  });
  return {
    status: captured.status,
    contentType: captured.headers['Content-Type'] || captured.headers['content-type'] || 'application/json; charset=utf-8',
    body: captured.payload.toString('base64'),
  };
}

async function handleAgent(req, res, pathname, url) {
  if (req.method === 'POST' && pathname === '/agent/v1/register') {
    return send(res, 201, service.registerAgent(await readJson(req)));
  }
  const node = requireAgent(req);
  if (req.method === 'POST' && pathname === '/agent/v1/panel-proxy') {
    return send(res, 200, await dispatchPanelEnvelope(await readJson(req)));
  }
  if (req.method === 'POST' && pathname === '/agent/v1/heartbeat') {
    return send(res, 200, service.heartbeat(node.id, await readJson(req)));
  }
  if (req.method === 'GET' && pathname === '/agent/v1/config') {
    const desired = service.getDesiredConfig(node.id, Number(url.searchParams.get('currentVersion') || 0));
    return desired ? send(res, 200, desired) : send(res, 204);
  }
  if (req.method === 'GET' && pathname === '/agent/v1/replica-snapshot') {
    return send(res, 200, { snapshot: database.exportSnapshot() });
  }
  let params = match(pathname, '/agent/v1/config/:id/report');
  if (req.method === 'POST' && params) {
    const input = await readJson(req);
    return send(res, 200, service.reportConfig(node.id, params.id, input.phase, input.error));
  }
  if (req.method === 'GET' && pathname === '/agent/v1/commands/next') {
    const command = service.claimCommand(node.id);
    return command ? send(res, 200, command) : send(res, 204);
  }
  params = match(pathname, '/agent/v1/commands/:id/complete');
  if (req.method === 'POST' && params) {
    return send(res, 200, service.completeCommand(node.id, params.id, await readJson(req)));
  }
  return send(res, 404, { error: 'Agent 接口不存在' });
}

async function handlePeer(req, res, pathname) {
  if (req.method !== 'POST') return send(res, 405, { error: '协调接口只接受 POST' });
  const input = await readJson(req, 64 * 1_048_576);
  const networkId = String(input.networkId || '');
  const remaining = decodeControlRoute(req.headers['x-pathweaver-control-route']);
  if (remaining.length) {
    const [next, ...rest] = remaining;
    const runtime = service.getClusterRuntime(networkId, localNodeId(networkId));
    if (runtime.control.forwarders?.[next.nodeId] !== next.url) throw new Error('协调路径下一跳不属于当前已验证邻接');
    const trace = String(req.headers['x-pathweaver-relay-trace'] || '').split(',').filter(Boolean);
    const selfId = localNodeId(networkId);
    if (trace.includes(selfId)) throw new Error('协调路径检测到重复节点，已阻断环路');
    trace.push(selfId);
    const upstream = await fetch(new URL(pathname, `${next.url.replace(/\/$/, '')}/`), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: req.headers.authorization || '',
        'X-PathWeaver-Relay-Trace': trace.join(','),
        ...(rest.length ? { 'X-PathWeaver-Control-Route': encodeControlRoute(rest) } : {}),
      },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(30_000),
    });
    const body = Buffer.from(await upstream.arrayBuffer());
    return send(res, upstream.status, body, {
      'Content-Type': upstream.headers.get('content-type') || 'application/json; charset=utf-8',
    });
  }
  const cluster = requireClusterSecret(req, networkId);
  const election = electionFor(networkId);
  if (pathname === '/peer/v1/election/request-vote') {
    const result = election.requestVote(input);
    if (result.granted) {
      database.run(
        'UPDATE cluster_state SET term = ?, voted_for = ?, updated_at = ? WHERE network_id = ?',
        result.term, input.candidateId, new Date().toISOString(), networkId,
      );
      coordinatorLeases.delete(networkId);
    }
    return send(res, 200, {
      ...result,
      leaderId: election.leaderId,
      revision: election.snapshotRevision,
    });
  }
  if (pathname === '/peer/v1/election/heartbeat') {
    const result = election.noteLeader(input);
    if (result.accepted) {
      service.observeCoordinator(networkId, {
        coordinatorNodeId: input.leaderId,
        term: input.term,
        revision: input.revision,
      });
      if (input.leaderId !== localNodeId(networkId)) coordinatorLeases.delete(networkId);
    }
    return send(res, 200, {
      ...result,
      leaderId: election.leaderId,
      revision: election.snapshotRevision,
    });
  }
  if (pathname === '/peer/v1/replica/install') {
    if (Number(input.snapshot?.revision || 0) >= cluster.revision) {
      database.importSnapshot(input.snapshot);
      coordinatorElections.clear();
      coordinatorLeases.clear();
      electionFor(networkId);
    }
    return send(res, 200, { ok: true, revision: service.getClusterState(networkId).revision });
  }
  if (pathname === '/peer/v1/coordinator-panel') {
    if (service.getClusterState(networkId).coordinatorNodeId !== localNodeId(networkId)) {
      const error = new Error('请求未到达当前配置协调节点');
      error.statusCode = 503;
      throw error;
    }
    requireCoordinatorWrite();
    const beforeRevision = clusterRevision();
    const memberships = clusterMemberships();
    const envelope = await dispatchPanelEnvelope(input.request || {});
    if (Number(envelope.status || 500) < 400 && clusterRevision() > beforeRevision) {
      await replicateSnapshot(memberships);
    }
    return send(res, 200, envelope);
  }
  return send(res, 404, { error: '协调接口不存在' });
}

function capturedResponse() {
  return {
    status: 200,
    headers: {},
    body: Buffer.alloc(0),
    writeHead(status, headers = {}) {
      this.status = Number(status);
      this.headers = headers;
    },
    end(payload = '') {
      this.body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload));
    },
    flush(res) {
      res.writeHead(this.status, this.headers);
      res.end(this.body);
    },
  };
}

function localIsFollower() {
  return service.listNetworks().some((network) =>
    service.getClusterState(network.id).coordinatorNodeId !== localNodeId(network.id));
}

async function handleReplicatedMutation(handler, req, res) {
  requireCoordinatorWrite();
  const beforeRevision = clusterRevision();
  const memberships = clusterMemberships();
  const captured = capturedResponse();
  await handler(req, captured);
  if (captured.status < 400 && clusterRevision() > beforeRevision) await replicateSnapshot(memberships);
  captured.flush(res);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, publicUrl);
  const pathname = url.pathname;
  try {
    if (pathname === '/healthz') return send(res, 200, {
      status: 'ok',
      time: new Date().toISOString(),
      centerDataPlane: centerDataPlane.runtimeInfo(),
    });
    if (pathname === '/install.sh') {
      let source = url.searchParams.get('source') || `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;
      try {
        const parsedSource = new URL(source);
        if (!['http:', 'https:'].includes(parsedSource.protocol)) throw new Error('invalid protocol');
        if (parsedSource.username || parsedSource.password || parsedSource.origin === 'null') throw new Error('invalid authority');
        source = parsedSource.origin;
      } catch {
        return send(res, 400, { error: '安装源地址无效' });
      }
      const installer = readFileSync(join(rootDir, 'scripts', 'install.sh'), 'utf8').replace('__PATHWEAVER_SOURCE__', source);
      return send(res, 200, installer, {
        'Content-Type': 'text/x-shellscript; charset=utf-8',
        'Cache-Control': 'public, max-age=60',
      });
    }
    if (req.method === 'GET' && pathname === '/artifacts/wireguard/manifest.json') {
      return send(res, 200, wireGuardRuntimeManifest(), { 'Cache-Control': 'public, max-age=300' });
    }
    if (req.method === 'GET' && pathname === '/artifacts/center/pathweaver-center.tar.gz') {
      const bundle = createCenterBundle(rootDir);
      return send(res, 200, bundle, {
        'Content-Type': 'application/gzip',
        'Content-Length': bundle.length,
        'Cache-Control': 'public, max-age=300',
      });
    }
    const wireGuardArtifactMatch = pathname.match(/^\/artifacts\/wireguard\/([^/]+)$/);
    if (req.method === 'GET' && wireGuardArtifactMatch) {
      const artifact = await wireGuardArtifacts.load(decodeURIComponent(wireGuardArtifactMatch[1]));
      return send(res, 200, artifact.content, {
        'Content-Type': artifact.descriptor.contentType,
        'Content-Length': artifact.content.length,
        'Cache-Control': 'public, max-age=31536000, immutable',
        'X-PathWeaver-Artifact-Cache': artifact.cached ? 'HIT' : 'MISS',
      });
    }
    if (pathname === '/artifacts/agent/agent.js') {
      return send(res, 200, readFileSync(join(rootDir, 'src', 'agent', 'agent.js')), {
        'Content-Type': 'text/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=300',
      });
    }
    if (pathname === '/artifacts/agent/runtime.js') {
      return send(res, 200, readFileSync(join(rootDir, 'src', 'agent', 'runtime.js')), {
        'Content-Type': 'text/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=300',
      });
    }
    if (pathname === '/artifacts/agent/wireguard.js') {
      return send(res, 200, readFileSync(join(rootDir, 'src', 'agent', 'wireguard.js')), {
        'Content-Type': 'text/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=300',
      });
    }
    if (pathname.startsWith('/peer/v1/')) return await handlePeer(req, res, pathname);
    if (pathname.startsWith('/api/v1/')) {
      if (req.method === 'GET' || localIsFollower()) return await handleAdmin(req, res, pathname, url);
      return await handleReplicatedMutation(
        (nestedReq, nestedRes) => handleAdmin(nestedReq, nestedRes, pathname, url), req, res,
      );
    }
    if (pathname.startsWith('/agent/v1/')) {
      if (req.method === 'GET') return await handleAgent(req, res, pathname, url);
      return await handleReplicatedMutation(
        (nestedReq, nestedRes) => handleAgent(nestedReq, nestedRes, pathname, url), req, res,
      );
    }
    if (req.method === 'GET' && serveStatic(pathname, res)) return;
    if (req.method === 'GET' && !pathname.includes('.')) return serveStatic('/', res);
    return send(res, 404, { error: '资源不存在' });
  } catch (error) {
    const status = error.statusCode || (error.message?.includes('不存在') ? 404 : 400);
    if (status >= 500) console.error(`[${new Date().toISOString()}] ${req.method} ${pathname}:`, error);
    return send(res, status, { error: error.message || '服务器内部错误', details: error.details });
  }
});

server.listen(port, host, () => {
  console.log(`PathWeaver node panel listening at ${publicUrl}`);
  if (adminToken === 'dev-admin-token') console.log('Development admin token: dev-admin-token');
});

function shutdown() {
  clearInterval(runtimeSweep);
  clearInterval(centerDataPlaneSweep);
  clearInterval(centerManagedNodesSweep);
  clearInterval(coordinatorHeartbeatSweep);
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
