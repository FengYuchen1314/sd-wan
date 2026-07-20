import { createHash, generateKeyPairSync, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Database } from '../center/database.js';
import { CoordinatorElection } from '../core/coordinator.js';
import { executeBenchmark, handleBenchmarkRequest, prepareBenchmark } from '../core/benchmark.js';
import { fetchViaInternalControlRoutes } from '../core/control-fetch.js';
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
const replicaFile = join(dataDir, 'coordinator-replica.json');
const coordinatorServerFile = fileURLToPath(new URL('../center/server.js', import.meta.url));
const applyNetwork = process.env.SDWAN_APPLY_NETWORK === '1' && process.platform === 'linux';
const pollInterval = Number(process.env.SDWAN_POLL_INTERVAL || 5000);
const coordinatorLeaseMs = Math.max(1_000, Number(process.env.SDWAN_COORDINATOR_LEASE_MS || 12_000));
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

function booleanValue(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'y', 'on'].includes(String(value).toLowerCase());
}

function normalizeReachabilityType(value, { hasPublicEndpoint, dataEndpoint } = {}) {
  const raw = String(value ?? '').trim().toLowerCase();
  if (raw === 'public' || raw === 'nat' || raw === 'ix') return raw;
  if (raw === 'yes' || raw === 'y' || raw === '1' || raw === 'true' || raw === 'on') return 'public';
  if (raw === 'no' || raw === 'n' || raw === '0' || raw === 'false' || raw === 'off') return 'nat';
  if (value === undefined || value === null || value === '') {
    if (hasPublicEndpoint !== undefined) return booleanValue(hasPublicEndpoint) ? 'public' : 'nat';
    return dataEndpoint ? 'public' : 'nat';
  }
  throw new Error('节点拨入类型只能是 public、nat 或 ix');
}

function atomicJson(filename, value) {
  const temporary = `${filename}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, filename);
}

function updateMarker() {
  const filename = resolve(process.env.SDWAN_UPDATE_APPLIED_FILE || (process.platform === 'linux'
    ? '/var/lib/pathweaver/update-applied.json'
    : './data/update-applied.json'));
  try {
    const marker = JSON.parse(readFileSync(filename, 'utf8'));
    return marker?.rolloutId ? marker : null;
  } catch {
    return null;
  }
}

async function fetchUpdateArtifact(payload) {
  const fetchChecked = async (url, maxBytes, label) => {
    const response = await fetch(url, { signal: AbortSignal.timeout(30_000), redirect: 'follow' });
    if (!response.ok) throw new Error(`${label}返回 HTTP ${response.status}`);
    const declared = Number(response.headers.get('content-length') || 0);
    if (declared > maxBytes) throw new Error(`${label}超过 ${Math.ceil(maxBytes / 1_048_576)} MiB 上限`);
    const content = Buffer.from(await response.arrayBuffer());
    if (!content.length || content.length > maxBytes) throw new Error(`${label}大小无效`);
    return content;
  };
  const installer = await fetchChecked(payload.installerUrl, 512 * 1024, 'GitHub 安装器');
  const bundle = await fetchChecked(payload.bundleUrl, 16 * 1024 * 1024, 'GitHub 更新制品');
  if (!installer.toString('utf8').startsWith('#!/usr/bin/env bash')) throw new Error('GitHub 安装器内容无效');
  if (bundle[0] !== 0x1f || bundle[1] !== 0x8b) throw new Error('GitHub 更新制品不是 gzip 包');
  return {
    ok: true,
    installer: installer.toString('utf8'),
    bundleBase64: bundle.toString('base64'),
    bundleSha256: createHash('sha256').update(bundle).digest('hex'),
  };
}

function triggerUpdateApply(requestFile) {
  if (process.platform !== 'linux') return;
  const applyScript = existsSync('/usr/local/libexec/pathweaver-apply-update')
    ? '/usr/local/libexec/pathweaver-apply-update'
    : resolve(dirname(fileURLToPath(import.meta.url)), '../../scripts/apply-update-request.sh');
  const trySpawn = (command, args) => {
    try {
      const child = spawn(command, args, {
        detached: true,
        stdio: 'ignore',
        env: {
          ...process.env,
          PATHWEAVER_UPDATE_REQUEST_FILE: requestFile,
          PATHWEAVER_UPDATE_STAGING_DIR: process.env.SDWAN_UPDATE_STAGING_DIR || join(dirname(requestFile), 'update-staging'),
          PATHWEAVER_UPDATE_APPLIED_FILE: process.env.SDWAN_UPDATE_APPLIED_FILE || join(dirname(requestFile), 'update-applied.json'),
        },
      });
      child.unref();
      return true;
    } catch {
      return false;
    }
  };
  if (trySpawn('systemctl', ['start', 'pathweaver-update-apply.service'])) return;
  if (existsSync(applyScript)) trySpawn('bash', [applyScript]);
}

function stageUpdateArtifact(payload) {
  const rolloutId = String(payload.rolloutId || '');
  if (!/^[0-9a-f-]{36}$/i.test(rolloutId)) throw new Error('更新任务 ID 无效');
  const bundle = Buffer.from(String(payload.bundleBase64 || ''), 'base64');
  const digest = createHash('sha256').update(bundle).digest('hex');
  if (digest !== payload.bundleSha256 || bundle[0] !== 0x1f || bundle[1] !== 0x8b) {
    throw new Error('控制面分发的更新制品摘要无效');
  }
  const requestFile = resolve(process.env.SDWAN_UPDATE_REQUEST_FILE || (process.platform === 'linux'
    ? '/var/lib/pathweaver/update-request.json'
    : './data/update-request.json'));
  const stagingRoot = resolve(process.env.SDWAN_UPDATE_STAGING_DIR || join(dirname(requestFile), 'update-staging'));
  const stagingDir = join(stagingRoot, rolloutId);
  mkdirSync(stagingDir, { recursive: true, mode: 0o700 });
  const installerFile = join(stagingDir, 'install.sh');
  const bundleFile = join(stagingDir, 'pathweaver.tar.gz');
  writeFileSync(installerFile, String(payload.installer || ''), { mode: 0o700 });
  writeFileSync(bundleFile, bundle, { mode: 0o600 });
  mkdirSync(dirname(requestFile), { recursive: true });
  atomicJson(requestFile, { rolloutId, installerFile, bundleFile, bundleSha256: digest });
  triggerUpdateApply(requestFile);
  return { ok: true, scheduled: true, rolloutId, bundleSha256: digest };
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
state.pendingBenchmarks ||= {};
if (args.panelProxyToken || process.env.SDWAN_PANEL_PROXY_TOKEN) {
  state.panelProxyTokenHash = createHash('sha256')
    .update(String(args.panelProxyToken || process.env.SDWAN_PANEL_PROXY_TOKEN))
    .digest('hex');
}
const reachabilitySetting = args.reachability ?? process.env.SDWAN_REACHABILITY
  ?? args.publicEndpoint ?? process.env.SDWAN_PUBLIC_ENDPOINT;
state.reachabilityType = normalizeReachabilityType(reachabilitySetting, {
  hasPublicEndpoint: state.hasPublicEndpoint,
  dataEndpoint: state.dataEndpoint || args.dataEndpoint || process.env.SDWAN_DATA_ENDPOINT,
});
state.hasPublicEndpoint = state.reachabilityType === 'public' || state.reachabilityType === 'ix';
if (state.hasPublicEndpoint) {
  state.controlEndpoint ||= args.controlEndpoint || process.env.SDWAN_CONTROL_ENDPOINT || null;
  state.dataEndpoint ||= args.dataEndpoint || process.env.SDWAN_DATA_ENDPOINT || null;
} else {
  state.controlEndpoint = null;
  state.dataEndpoint = null;
}
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
let replica = null;
try { replica = existsSync(replicaFile) ? JSON.parse(readFileSync(replicaFile, 'utf8')) : null; } catch {}
const election = new CoordinatorElection({
  nodeId: state.nodeId || state.agentInstanceId,
  ...(state.coordinatorElection || {}),
  snapshotRevision: Math.max(
    Number(state.coordinatorElection?.snapshotRevision || 0),
    Number(replica?.revision || 0),
  ),
});
let coordinatorProcess = null;
let localCoordinatorUrl = null;
let consecutiveControlFailures = 0;

function safeEqualHash(token, expectedHash) {
  const actual = createHash('sha256').update(String(token ?? '')).digest();
  const expected = Buffer.from(String(expectedHash ?? ''), 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function safeEqualText(left, right) {
  const actual = Buffer.from(String(left ?? ''));
  const expected = Buffer.from(String(right ?? ''));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function persistElection() {
  state.coordinatorElection = election.snapshot();
  atomicJson(stateFile, state);
}

function applyClusterDescriptor(cluster, { renewLease = false } = {}) {
  if (!cluster?.coordinatorNodeId) return;
  state.controlCluster = {
    ...state.controlCluster,
    ...cluster,
    voterIds: Array.isArray(cluster.voterIds) ? cluster.voterIds : (state.controlCluster?.voterIds || []),
  };
  election.nodeId = state.nodeId || state.agentInstanceId;
  election.observeCluster(cluster);
  if (renewLease) {
    election.noteLeader({
      term: cluster.term,
      leaderId: cluster.coordinatorNodeId,
      revision: cluster.revision,
      leaseMs: coordinatorLeaseMs,
    });
  }
  persistElection();
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

function reachableControlUrl(value) {
  const normalized = normalizeControlUrl(value);
  if (applyNetwork) return normalized;
  const parsed = new URL(normalized);
  parsed.hostname = '127.0.0.1';
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

function pushControlRouteCandidates(candidates, seen, targetId, { localUrl = null } = {}) {
  if (targetId === state.nodeId && localUrl) {
    const key = `${localUrl}\u0000`;
    if (!seen.has(key)) {
      seen.add(key);
      candidates.push({ id: `local-${targetId}`, targetId, baseUrl: localUrl, remaining: [] });
    }
  }
  for (const route of shuffled(state.controlRoutesByTarget?.[targetId] || [])) {
    if (!Array.isArray(route.hops) || !route.hops.length || route.hops.length > MAX_PROBE_HOPS) continue;
    if (new Set(route.nodeIds || []).size !== (route.nodeIds || []).length) continue;
    const [first, ...remaining] = route.hops;
    try {
      const firstUrl = normalizeControlUrl(first.url);
      if (state.controlForwarders?.[first.nodeId] !== firstUrl) continue;
      const key = `${firstUrl}\u0000${remaining.map((hop) => `${hop.nodeId}:${hop.url}`).join('\u0000')}`;
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({ id: route.id, targetId, baseUrl: firstUrl, remaining });
    } catch {}
  }
}

function controlCandidates() {
  const candidates = [];
  const seen = new Set();
  const coordinatorId = state.controlCluster?.coordinatorNodeId;
  const leaderId = election.leaderId || coordinatorId;
  if (coordinatorId) {
    pushControlRouteCandidates(candidates, seen, coordinatorId, {
      localUrl: coordinatorId === state.nodeId ? localCoordinatorUrl : null,
    });
  }
  for (const targetId of shuffled(state.controlCluster?.voterIds || []).filter((id) => id && id !== coordinatorId)) {
    pushControlRouteCandidates(candidates, seen, targetId, {
      localUrl: targetId === state.nodeId ? localCoordinatorUrl : null,
    });
  }
  if (leaderId && leaderId !== coordinatorId) {
    pushControlRouteCandidates(candidates, seen, leaderId, {
      localUrl: leaderId === state.nodeId ? localCoordinatorUrl : null,
    });
  }
  if (state.upstream) {
    const baseUrl = normalizeControlUrl(state.upstream);
    const key = `${baseUrl}\u0000`;
    if (!seen.has(key)) {
      seen.add(key);
      candidates.push({
        id: 'coordinator-upstream',
        baseUrl,
        remaining: [],
        targetId: coordinatorId,
      });
    }
  }
  if (!state.controlCluster) {
    for (const route of shuffled(state.controlRoutes || [])) {
      if (!Array.isArray(route.hops) || !route.hops.length || route.hops.length > MAX_PROBE_HOPS) continue;
      if (new Set(route.nodeIds || []).size !== (route.nodeIds || []).length) continue;
      const [first, ...remaining] = route.hops;
      try {
        const firstUrl = normalizeControlUrl(first.url);
        if (state.controlForwarders?.[first.nodeId] !== firstUrl) continue;
        const key = `${firstUrl}\u0000${remaining.map((hop) => `${hop.nodeId}:${hop.url}`).join('\u0000')}`;
        if (seen.has(key)) continue;
        seen.add(key);
        candidates.push({ id: route.id, baseUrl: firstUrl, remaining });
      } catch {}
    }
  }
  return candidates;
}

async function api(pathname, options = {}) {
  const {
    credential = state.credential,
    timeout = 20_000,
    attemptTimeout = 5_000,
    ...requestOptions
  } = options;
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
      const response = await fetch(new URL(pathname, `${reachableControlUrl(candidate.baseUrl)}/`), {
        ...requestOptions,
        headers,
        signal: AbortSignal.timeout(Math.max(250, Math.min(attemptTimeout, remainingTime))),
      });
      if (response.status === 204) return null;
      const contentType = response.headers.get('content-type') ?? '';
      const body = contentType.includes('json') ? await response.json() : await response.text();
      if (!response.ok) {
        const message = body?.error || `控制路径返回 HTTP ${response.status}`;
        if (response.status === 401 && candidate.id === 'coordinator-upstream') {
          throw Object.assign(new Error(message), { terminal: true });
        }
        throw new Error(message);
      }
      if (state.controlCluster && candidate.targetId === (election.leaderId || state.controlCluster.coordinatorNodeId)) {
        election.noteLeader({
          term: state.controlCluster.term,
          leaderId: candidate.targetId,
          revision: Math.max(Number(state.controlCluster.revision || 0), Number(replica?.revision || 0)),
          leaseMs: coordinatorLeaseMs,
        });
        persistElection();
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
      hasPublicEndpoint: state.hasPublicEndpoint,
      reachabilityType: state.reachabilityType,
    }),
  });
  state = {
    ...state,
    nodeId: result.node.id,
    credential: result.credential,
    joinToken: null,
    networkId: result.node.networkId,
    reachabilityType: result.node.reachabilityType || state.reachabilityType,
    hasPublicEndpoint: result.node.hasPublicEndpoint,
  };
  election.nodeId = state.nodeId;
  atomicJson(stateFile, state);
  console.log(`节点 ${result.node.name} 已注册，业务地址 ${result.node.dataIp}`);
}

const wireguard = new WireGuardManager({
  dataDir,
  privateKey: state.dataKeys.privateKey,
  applyNetwork,
});

function applyCoordinatorUpstream(url) {
  if (!url || state.managedByParent || !applyNetwork) return;
  const normalized = normalizeControlUrl(url);
  if (state.upstream === normalized) return;
  state.upstream = normalized;
  atomicJson(stateFile, state);
}

function applyDesiredControlConfig(config) {
  state.controlRoutes = Array.isArray(config?.control?.routes) ? config.control.routes : [];
  state.controlRoutesByTarget = config?.control?.routesByTarget || {};
  state.controlForwarders = Object.fromEntries(Object.entries(config?.control?.forwarders || {}).map(
    ([nodeId, url]) => [nodeId, normalizeControlUrl(url)],
  ));
  applyClusterDescriptor(config?.control?.cluster);
  applyCoordinatorUpstream(config?.control?.coordinatorUrl);
}

async function applyDesiredConfig(desired) {
  if (!desired) return null;
  if (desired.phase === 'prepare' && state.preparedVersion !== desired.version) {
    try {
      await wireguard.prepare(desired.version, desired.config);
      state.preparedVersion = desired.version;
      applyDesiredControlConfig(desired.config);
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
      applyDesiredControlConfig(desired.config);
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

function installReplica(nextReplica) {
  if (!nextReplica || Number(nextReplica.schemaVersion) !== 1) throw new Error('协调快照格式无效');
  if (Number(nextReplica.revision || 0) < Number(replica?.revision || 0)) return false;
  atomicJson(replicaFile, nextReplica);
  replica = nextReplica;
  election.snapshotRevision = Math.max(election.snapshotRevision, Number(nextReplica.revision || 0));
  persistElection();
  return true;
}

async function syncReplica() {
  const response = await api('/agent/v1/replica-snapshot');
  if (response?.snapshot) installReplica(response.snapshot);
}

async function requestPeer(targetId, pathname, payload, timeout = 5_000) {
  const secret = state.controlCluster?.electionSecret;
  if (!secret) throw new Error('缺少协调选举凭据');
  const routes = shuffled(state.controlRoutesByTarget?.[targetId] || []);
  const failures = [];
  for (const route of routes) {
    if (!Array.isArray(route.hops) || !route.hops.length || route.hops.length > MAX_PROBE_HOPS) continue;
    const [first, ...remaining] = route.hops;
    try {
      const firstUrl = normalizeControlUrl(first.url);
      if (state.controlForwarders?.[first.nodeId] !== firstUrl) continue;
      const response = await fetch(new URL(pathname, `${reachableControlUrl(firstUrl)}/`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'X-PathWeaver-Relay-Trace': state.nodeId || state.agentInstanceId,
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

async function waitForCoordinator(url, child) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`本机协调服务提前退出：${child.exitCode}`);
    try {
      const response = await fetch(new URL('/healthz', `${url}/`), { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error('本机协调服务启动超时');
}

async function stopLocalCoordinator() {
  const child = coordinatorProcess;
  coordinatorProcess = null;
  localCoordinatorUrl = null;
  if (child?.exitCode === null) child.kill('SIGTERM');
}

async function startLocalCoordinator(term) {
  if (!replica) throw new Error('本机还没有可用于接管的协调快照');
  if (coordinatorProcess?.exitCode === null && localCoordinatorUrl) return;
  const coordinatorDir = join(dataDir, 'coordinator');
  mkdirSync(coordinatorDir, { recursive: true });
  const database = new Database(join(coordinatorDir, 'pathweaver.db'));
  try { database.importSnapshot(replica); } finally { database.close(); }
  state.coordinatorPort = await selectAvailableTcpPort({ preferred: state.coordinatorPort || 19774 });
  persistElection();
  const internalToken = randomBytes(32).toString('base64url');
  const url = `http://127.0.0.1:${state.coordinatorPort}`;
  const child = spawn(process.execPath, [coordinatorServerFile], {
    cwd: resolve(fileURLToPath(new URL('../..', import.meta.url))),
    stdio: ['ignore', 'inherit', 'inherit'],
    env: {
      ...process.env,
      NODE_ENV: 'production',
      SDWAN_HOST: '127.0.0.1',
      SDWAN_PORT: String(state.coordinatorPort),
      SDWAN_PUBLIC_URL: state.controlEndpoint || `http://127.0.0.1:${state.controlListenPort}`,
      SDWAN_DATA_DIR: coordinatorDir,
      SDWAN_ADMIN_TOKEN: internalToken,
      SDWAN_COORDINATOR_ONLY: '1',
      SDWAN_EXTERNAL_COORDINATOR: '1',
      SDWAN_PROMOTE_NODE_ID: state.nodeId,
      SDWAN_COORDINATOR_TERM: String(term),
      SDWAN_APPLY_NETWORK: '0',
    },
  });
  coordinatorProcess = child;
  child.once('exit', () => {
    if (coordinatorProcess === child) {
      coordinatorProcess = null;
      localCoordinatorUrl = null;
    }
  });
  await waitForCoordinator(url, child);
  localCoordinatorUrl = url;
  await syncReplica();
}

async function broadcastCoordinatorHeartbeat() {
  if (!state.controlCluster || election.leaderId !== state.nodeId || !localCoordinatorUrl) return;
  const heartbeat = {
    networkId: state.controlCluster.networkId,
    term: election.term,
    leaderId: state.nodeId,
    revision: Math.max(election.snapshotRevision, Number(replica?.revision || 0)),
    leaseMs: coordinatorLeaseMs,
  };
  await Promise.all((state.controlCluster.voterIds || []).filter((id) => id !== state.nodeId).map((id) =>
    requestPeer(id, '/peer/v1/election/heartbeat', heartbeat).catch(() => null)));
  election.noteLeader(heartbeat);
  persistElection();
}

async function maybeElectCoordinator() {
  const voterIds = state.controlCluster?.voterIds || [];
  if (!state.nodeId || !replica || !voterIds.includes(state.nodeId) || election.leaseUntil > Date.now()) return false;
  await new Promise((resolveWait) => setTimeout(resolveWait, randomInt(200, 1_200)));
  if (election.leaseUntil > Date.now()) return false;
  const request = election.beginElection();
  persistElection();
  let votes = 1;
  let leasedLeader = null;
  const responses = await Promise.all(voterIds.filter((id) => id !== state.nodeId).map((id) =>
    requestPeer(id, '/peer/v1/election/request-vote', {
      networkId: state.controlCluster.networkId,
      ...request,
    }).catch(() => null)));
  for (const response of responses) {
    if (response?.granted && Number(response.term) === election.term) votes += 1;
    if (response?.reason === 'leader-lease-active' && response?.leaderId) leasedLeader = response;
    if (Number(response?.term || 0) > election.term && response?.leaderId) {
      election.noteLeader({ term: response.term, leaderId: response.leaderId, revision: response.revision });
    }
  }
  if (leasedLeader) {
    election.followLease({
      term: leasedLeader.term,
      leaderId: leasedLeader.leaderId,
      revision: leasedLeader.revision,
      leaseMs: coordinatorLeaseMs,
    });
    state.controlCluster.coordinatorNodeId = leasedLeader.leaderId;
    state.controlCluster.term = Number(leasedLeader.term);
    persistElection();
    return false;
  }
  if (votes < 1) {
    persistElection();
    return false;
  }
  election.noteLeader({
    term: election.term,
    leaderId: state.nodeId,
    revision: Number(replica.revision || 0),
    leaseMs: coordinatorLeaseMs,
  });
  state.controlCluster.coordinatorNodeId = state.nodeId;
  state.controlCluster.term = election.term;
  persistElection();
  await startLocalCoordinator(election.term);
  await broadcastCoordinatorHeartbeat();
  return true;
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
  try {
    await requestManagedTarget(child, '/agent/v1/adopt/complete', {
      method: 'POST',
      body: JSON.stringify({ node: registered.node }),
    });
  } catch (error) {
    child.targetConfirmationPending = true;
    child.targetConfirmationError = error.message;
    atomicJson(stateFile, state);
    console.warn(`节点 ${registered.node.id} 已登记，目标确认将在后台重试：${error.message}`);
  }
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
  const child = await finishLocalAdoption(context, registered, registered.credential);
  return {
    ok: true,
    nodeId: registered.node.id,
    node: registered.node,
    targetConfirmationPending: Boolean(child.targetConfirmationPending),
  };
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
      const probe = await fetchViaInternalControlRoutes({
        targetId: command.payload.expectedNodeId,
        pathname: `/agent/v1/link-probe/${command.payload.validationId}`,
        routesByTarget: state.controlRoutesByTarget,
        forwarders: state.controlForwarders,
        relayTrace: state.nodeId || state.agentInstanceId,
        method: 'POST',
        body: JSON.stringify({
          token: command.payload.token,
          probeId,
          trace: [state.nodeId || state.agentInstanceId],
          remainingHops: maxHops - 1,
        }),
        timeout: 12_000,
        resolveUrl: reachableControlUrl,
      });
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
    } else if (command.type === 'probe-update-source') {
      result = await fetchUpdateArtifact(command.payload);
    } else if (command.type === 'install-update-bundle') {
      let payload = command.payload;
      if (!payload?.bundleBase64 || !payload?.installer) {
        const artifact = await api(`/agent/v1/update-artifacts/${payload.rolloutId}`, {
          timeout: 180_000,
          attemptTimeout: 120_000,
        });
        payload = { ...payload, ...artifact };
      }
      result = stageUpdateArtifact(payload);
    } else if (command.type === 'prepare-link-benchmark') {
      result = prepareBenchmark(state.pendingBenchmarks, command.payload);
      atomicJson(stateFile, state);
    } else if (command.type === 'execute-link-benchmark') {
      const expectedNodeId = String(command.payload.expectedNodeId || '');
      result = await executeBenchmark(command.payload, {
        measureSample: async () => {
          const sample = await fetchViaInternalControlRoutes({
            targetId: expectedNodeId,
            pathname: `/agent/v1/benchmark/${encodeURIComponent(command.payload.itemId)}?mode=latency`,
            routesByTarget: state.controlRoutesByTarget,
            forwarders: state.controlForwarders,
            relayTrace: state.nodeId || state.agentInstanceId,
            method: 'POST',
            headers: { 'X-PathWeaver-Benchmark-Token': String(command.payload.token || '') },
            body: Buffer.alloc(0),
            timeout: 20_000,
            resolveUrl: reachableControlUrl,
          });
          if (sample.nodeId !== expectedNodeId) throw new Error('延迟探测目标节点身份与预期不一致');
        },
      });
    } else {
      throw new Error(`不允许执行命令 ${command.type}`);
    }
  } catch (error) {
    result = { ok: false, error: error.message };
  }
  return result;
}

async function executeCommand(command) {
  const largeTransfer = ['probe-update-source', 'install-update-bundle'].includes(command.type);
  try {
    const result = await runCommand(command);
    await api(`/agent/v1/commands/${command.id}/complete`, {
      method: 'POST',
      body: JSON.stringify(result),
      timeout: largeTransfer ? 180_000 : 60_000,
      attemptTimeout: largeTransfer ? 120_000 : 30_000,
    });
  } catch (error) {
    if (largeTransfer) {
      console.error(`更新命令 ${command.type} 传输失败，将在租约到期后重试：`, error.message);
      return;
    }
    throw error;
  }
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
      updateAppliedRolloutId: health.updateApplied?.rolloutId,
      updateError: health.updateApplied?.ok === false ? health.updateApplied.error : null,
      linkHealth: health.linkHealth,
    }),
  });
  const desired = await api(`/agent/v1/config?currentVersion=${Number(child.currentVersion || 0)}`, {
    credential: child.credential,
  });
  let command = await api('/agent/v1/commands/next', { credential: child.credential });
  if (command?.type === 'install-update-bundle' && (!command.payload?.bundleBase64 || !command.payload?.installer)) {
    try {
      const artifact = await api(`/agent/v1/update-artifacts/${command.payload.rolloutId}`, {
        credential: child.credential,
        timeout: 180_000,
        attemptTimeout: 120_000,
      });
      command = { ...command, payload: { ...command.payload, ...artifact } };
    } catch (error) {
      console.error(`被认领节点 ${child.nodeId} 领取更新制品失败，将在租约到期后重试：`, error.message);
      return;
    }
  }
  const largeTransfer = ['probe-update-source', 'install-update-bundle'].includes(command?.type);
  const result = await requestManagedChild(child, '/agent/v1/managed/tick', {
    method: 'POST',
    body: JSON.stringify({ node: child.node, desired, command }),
    timeout: largeTransfer ? 180_000 : 30_000,
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
      timeout: ['probe-update-source', 'install-update-bundle'].includes(command.type) ? 180_000 : 60_000,
      attemptTimeout: ['probe-update-source', 'install-update-bundle'].includes(command.type) ? 120_000 : 30_000,
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
  const appliedUpdate = updateMarker();
  const heartbeat = await api('/agent/v1/heartbeat', {
    method: 'POST',
    body: JSON.stringify({
      agentVersion: '0.1.0',
      controlEndpoint: state.controlEndpoint,
      controlListenPort: state.controlListenPort,
      dataEndpoint: state.dataEndpoint,
      dataListenPort: state.dataListenPort,
      updateAppliedRolloutId: appliedUpdate?.rolloutId,
      updateError: appliedUpdate?.ok === false ? appliedUpdate.error : null,
      linkHealth,
    }),
  });
  applyClusterDescriptor(heartbeat?.cluster, { renewLease: true });
  applyCoordinatorUpstream(heartbeat?.coordinatorUrl);
  await syncConfig();
  await syncReplica().catch((error) => console.error('协调快照同步失败：', error.message));
  const command = await api('/agent/v1/commands/next');
  if (command) await executeCommand(command);
  for (const child of Object.values(state.managedChildren)) {
    await syncManagedChild(child).catch((error) => console.error(`被认领节点 ${child.nodeId} 同步失败：`, error.message));
  }
}

async function agentCycle() {
  try {
    await tick();
    consecutiveControlFailures = 0;
  } catch (error) {
    consecutiveControlFailures += 1;
    console.error('同步失败：', error.message);
    if (consecutiveControlFailures >= 2) await maybeElectCoordinator().catch((electionError) => {
      console.error('协调选举失败：', electionError.message);
    });
  }
  if (election.leaderId === state.nodeId && localCoordinatorUrl) {
    await broadcastCoordinatorHeartbeat().catch((error) => console.error('协调租约续期失败：', error.message));
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
  } else if (!targetUrl && state.controlCluster) {
    if (election.leaderId === state.nodeId) {
      targetUrl = localCoordinatorUrl;
    } else {
      const leader = controlCandidates().find((candidate) =>
        candidate.targetId === (election.leaderId || state.controlCluster.coordinatorNodeId));
      targetUrl = leader?.baseUrl || null;
      if (leader?.remaining?.length) remaining.splice(0, remaining.length, ...leader.remaining);
    }
  }
  if (!targetUrl) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: '中继节点没有可用的下一跳控制路径' }));
  }
  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks);
  const largeTransfer = /\/agent\/v1\/update-artifacts\//.test(req.url || '')
    || (req.method === 'POST' && /\/agent\/v1\/commands\/[^/]+\/complete/.test(req.url || '') && (body?.length || 0) > 256 * 1024);
  const upstream = await fetch(new URL(req.url, `${reachableControlUrl(targetUrl)}/`), {
    method: req.method,
    headers: {
      ...(req.headers.authorization ? { Authorization: req.headers.authorization } : {}),
      ...(req.headers['content-type'] ? { 'Content-Type': req.headers['content-type'] } : {}),
      'X-PathWeaver-Relay-Trace': relayTrace,
      ...(remaining.length ? { 'X-PathWeaver-Control-Route': encodeControlRoute(remaining) } : {}),
    },
    body,
    signal: AbortSignal.timeout(largeTransfer ? 180_000 : 30_000),
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
        updateApplied: updateMarker(),
        linkHealth,
      }));
    }
    const coordinatorPeerPath = [
      '/peer/v1/election/request-vote',
      '/peer/v1/election/heartbeat',
      '/peer/v1/replica/install',
      '/peer/v1/coordinator-panel',
    ].includes(req.url);
    if (coordinatorPeerPath && decodeControlRoute(req.headers['x-pathweaver-control-route']).length) {
      return await proxy(req, res);
    }
    if (coordinatorPeerPath) {
      if (!state.controlCluster?.electionSecret || !safeEqualText(bearerToken(req), state.controlCluster.electionSecret)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: '协调节点间凭据无效' }));
      }
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      if (input.networkId !== state.controlCluster.networkId) throw new Error('协调请求所属节点组不匹配');
      if (req.url === '/peer/v1/election/request-vote') {
        const result = election.requestVote(input);
        if (result.granted && localCoordinatorUrl) await stopLocalCoordinator();
        persistElection();
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({
          ...result,
          leaderId: election.leaderId,
          revision: election.snapshotRevision,
        }));
      }
      if (req.url === '/peer/v1/election/heartbeat') {
        const result = election.noteLeader(input);
        if (result.accepted) {
          state.controlCluster.coordinatorNodeId = input.leaderId;
          state.controlCluster.term = Number(input.term);
          state.controlCluster.revision = Math.max(Number(state.controlCluster.revision || 0), Number(input.revision || 0));
          if (input.leaderId !== state.nodeId && localCoordinatorUrl) await stopLocalCoordinator();
          persistElection();
        }
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({
          ...result,
          leaderId: election.leaderId,
          revision: election.snapshotRevision,
        }));
      }
      if (req.url === '/peer/v1/replica/install') {
        installReplica(input.snapshot);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({ ok: true, revision: election.snapshotRevision }));
      }
      if (req.url === '/peer/v1/coordinator-panel') {
        if (election.leaderId !== state.nodeId || !localCoordinatorUrl) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: '请求未到达当前配置协调节点' }));
        }
        const upstream = await fetch(new URL('/peer/v1/coordinator-panel', `${localCoordinatorUrl}/`), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: req.headers.authorization,
          },
          body: JSON.stringify(input),
          signal: AbortSignal.timeout(30_000),
        });
        const body = Buffer.from(await upstream.arrayBuffer());
        res.writeHead(upstream.status, {
          'Content-Type': upstream.headers.get('content-type') || 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        return res.end(body);
      }
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
    const requestUrl = new URL(req.url, 'http://pathweaver.local');
    if (await handleBenchmarkRequest(
      req, res, requestUrl.pathname, requestUrl, state.pendingBenchmarks,
      state.nodeId || state.agentInstanceId,
    )) return;
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
      pending.probeResponses ||= {};
      if (pending.probeResponses[accepted.probeId]) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(pending.probeResponses[accepted.probeId]));
      }
      pending.seenProbeIds = [...pending.seenProbeIds.slice(-63), accepted.probeId];
      const response = {
        ok: true,
        nodeId: state.nodeId,
        probeId: accepted.probeId,
        trace: accepted.trace,
        remainingHops: accepted.remainingHops,
        reachedAt: new Date().toISOString(),
      };
      pending.probeResponses[accepted.probeId] = response;
      const retained = new Set(pending.seenProbeIds);
      for (const id of Object.keys(pending.probeResponses)) if (!retained.has(id)) delete pending.probeResponses[id];
      atomicJson(stateFile, state);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(response));
    }
    const proxyPathname = new URL(req.url, 'http://pathweaver.local').pathname;
    if (proxyPathname.startsWith('/agent/v1/') || proxyPathname === '/install.sh' || proxyPathname.startsWith('/artifacts/')) {
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
  const cycle = setInterval(() => void agentCycle(), pollInterval);
  cycle.unref();
  void agentCycle();
});

function shutdown() {
  if (coordinatorProcess?.exitCode === null) coordinatorProcess.kill('SIGTERM');
  relayServer.close(() => process.exit(0));
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
