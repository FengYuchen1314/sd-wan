import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Database } from './database.js';
import { createCenterBundle } from './center-bundle.js';
import { CenterDataPlane } from './data-plane.js';
import { CenterManagedNodes } from './managed-nodes.js';
import { ControlService } from './service.js';
import { WireGuardArtifactStore, wireGuardRuntimeManifest } from './wireguard-artifacts.js';
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

if (!adminToken && !adminPasswordHash) {
  throw new Error('生产环境必须设置面板密码哈希');
}

const database = new Database(join(dataDir, 'pathweaver.db'));
const service = new ControlService(database, {
  publicUrl,
  nodeOfflineAfterMs,
  defaultDataPort,
  manageLocalCenters: true,
});
const wireGuardArtifacts = new WireGuardArtifactStore(join(dataDir, 'artifacts', 'wireguard'));
service.ensureDefaultNetwork();
const centerDataPlane = new CenterDataPlane(service, {
  dataDir,
  applyNetwork: process.env.SDWAN_APPLY_NETWORK === '1' && process.platform === 'linux',
  wireguardDir: process.env.SDWAN_WIREGUARD_DIR || (process.platform === 'linux' ? '/etc/wireguard' : undefined),
  runtimeDir: process.env.SDWAN_WIREGUARD_RUNTIME_DIR,
});
void centerDataPlane.tick().catch((error) => console.error('center data plane reconciliation failed:', error));
const centerDataPlaneSweep = setInterval(() => {
  void centerDataPlane.tick().catch((error) => console.error('center data plane reconciliation failed:', error));
}, Math.max(1_000, runtimeSweepIntervalMs));
centerDataPlaneSweep.unref();
const centerManagedNodes = new CenterManagedNodes(service, { panelProxy: dispatchPanelEnvelope });
void centerManagedNodes.tick().catch((error) => console.error('center managed-node reconciliation failed:', error));
const centerManagedNodesSweep = setInterval(() => {
  void centerManagedNodes.tick().catch((error) => console.error('center managed-node reconciliation failed:', error));
}, Math.max(1_000, runtimeSweepIntervalMs));
centerManagedNodesSweep.unref();
service.reconcileRuntimeState();
const runtimeSweep = setInterval(() => {
  try {
    service.reconcileRuntimeState();
  } catch (error) {
    console.error(`[${new Date().toISOString()}] runtime state sweep failed:`, error);
  }
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

async function readJson(req) {
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 1_048_576) throw new Error('请求内容超过 1 MiB 限制');
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new Error('请求 JSON 格式无效');
  }
}

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
  if (!filename.startsWith(publicDir)) return false;
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

async function handleAdmin(req, res, pathname, url, authenticated = false) {
  if (!authenticated) requireAdmin(req);
  if (req.method === 'GET' && pathname === '/api/v1/panel-status') {
    return send(res, 200, {
      synchronized: true,
      syncMode: 'live-control-state',
      panelPort: port,
      message: '所有节点面板通过无环控制路径读写同一份版本化配置',
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
        source = parsedSource.href.replace(/\/$/, '');
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
    if (pathname.startsWith('/api/v1/') || pathname.startsWith('/agent/v1/')) service.reconcileRuntimeState();
    if (pathname.startsWith('/api/v1/')) return await handleAdmin(req, res, pathname, url);
    if (pathname.startsWith('/agent/v1/')) return await handleAgent(req, res, pathname, url);
    if (req.method === 'GET' && serveStatic(pathname, res)) return;
    if (req.method === 'GET' && !pathname.includes('.')) return serveStatic('/', res);
    return send(res, 404, { error: '资源不存在' });
  } catch (error) {
    const status = error.statusCode || (error.message?.includes('不存在') ? 404 : 400);
    console.error(`[${new Date().toISOString()}] ${req.method} ${pathname}:`, error);
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
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
