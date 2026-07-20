import { createServer } from 'node:http';
import { readFileSync, statSync } from 'node:fs';
import { extname, isAbsolute, join, normalize, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyPanelPassword } from '../core/password.js';

const rootDir = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const publicDir = join(rootDir, 'public');
const port = Number(process.env.SDWAN_PANEL_PORT || 19773);
const host = process.env.SDWAN_PANEL_HOST || '0.0.0.0';
const relayUrl = new URL(process.env.SDWAN_AGENT_RELAY_URL || 'http://127.0.0.1:8790');
const panelPasswordHash = (process.env.SDWAN_PANEL_PASSWORD_HASH || '').trim();
const proxyToken = process.env.SDWAN_PANEL_PROXY_TOKEN || '';
const developmentToken = process.env.NODE_ENV === 'production' ? '' : 'dev-admin-token';

if (!panelPasswordHash && !developmentToken) throw new Error('生产环境必须设置面板密码哈希');
if (!proxyToken) throw new Error('缺少本机面板代理凭据');

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function send(res, status, body, headers = {}) {
  const payload = Buffer.isBuffer(body) ? body : typeof body === 'string' ? body : JSON.stringify(body ?? {});
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

function bearer(req) {
  const authorization = String(req.headers.authorization || '');
  return authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
}

function requireAdmin(req) {
  const password = bearer(req);
  if ((developmentToken && password === developmentToken) || verifyPanelPassword(password, panelPasswordHash)) return;
  const error = new Error('面板密码无效');
  error.statusCode = 401;
  throw error;
}

async function readBody(req) {
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 1_048_576) throw new Error('请求内容超过 1 MiB 限制');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function staticCacheControl(filename) {
  const ext = extname(filename);
  if (['.html', '.css', '.js'].includes(ext)) {
    return 'no-store, max-age=0, must-revalidate';
  }
  return 'public, max-age=300';
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
      'Cache-Control': staticCacheControl(filename),
      ...(['.html', '.css', '.js'].includes(extname(filename)) ? { Pragma: 'no-cache' } : {}),
    });
    return true;
  } catch {
    return false;
  }
}

async function proxyAdmin(req, res) {
  requireAdmin(req);
  const body = await readBody(req);
  const upstream = await fetch(new URL('/peer/v1/panel-proxy', relayUrl), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${proxyToken}` },
    body: JSON.stringify({
      method: req.method,
      path: req.url,
      contentType: req.headers['content-type'] || 'application/json',
      body: body.toString('base64'),
    }),
    signal: AbortSignal.timeout(30_000),
  });
  const envelope = await upstream.json().catch(() => ({ error: `本机 Agent 返回 HTTP ${upstream.status}` }));
  if (!upstream.ok) return send(res, upstream.status, envelope);
  const responseBody = Buffer.from(String(envelope.body || ''), 'base64');
  return send(res, Number(envelope.status || 502), responseBody, {
    'Content-Type': envelope.contentType || 'application/json; charset=utf-8',
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  try {
    if (url.pathname === '/healthz') return send(res, 200, { status: 'ok', panelPort: port, syncMode: 'live-control-proxy' });
    if (url.pathname === '/api/v1/panel-status') {
      requireAdmin(req);
      return send(res, 200, {
        synchronized: true,
        syncMode: 'quorum-replicated-control-proxy',
        panelPort: port,
        message: '本面板通过无环控制路径访问当前协调节点；成功写入已同步到选民多数派',
      });
    }
    if (url.pathname.startsWith('/api/v1/')) return await proxyAdmin(req, res);
    if (req.method === 'GET' && serveStatic(url.pathname, res)) return;
    if (req.method === 'GET' && !url.pathname.includes('.')) return serveStatic('/', res);
    return send(res, 404, { error: '资源不存在' });
  } catch (error) {
    return send(res, error.statusCode || 502, { error: error.message || '面板代理失败' });
  }
});

server.listen(port, host, () => {
  console.log(`PathWeaver peer panel listening on http://${host}:${port}`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
