import { randomBytes } from 'node:crypto';

const now = () => new Date().toISOString();

function normalizedTargetUrl(value) {
  let parsed;
  try { parsed = new URL(String(value || '')); } catch { throw new Error('待认领节点地址无效'); }
  if (parsed.protocol !== 'http:') throw new Error('待认领 Agent 当前只支持 HTTP 控制入口');
  if (!parsed.hostname || !parsed.port || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('待认领节点地址必须包含 IP 或域名和控制端口');
  }
  return parsed.href.replace(/\/$/, '');
}

function endpointHost(parsed) {
  return parsed.hostname.includes(':') ? `[${parsed.hostname}]` : parsed.hostname;
}

export class CenterManagedNodes {
  constructor(service, options = {}) {
    this.service = service;
    this.panelProxy = options.panelProxy ?? null;
    this.running = false;
  }

  async request(proxy, pathname, options = {}) {
    const response = await fetch(new URL(pathname, `${proxy.targetUrl}/`), {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${proxy.sessionToken}`,
        ...(options.headers ?? {}),
      },
      signal: AbortSignal.timeout(options.timeout ?? 20_000),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `被认领节点返回 HTTP ${response.status}`);
    return body;
  }

  async requestProxy(proxy, pathname, options = {}) {
    const route = proxy.relayPath || [];
    if (!route.length) return this.request(proxy, pathname, options);
    const firstRelay = this.proxies().find((item) => item.nodeId === route[0]);
    if (!firstRelay || firstRelay.relayPath.length) throw new Error('中心代理路径无效');
    return this.request(firstRelay, '/agent/v1/managed/relay', {
      method: 'POST',
      timeout: options.timeout ?? 30_000,
      body: JSON.stringify({
        path: route.slice(1),
        childNodeId: proxy.nodeId,
        pathname,
        request: {
          method: options.method || 'GET',
          body: options.body,
          timeout: options.timeout,
        },
      }),
    });
  }

  async adopt(managerNodeId, payload) {
    const manager = this.service.getNode(managerNodeId);
    if (!manager.isCenter) throw new Error('中心代理认领只能替中心节点执行');
    const targetUrl = normalizedTargetUrl(payload.targetUrl);
    const sessionToken = `pws_${randomBytes(32).toString('base64url')}`;
    const response = await fetch(new URL('/agent/v1/adopt', `${targetUrl}/`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ claimToken: payload.claimToken, sessionToken }),
      signal: AbortSignal.timeout(20_000),
    });
    const descriptor = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(descriptor.error || `目标返回 HTTP ${response.status}`);
    if (!descriptor.agent?.dataListenPort) throw new Error('目标没有返回 WireGuard 监听端口');

    const reachedTarget = new URL(`${targetUrl}/`);
    const registered = this.service.registerAgent({
      token: payload.claimToken,
      passive: true,
      ...descriptor.agent,
      controlEndpoint: targetUrl,
      controlListenPort: Number(reachedTarget.port),
      dataEndpoint: `${endpointHost(reachedTarget)}:${descriptor.agent.dataListenPort}`,
    });
    const timestamp = now();
    this.service.db.run(
      `INSERT INTO managed_node_proxies(
        node_id, manager_node_id, target_url, session_token, relay_path_json, current_version, created_at, updated_at
      ) VALUES (?, ?, ?, ?, '[]', 0, ?, ?)
      ON CONFLICT(node_id) DO UPDATE SET manager_node_id = excluded.manager_node_id,
        target_url = excluded.target_url, session_token = excluded.session_token, updated_at = excluded.updated_at`,
      registered.node.id, manager.id, targetUrl, sessionToken, timestamp, timestamp,
    );
    const proxy = { nodeId: registered.node.id, targetUrl, sessionToken };
    let targetConfirmationPending = false;
    let warning = null;
    try {
      await this.request(proxy, '/agent/v1/adopt/complete', {
        method: 'POST',
        body: JSON.stringify({ node: registered.node }),
      });
    } catch (error) {
      targetConfirmationPending = true;
      warning = `节点已登记，目标确认将在后台重试：${error.message}`;
      console.warn(warning);
    }
    return {
      ok: true,
      node: registered.node,
      manager,
      versionId: registered.versionId,
      targetConfirmationPending,
      ...(warning ? { warning } : {}),
    };
  }

  proxies() {
    return this.service.db.all(
      'SELECT node_id, manager_node_id, target_url, session_token, relay_path_json, current_version FROM managed_node_proxies',
    ).map((row) => ({
      nodeId: row.node_id,
      managerNodeId: row.manager_node_id,
      targetUrl: row.target_url,
      sessionToken: row.session_token,
      relayPath: JSON.parse(row.relay_path_json || '[]'),
      currentVersion: Number(row.current_version || 0),
    }));
  }

  async reconcileProxy(proxy) {
    const node = this.service.getNode(proxy.nodeId);
    const health = await this.requestProxy(proxy, '/healthz', { method: 'GET', timeout: 10_000 });
    if (this.panelProxy) {
      const panelRequests = await this.requestProxy(proxy, '/agent/v1/managed/panel-requests', {
        method: 'GET', timeout: 10_000,
      }).catch(() => ({ requests: [] }));
      for (const request of panelRequests.requests ?? []) {
        let result;
        try {
          result = await this.panelProxy(request.input);
        } catch (error) {
          const payload = Buffer.from(JSON.stringify({ error: error.message }), 'utf8').toString('base64');
          result = { status: error.statusCode || 502, contentType: 'application/json; charset=utf-8', body: payload };
        }
        await this.requestProxy(proxy, '/agent/v1/managed/panel-results', {
          method: 'POST',
          body: JSON.stringify({ id: request.id, result }),
          timeout: 10_000,
        });
      }
    }
    this.service.heartbeat(node.id, {
      agentVersion: '0.1.0',
      controlEndpoint: node.controlEndpoint,
      controlListenPort: Number(health.controlListenPort || node.controlListenPort),
      dataEndpoint: node.dataEndpoint,
      dataListenPort: Number(health.dataListenPort || node.dataListenPort),
      linkHealth: health.linkHealth,
    });
    const desired = this.service.getDesiredConfig(node.id, proxy.currentVersion);
    const command = this.service.claimCommand(node.id);
    let result;
    try {
      result = await this.requestProxy(proxy, '/agent/v1/managed/tick', {
        method: 'POST',
        body: JSON.stringify({ node, desired, command }),
        timeout: 30_000,
      });
    } catch (error) {
      if (command) this.service.completeCommand(node.id, command.id, { ok: false, error: error.message });
      throw error;
    }
    if (result.currentVersion !== undefined) {
      this.service.db.run(
        'UPDATE managed_node_proxies SET current_version = ?, updated_at = ? WHERE node_id = ?',
        Number(result.currentVersion), now(), node.id,
      );
    }
    if (result.configReport) {
      this.service.reportConfig(
        node.id,
        result.configReport.versionId,
        result.configReport.phase,
        result.configReport.error,
      );
    }
    if (command && result.commandResult) {
      let commandResult = result.commandResult;
      if (commandResult.delegatedAdoption) {
        const context = commandResult.delegatedAdoption;
        const registered = this.service.registerAgent({
          token: context.claimToken,
          passive: true,
          ...context.agent,
        });
        const relayPath = [...proxy.relayPath, proxy.nodeId];
        const timestamp = now();
        this.service.db.run(
          `INSERT INTO managed_node_proxies(
            node_id, manager_node_id, target_url, session_token, relay_path_json,
            current_version, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
          registered.node.id, node.id, context.targetUrl, context.sessionToken,
          JSON.stringify(relayPath), timestamp, timestamp,
        );
        await this.requestProxy(proxy, '/agent/v1/managed/adoption-complete', {
          method: 'POST',
          body: JSON.stringify({ context, node: registered.node }),
        });
        commandResult = { ok: true, nodeId: registered.node.id, node: registered.node };
      }
      this.service.completeCommand(node.id, command.id, commandResult);
    }
  }

  async tick() {
    if (this.running) return;
    this.running = true;
    try {
      for (const proxy of this.proxies()) {
        await this.reconcileProxy(proxy).catch((error) => {
          console.error(`中心代理节点 ${proxy.nodeId} 同步失败：`, error.message);
        });
      }
    } finally {
      this.running = false;
    }
  }
}
