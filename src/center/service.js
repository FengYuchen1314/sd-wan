import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { parseCIDR, parseIPv4, usableHost } from '../core/ipv4.js';
import { enumerateSimplePaths } from '../core/paths.js';
import { validateAndCompileTopology } from '../core/topology.js';

const now = () => new Date().toISOString();
const hashSecret = (value) => createHash('sha256').update(String(value)).digest('hex');
const json = (value) => JSON.stringify(value ?? {});
const DEFAULT_DATA_PORT = 19801;

function normalizePort(value, label = 'WireGuard 端口', fallback = undefined) {
  if (value === undefined || value === null || value === '') {
    if (fallback !== undefined) return fallback;
    throw new Error(`${label}不能为空`);
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${label}必须是 1 到 65535 的整数`);
  return port;
}

function endpointPort(endpoint) {
  const match = String(endpoint ?? '').trim().match(/:(\d+)$/);
  return match ? normalizePort(match[1]) : null;
}

function normalizeReachableHost(value, label) {
  const host = String(value ?? '').trim();
  if (!host) throw new Error(`${label}不能为空`);
  if (host.includes('://') || host.includes('/') || /\s/.test(host)) {
    throw new Error(`${label}只能填写 IP 或域名，不要包含协议、路径和端口`);
  }
  if (/^\d+(\.\d+){3}$/.test(host)) {
    parseIPv4(host);
    return host;
  }
  if (/^\[[0-9a-f:]+\]$/i.test(host)) return host.toLowerCase();
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(host)) {
    throw new Error(`${label}不是有效的 IP 或域名`);
  }
  return host.toLowerCase();
}

function endpointHost(endpoint) {
  if (endpoint.startsWith('[')) return endpoint.slice(0, endpoint.indexOf(']') + 1);
  return endpoint.slice(0, endpoint.lastIndexOf(':'));
}

function wireGuardKeyPair() {
  const pair = generateKeyPairSync('x25519');
  const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' });
  return {
    privateKey: privateDer.subarray(privateDer.length - 32).toString('base64'),
    publicKey: publicDer.subarray(publicDer.length - 32).toString('base64'),
  };
}

function networkFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    dataCidr: row.data_cidr,
    controlCidr: row.control_cidr,
    listenPort: Number(row.listen_port),
    mtu: Number(row.mtu),
    createdAt: row.created_at,
  };
}

function nodeFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    networkId: row.network_id,
    name: row.name,
    status: row.status,
    isCenter: Boolean(row.is_center),
    canRelay: Boolean(row.can_relay),
    parentId: row.parent_id,
    controlIp: row.control_ip,
    dataIp: row.data_ip,
    controlEndpoint: row.control_endpoint,
    dataEndpoint: row.data_endpoint,
    dataListenPort: Number(row.data_listen_port || DEFAULT_DATA_PORT),
    wgControlPublicKey: row.wg_control_public_key,
    wgDataPublicKey: row.wg_data_public_key,
    agentVersion: row.agent_version,
    lastSeen: row.last_seen,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function canonicalNodePair(nodeAId, nodeBId) {
  return String(nodeAId).localeCompare(String(nodeBId)) <= 0
    ? [nodeAId, nodeBId]
    : [nodeBId, nodeAId];
}

export class ControlService {
  constructor(database, options = {}) {
    this.db = database;
    this.publicUrl = String(options.publicUrl ?? 'http://127.0.0.1:8787').replace(/\/$/, '');
    const offlineAfterMs = Number(options.nodeOfflineAfterMs ?? 20_000);
    this.nodeOfflineAfterMs = Number.isFinite(offlineAfterMs) && offlineAfterMs > 0 ? offlineAfterMs : 20_000;
  }

  reconcileRuntimeState(at = new Date()) {
    const checkedAt = at instanceof Date ? at : new Date(at);
    if (Number.isNaN(checkedAt.getTime())) throw new Error('运行状态校验时间无效');
    const timestamp = checkedAt.toISOString();
    const offlineBefore = new Date(checkedAt.getTime() - this.nodeOfflineAfterMs).toISOString();
    const staleNodes = this.db.all(
      `SELECT id, name FROM nodes
       WHERE is_center = 0 AND status = 'online' AND (last_seen IS NULL OR last_seen < ?)`,
      offlineBefore,
    );
    const expiredLinks = this.db.all(
      `SELECT id, validation_status FROM topology_links
       WHERE validation_status IN ('preparing', 'probing')
         AND validation_expires_at IS NOT NULL AND validation_expires_at <= ?`,
      timestamp,
    );
    const expiredLinkIds = new Set(expiredLinks.map((link) => link.id));

    if (!staleNodes.length && !expiredLinks.length) return { offlineNodes: 0, expiredLinks: 0, cancelledCommands: 0 };

    let cancelledCommands = 0;
    this.db.transaction(() => {
      for (const node of staleNodes) {
        this.db.run("UPDATE nodes SET status = 'offline', updated_at = ? WHERE id = ?", timestamp, node.id);
        this.audit('agent.offline', 'node', node.id, { lastSeenBefore: offlineBefore });
      }

      for (const link of expiredLinks) {
        const error = link.validation_status === 'preparing'
          ? '验证超时：Agent 未在有效期内完成准备'
          : '验证超时：节点未在有效期内完成双向探测';
        this.db.run(
          `UPDATE topology_links SET validation_status = 'failed', validation_error = ?, validation_token = NULL
           WHERE id = ?`,
          error, link.id,
        );
        this.audit('topology-link.expired', 'topology-link', link.id, { previousStatus: link.validation_status, error });
      }

      const queuedCommands = this.db.all(
        `SELECT id, payload_json FROM commands
         WHERE status IN ('pending', 'running') AND type IN ('prepare-link-probe', 'execute-link-probe')`,
      );
      for (const command of queuedCommands) {
        let payload;
        try { payload = JSON.parse(command.payload_json); } catch { continue; }
        if (!expiredLinkIds.has(payload.validationId)) continue;
        this.db.run(
          `UPDATE commands SET status = 'failed', result_json = ?, completed_at = ? WHERE id = ?`,
          json({ ok: false, error: '连接验证已超时，命令已取消' }), timestamp, command.id,
        );
        cancelledCommands += 1;
      }
    });

    return { offlineNodes: staleNodes.length, expiredLinks: expiredLinks.length, cancelledCommands };
  }

  audit(action, resourceType, resourceId, detail = {}, actor = 'admin') {
    this.db.run(
      'INSERT INTO audit_log(actor, action, resource_type, resource_id, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      actor, action, resourceType, resourceId ?? null, json(detail), now(),
    );
  }

  ensureDefaultNetwork() {
    const existing = this.db.get('SELECT id FROM networks ORDER BY created_at LIMIT 1');
    if (existing) {
      this.ensureCenterKeys();
      return existing.id;
    }
    return this.createNetwork({
      name: '默认网络',
      dataCidr: '10.77.0.0/16',
      controlCidr: '10.254.0.0/16',
      listenPort: DEFAULT_DATA_PORT,
      mtu: 1380,
    }).id;
  }

  ensureCenterKeys() {
    const centers = this.db.all(`
      SELECT n.*, k.node_id AS has_local_keys FROM nodes n
      LEFT JOIN local_node_keys k ON k.node_id = n.id
      WHERE n.is_center = 1
    `);
    for (const center of centers) {
      if (center.has_local_keys && center.wg_control_public_key && center.wg_data_public_key) continue;
      const controlKeys = wireGuardKeyPair();
      const dataKeys = wireGuardKeyPair();
      this.db.transaction(() => {
        this.db.run(
          'UPDATE nodes SET wg_control_public_key = ?, wg_data_public_key = ?, updated_at = ? WHERE id = ?',
          controlKeys.publicKey, dataKeys.publicKey, now(), center.id,
        );
        this.db.run(
          `INSERT INTO local_node_keys(node_id, control_private_key, data_private_key, created_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(node_id) DO UPDATE SET control_private_key = excluded.control_private_key,
             data_private_key = excluded.data_private_key`,
          center.id, controlKeys.privateKey, dataKeys.privateKey, now(),
        );
      });
    }
  }

  createNetwork(input) {
    const name = String(input.name ?? '').trim();
    if (!name) throw new Error('节点组名称不能为空');
    const data = parseCIDR(input.dataCidr ?? '10.77.0.0/16');
    const control = parseCIDR(input.controlCidr ?? '10.254.0.0/16');
    if (!(data.broadcast < control.network || control.broadcast < data.network)) {
      throw new Error('业务网段与控制网段不能重叠');
    }
    const listenPort = Number(input.listenPort ?? DEFAULT_DATA_PORT);
    const mtu = Number(input.mtu ?? 1380);
    if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) throw new Error('监听端口无效');
    if (!Number.isInteger(mtu) || mtu < 576 || mtu > 9000) throw new Error('MTU 无效');

    const id = randomUUID();
    const centerId = randomUUID();
    const timestamp = now();
    const centerControlKeys = wireGuardKeyPair();
    const centerDataKeys = wireGuardKeyPair();
    let centerDataEndpoint = null;
    try {
      centerDataEndpoint = `${new URL(this.publicUrl).hostname}:${listenPort}`;
    } catch {}
    this.db.transaction(() => {
      this.db.run(
        'INSERT INTO networks(id, name, data_cidr, control_cidr, listen_port, mtu, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        id, name, data.cidr, control.cidr, listenPort, mtu, timestamp,
      );
      this.db.run(
        `INSERT INTO nodes(id, network_id, name, status, is_center, can_relay, parent_id, control_ip, data_ip,
          control_endpoint, data_endpoint, data_listen_port, wg_control_public_key, wg_data_public_key,
          created_at, updated_at, last_seen)
         VALUES (?, ?, ?, 'online', 1, 1, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        centerId, id, '中心节点', usableHost(control, 1), usableHost(data, 1), this.publicUrl, centerDataEndpoint,
        listenPort, centerControlKeys.publicKey, centerDataKeys.publicKey, timestamp, timestamp, timestamp,
      );
      this.db.run(
        'INSERT INTO local_node_keys(node_id, control_private_key, data_private_key, created_at) VALUES (?, ?, ?, ?)',
        centerId, centerControlKeys.privateKey, centerDataKeys.privateKey, timestamp,
      );
      this.createVersionInTransaction(id, '创建节点组');
      this.audit('network.create', 'network', id, { name, dataCidr: data.cidr, controlCidr: control.cidr });
    });
    return this.getNetwork(id);
  }

  listNetworks() {
    return this.db.all(`
      SELECT n.*,
        (SELECT COUNT(*) FROM nodes d WHERE d.network_id = n.id) AS node_count,
        (SELECT COUNT(*) FROM nodes d WHERE d.network_id = n.id AND d.status = 'online') AS online_count,
        (SELECT MAX(version) FROM config_versions v WHERE v.network_id = n.id) AS latest_version
      FROM networks n ORDER BY n.created_at
    `).map((row) => ({
      ...networkFromRow(row),
      nodeCount: Number(row.node_count),
      onlineCount: Number(row.online_count),
      latestVersion: Number(row.latest_version ?? 0),
    }));
  }

  getNetwork(id) {
    const row = this.db.get('SELECT * FROM networks WHERE id = ?', id);
    if (!row) throw new Error('节点组不存在');
    return networkFromRow(row);
  }

  listNodes(networkId) {
    return this.db.all('SELECT * FROM nodes WHERE network_id = ? ORDER BY is_center DESC, created_at', networkId).map(nodeFromRow);
  }

  getNode(id) {
    const row = this.db.get('SELECT * FROM nodes WHERE id = ?', id);
    if (!row) throw new Error('节点不存在');
    return nodeFromRow(row);
  }

  listLinks(networkId, activeOnly = false) {
    const condition = activeOnly ? " AND validation_status = 'active'" : '';
    return this.db.all(`SELECT * FROM topology_links WHERE network_id = ?${condition} ORDER BY priority, created_at`, networkId)
      .map((row) => ({
        id: row.id,
        upstreamId: row.upstream_id,
        downstreamId: row.downstream_id,
        priority: Number(row.priority),
        upstreamEndpoint: row.upstream_endpoint,
        downstreamEndpoint: row.downstream_endpoint,
        validationStatus: row.validation_status ?? 'active',
        validationError: row.validation_error,
        validationProgress: {
          prepared: Number(row.validation_prepared_upstream ?? 0) + Number(row.validation_prepared_downstream ?? 0),
          probed: Number(row.validation_probed_upstream ?? 0) + Number(row.validation_probed_downstream ?? 0),
        },
        validationExpiresAt: row.validation_expires_at,
        validatedAt: row.validated_at,
      }));
  }

  listPathPolicies(networkId) {
    return this.db.all(
      'SELECT * FROM path_policies WHERE network_id = ? ORDER BY source_id, target_id', networkId,
    ).map((row) => ({
      id: row.id,
      networkId: row.network_id,
      sourceId: row.source_id,
      targetId: row.target_id,
      mode: row.mode,
      paths: JSON.parse(row.paths_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  getPathOptions(networkId, sourceId, targetId) {
    const source = this.getNode(sourceId);
    const target = this.getNode(targetId);
    if (source.networkId !== networkId || target.networkId !== networkId) throw new Error('所选节点不属于当前节点组');
    if (source.id === target.id) throw new Error('请选择两个不同的节点');
    const nodes = this.listNodes(networkId);
    const links = this.listLinks(networkId, true);
    const result = enumerateSimplePaths({ nodes, links, sourceId: source.id, targetId: target.id });
    const nodeById = new Map(nodes.map((node) => [node.id, node]));
    const [canonicalSourceId, canonicalTargetId] = canonicalNodePair(source.id, target.id);
    const policy = this.listPathPolicies(networkId).find((item) =>
      item.sourceId === canonicalSourceId && item.targetId === canonicalTargetId);
    const selectedWeights = new Map((policy?.paths ?? []).map((path) => [path.pathId, Number(path.weight)]));

    return {
      source,
      target,
      paths: result.paths.map((path) => ({
        ...path,
        nodes: path.nodeIds.map((nodeId) => {
          const node = nodeById.get(nodeId);
          return { id: node.id, name: node.name, dataIp: node.dataIp, status: node.status };
        }),
        selected: selectedWeights.has(path.id),
        weight: selectedWeights.get(path.id) ?? 1,
      })),
      truncated: result.truncated,
      policy: policy ? {
        id: policy.id,
        mode: policy.mode,
        paths: policy.paths.map((path) => ({ pathId: path.pathId, weight: Number(path.weight) })),
        updatedAt: policy.updatedAt,
      } : null,
    };
  }

  savePathPolicy(networkId, input) {
    const details = this.getPathOptions(networkId, input.sourceId, input.targetId);
    const requested = Array.isArray(input.paths) ? input.paths : [];
    if (requested.length < 2) throw new Error('负载均衡至少需要选择两条无环路径');
    const available = new Map(details.paths.map((path) => [path.id, path]));
    const seen = new Set();
    const [sourceId, targetId] = canonicalNodePair(details.source.id, details.target.id);
    const selectedPaths = requested.map((selection) => {
      const option = available.get(selection.pathId);
      if (!option || seen.has(selection.pathId)) throw new Error('所选路径不存在、已失效或重复');
      seen.add(selection.pathId);
      const weight = Number(selection.weight);
      if (!Number.isInteger(weight) || weight < 1 || weight > 1000) throw new Error('路径权重必须是 1 到 1000 的整数');
      const canonicalDirection = option.nodeIds[0] === sourceId;
      return {
        pathId: option.id,
        weight,
        nodeIds: canonicalDirection ? option.nodeIds : [...option.nodeIds].reverse(),
        linkIds: canonicalDirection ? option.linkIds : [...option.linkIds].reverse(),
      };
    });
    const existing = this.db.get(
      'SELECT id, created_at FROM path_policies WHERE network_id = ? AND source_id = ? AND target_id = ?',
      networkId, sourceId, targetId,
    );
    const id = existing?.id ?? randomUUID();
    const timestamp = now();
    let versionId;
    this.db.transaction(() => {
      this.db.run(
        `INSERT INTO path_policies(id, network_id, source_id, target_id, mode, paths_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'weighted', ?, ?, ?)
         ON CONFLICT(network_id, source_id, target_id) DO UPDATE SET
           mode = excluded.mode, paths_json = excluded.paths_json, updated_at = excluded.updated_at`,
        id, networkId, sourceId, targetId, json(selectedPaths), existing?.created_at ?? timestamp, timestamp,
      );
      versionId = this.createVersionInTransaction(networkId, '更新多路径负载均衡策略');
      this.audit('path-policy.update', 'path-policy', id, { sourceId, targetId, paths: selectedPaths, versionId });
    });
    return { details: this.getPathOptions(networkId, input.sourceId, input.targetId), version: this.getConfiguration(versionId) };
  }

  deletePathPolicy(networkId, sourceNodeId, targetNodeId) {
    const source = this.getNode(sourceNodeId);
    const target = this.getNode(targetNodeId);
    if (source.networkId !== networkId || target.networkId !== networkId) throw new Error('所选节点不属于当前节点组');
    const [sourceId, targetId] = canonicalNodePair(source.id, target.id);
    const existing = this.db.get(
      'SELECT id FROM path_policies WHERE network_id = ? AND source_id = ? AND target_id = ?',
      networkId, sourceId, targetId,
    );
    if (!existing) return { deleted: false, details: this.getPathOptions(networkId, sourceNodeId, targetNodeId) };
    let versionId;
    this.db.transaction(() => {
      this.db.run('DELETE FROM path_policies WHERE id = ?', existing.id);
      versionId = this.createVersionInTransaction(networkId, '关闭多路径负载均衡策略');
      this.audit('path-policy.delete', 'path-policy', existing.id, { sourceId, targetId, versionId });
    });
    return {
      deleted: true,
      details: this.getPathOptions(networkId, sourceNodeId, targetNodeId),
      version: this.getConfiguration(versionId),
    };
  }

  getTopology(networkId) {
    const network = this.getNetwork(networkId);
    const nodes = this.listNodes(networkId);
    const links = this.listLinks(networkId);
    const activeLinks = links.filter((link) => link.validationStatus === 'active');
    let validation;
    try {
      validation = validateAndCompileTopology({ network, nodes, links: activeLinks }).summary;
    } catch (error) {
      validation = { fullyReachable: false, error: error.message, details: error.details };
    }
    return { network, nodes, links, validation };
  }

  replaceTopology(networkId, links) {
    const network = this.getNetwork(networkId);
    const nodes = this.listNodes(networkId);
    const compiled = validateAndCompileTopology({ network, nodes, links });
    let versionId;
    this.db.transaction(() => {
      this.db.run('DELETE FROM path_policies WHERE network_id = ?', networkId);
      this.db.run('DELETE FROM topology_links WHERE network_id = ?', networkId);
      for (const link of compiled.links) {
        this.db.run(
          `INSERT INTO topology_links(id, network_id, upstream_id, downstream_id, priority,
            upstream_endpoint, downstream_endpoint, validation_status, validated_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
          randomUUID(), networkId, link.upstreamId, link.downstreamId, link.priority,
          link.upstreamEndpoint ?? null, link.downstreamEndpoint ?? null, now(), now(),
        );
      }
      versionId = this.createVersionInTransaction(networkId, '修改数据拓扑', compiled);
      this.audit('topology.replace', 'network', networkId, { links: compiled.links, versionId });
    });
    return { version: this.getConfiguration(versionId), validation: compiled.summary };
  }

  updateNode(nodeId, input) {
    const node = this.getNode(nodeId);
    const network = this.getNetwork(node.networkId);
    const nextName = input.name === undefined ? node.name : String(input.name).trim();
    const nextIp = input.dataIp === undefined ? node.dataIp : String(input.dataIp).trim();
    const nextRelay = input.canRelay === undefined ? node.canRelay : Boolean(input.canRelay);
    const nextControlEndpoint = input.controlEndpoint === undefined ? node.controlEndpoint : String(input.controlEndpoint).trim() || null;
    const nextDataEndpoint = input.dataEndpoint === undefined ? node.dataEndpoint : String(input.dataEndpoint).trim() || null;
    const nextDataListenPort = normalizePort(input.dataListenPort, `${node.name} 的 WireGuard 端口`, node.dataListenPort);
    if (!nextName) throw new Error('节点名称不能为空');
    if (nextControlEndpoint) {
      let parsed;
      try { parsed = new URL(nextControlEndpoint); } catch { throw new Error('接入中继地址必须是完整的 HTTP 或 HTTPS URL'); }
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('接入中继地址只支持 HTTP 或 HTTPS');
    }
    if (nextDataEndpoint && !/^\[[0-9a-f:]+\]:\d+$|^[^\s:]+:\d+$/i.test(nextDataEndpoint)) {
      throw new Error('WireGuard 数据端点格式应为 IP或域名:端口');
    }

    const nodes = this.listNodes(node.networkId).map((item) => item.id === nodeId
      ? {
          ...item, name: nextName, dataIp: nextIp, canRelay: nextRelay,
          controlEndpoint: nextControlEndpoint, dataEndpoint: nextDataEndpoint, dataListenPort: nextDataListenPort,
        }
      : item);
    const links = this.listLinks(node.networkId, true);
    const compiled = validateAndCompileTopology({ network, nodes, links });
    let versionId;
    this.db.transaction(() => {
      this.db.run(
        `UPDATE nodes SET name = ?, data_ip = ?, can_relay = ?, control_endpoint = ?,
         data_endpoint = ?, data_listen_port = ?, updated_at = ? WHERE id = ?`,
        nextName, nextIp, nextRelay ? 1 : 0, nextControlEndpoint, nextDataEndpoint, nextDataListenPort, now(), nodeId,
      );
      versionId = this.createVersionInTransaction(node.networkId, '修改节点业务地址', compiled);
      this.audit('node.update', 'node', nodeId, {
        before: { name: node.name, dataIp: node.dataIp, controlEndpoint: node.controlEndpoint, dataEndpoint: node.dataEndpoint, dataListenPort: node.dataListenPort },
        after: { name: nextName, dataIp: nextIp, controlEndpoint: nextControlEndpoint, dataEndpoint: nextDataEndpoint, dataListenPort: nextDataListenPort }, versionId,
      });
    });
    return { node: this.getNode(nodeId), version: this.getConfiguration(versionId) };
  }

  createJoinToken(networkId, input = {}) {
    this.getNetwork(networkId);
    const parent = this.getNode(input.parentId);
    if (parent.networkId !== networkId) throw new Error('父节点不属于当前节点组');
    if (!parent.canRelay) throw new Error('所选父节点未启用下级接入能力');
    const mode = input.mode === 'passive' ? 'passive' : 'active';
    const dataPort = input.dataPort === undefined || input.dataPort === null || input.dataPort === ''
      ? null
      : normalizePort(input.dataPort, '新节点 WireGuard 端口');
    const ttlMinutes = Math.min(1440, Math.max(5, Number(input.ttlMinutes ?? 30)));
    const token = `pwj_${randomBytes(24).toString('base64url')}`;
    const id = randomUUID();
    const expiresAt = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
    this.db.run(
      `INSERT INTO join_tokens(id, token_hash, network_id, parent_id, mode, expires_at, max_uses, used_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?)`,
      id, hashSecret(token), networkId, parent.id, mode, expiresAt, now(),
    );
    const rawSourceUrl = String(input.sourceUrl || parent.controlEndpoint || '').trim();
    if (!rawSourceUrl) {
      throw new Error(`父节点 ${parent.name} 尚未配置新设备可访问的中继地址`);
    }
    let sourceUrl;
    try {
      const parsed = new URL(rawSourceUrl);
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('invalid protocol');
      sourceUrl = parsed.href.replace(/\/$/, '');
    } catch {
      throw new Error('安装包与接入地址必须是完整的 HTTP 或 HTTPS URL');
    }
    const installerUrl = `${sourceUrl}/install.sh?source=${encodeURIComponent(sourceUrl)}`;
    const dataPortArgument = dataPort ? ` --data-port '${dataPort}'` : '';
    const command = mode === 'passive'
      ? `curl -fsSL '${installerUrl}' | sudo bash -s -- --claim-token '${token}'${dataPortArgument}`
      : `curl -fsSL '${installerUrl}' | sudo bash -s -- --join-token '${token}' --upstream '${sourceUrl}'${dataPortArgument}`;
    this.audit('join-token.create', 'join-token', id, { networkId, parentId: parent.id, mode, expiresAt, dataPort });
    return { id, token, mode, expiresAt, parent, sourceUrl, dataPort, command };
  }

  createLinkValidation(networkId, input) {
    const network = this.getNetwork(networkId);
    const upstream = this.getNode(input.nodeAId);
    const downstream = this.getNode(input.nodeBId);
    if (upstream.networkId !== networkId || downstream.networkId !== networkId) throw new Error('所选节点不属于当前节点组');
    if (upstream.id === downstream.id) throw new Error('请选择两个不同节点');

    const duplicate = this.db.get(
      `SELECT id, validation_status FROM topology_links WHERE network_id = ?
       AND ((upstream_id = ? AND downstream_id = ?) OR (upstream_id = ? AND downstream_id = ?))
       AND validation_status != 'failed'`,
      networkId, upstream.id, downstream.id, downstream.id, upstream.id,
    );
    if (duplicate) throw new Error('这两个节点之间已经存在连接或正在验证');
    this.db.run(
      `DELETE FROM topology_links WHERE network_id = ? AND validation_status = 'failed'
       AND ((upstream_id = ? AND downstream_id = ?) OR (upstream_id = ? AND downstream_id = ?))`,
      networkId, upstream.id, downstream.id, downstream.id, upstream.id,
    );

    const upstreamHost = normalizeReachableHost(input.nodeAAddress, `${upstream.name} 的可达地址`);
    const downstreamHost = normalizeReachableHost(input.nodeBAddress, `${downstream.name} 的可达地址`);
    const upstreamPort = normalizePort(input.nodeAPort, `${upstream.name} 的 WireGuard 端口`, upstream.dataListenPort);
    const downstreamPort = normalizePort(input.nodeBPort, `${downstream.name} 的 WireGuard 端口`, downstream.dataListenPort);
    const upstreamEndpoint = `${upstreamHost}:${upstreamPort}`;
    const downstreamEndpoint = `${downstreamHost}:${downstreamPort}`;
    const priority = Math.max(0, Number.isInteger(Number(input.priority)) ? Number(input.priority) : 10);
    const id = randomUUID();
    const validationToken = `pwv_${randomBytes(24).toString('base64url')}`;
    const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
    const candidate = {
      id, upstreamId: upstream.id, downstreamId: downstream.id, priority,
      upstreamEndpoint, downstreamEndpoint, validationStatus: 'active',
    };
    validateAndCompileTopology({
      network,
      nodes: this.listNodes(networkId),
      links: [...this.listLinks(networkId, true), candidate],
    });

    this.db.run(
      `INSERT INTO topology_links(id, network_id, upstream_id, downstream_id, priority,
        upstream_endpoint, downstream_endpoint, validation_status, validation_token,
        validation_expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'preparing', ?, ?, ?)`,
      id, networkId, upstream.id, downstream.id, priority, upstreamEndpoint, downstreamEndpoint,
      validationToken, expiresAt, now(),
    );

    for (const node of [upstream, downstream]) {
      this.enqueueCommand(node.id, 'prepare-link-probe', { validationId: id, token: validationToken, expiresAt });
    }
    this.audit('topology-link.validate', 'topology-link', id, {
      networkId, upstreamId: upstream.id, downstreamId: downstream.id, upstreamEndpoint, downstreamEndpoint,
    });
    return this.listLinks(networkId).find((link) => link.id === id);
  }

  registerAgent(input) {
    const tokenHash = hashSecret(input.token ?? '');
    const credential = `pwn_${randomBytes(32).toString('base64url')}`;
    const timestamp = now();
    let created;
    this.db.transaction(() => {
      const token = this.db.get('SELECT * FROM join_tokens WHERE token_hash = ?', tokenHash);
      if (!token || token.used_count >= token.max_uses || token.expires_at <= timestamp) {
        throw new Error('加入令牌无效、已过期或已使用');
      }
      if ((token.mode === 'passive') !== Boolean(input.passive)) {
        throw new Error(token.mode === 'passive' ? '被动令牌必须通过认领流程使用' : '主动加入令牌不能用于被动认领');
      }
      const network = this.getNetwork(token.network_id);
      const parent = this.getNode(token.parent_id);
      const existingIps = new Set(this.listNodes(network.id).flatMap((node) => [node.dataIp, node.controlIp]));
      const dataIp = this.allocateIp(network.dataCidr, new Set(this.listNodes(network.id).map((node) => node.dataIp)));
      const controlIp = this.allocateIp(network.controlCidr, new Set(this.listNodes(network.id).map((node) => node.controlIp)));
      if (existingIps.has(dataIp) || existingIps.has(controlIp)) throw new Error('无法分配节点地址');
      const nodeId = randomUUID();
      const name = String(input.name || `节点-${nodeId.slice(0, 6)}`).slice(0, 80);
      const dataListenPort = normalizePort(
        input.dataListenPort,
        `${name} 的 WireGuard 端口`,
        endpointPort(input.dataEndpoint) || DEFAULT_DATA_PORT,
      );
      this.db.run(
        `INSERT INTO nodes(id, network_id, name, status, is_center, can_relay, parent_id, control_ip, data_ip,
          control_endpoint, data_endpoint, data_listen_port, wg_control_public_key, wg_data_public_key, credential_hash,
          agent_version, last_seen, created_at, updated_at)
         VALUES (?, ?, ?, 'online', 0, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        nodeId, network.id, name, parent.id, controlIp, dataIp,
        input.controlEndpoint ?? null, input.dataEndpoint ?? null, dataListenPort,
        input.wgControlPublicKey ?? '', input.wgDataPublicKey ?? '', hashSecret(credential),
        input.agentVersion ?? '0.1.0', timestamp, timestamp, timestamp,
      );
      this.db.run(
        'INSERT INTO topology_links(id, network_id, upstream_id, downstream_id, priority, created_at) VALUES (?, ?, ?, ?, 100, ?)',
        randomUUID(), network.id, parent.id, nodeId, timestamp,
      );
      this.db.run('UPDATE join_tokens SET used_count = used_count + 1 WHERE id = ?', token.id);
      const versionId = this.createVersionInTransaction(network.id, `节点 ${name} 加入`);
      this.audit('agent.register', 'node', nodeId, { parentId: parent.id, versionId }, `node:${nodeId}`);
      created = { node: this.getNode(nodeId), credential, parent, versionId };
    });
    return created;
  }

  allocateIp(cidr, used) {
    const parsed = parseCIDR(cidr);
    const capacity = Math.min(parsed.broadcast - parsed.network - 1, 1_000_000);
    for (let offset = 2; offset <= capacity; offset += 1) {
      const candidate = usableHost(parsed, offset);
      if (!used.has(candidate)) return candidate;
    }
    throw new Error(`网段 ${parsed.cidr} 没有可用地址`);
  }

  loadState(networkId) {
    return {
      network: this.getNetwork(networkId),
      nodes: this.listNodes(networkId),
      links: this.listLinks(networkId, true),
    };
  }

  createVersionInTransaction(networkId, reason, precompiled = null) {
    const state = this.loadState(networkId);
    const compiled = precompiled ?? validateAndCompileTopology(state);
    const pathPolicies = this.listPathPolicies(networkId);
    for (const config of Object.values(compiled.configs)) config.multipathPolicies = [];
    for (const policy of pathPolicies) {
      const totalWeight = policy.paths.reduce((total, path) => total + Number(path.weight), 0);
      for (const [sourceId, targetId, reverse] of [
        [policy.sourceId, policy.targetId, false],
        [policy.targetId, policy.sourceId, true],
      ]) {
        const config = compiled.configs[sourceId];
        if (!config) continue;
        config.multipathPolicies.push({
          policyId: policy.id,
          targetNodeId: targetId,
          mode: policy.mode,
          paths: policy.paths.map((path) => {
            const nodeIds = reverse ? [...path.nodeIds].reverse() : [...path.nodeIds];
            const linkIds = reverse ? [...path.linkIds].reverse() : [...path.linkIds];
            return {
              pathId: path.pathId,
              weight: Number(path.weight),
              share: totalWeight ? Number((Number(path.weight) / totalWeight).toFixed(4)) : 0,
              nextHopId: nodeIds[1],
              nodeIds,
              linkIds,
            };
          }),
        });
      }
    }
    const next = this.db.get('SELECT COALESCE(MAX(version), 0) + 1 AS version FROM config_versions WHERE network_id = ?', networkId);
    const id = randomUUID();
    const timestamp = now();
    const onlyCenter = state.nodes.every((node) => node.isCenter);
    const status = onlyCenter ? 'active' : 'preparing';
    this.db.run(
      "UPDATE config_versions SET status = 'superseded' WHERE network_id = ? AND status IN ('preparing', 'activating')",
      networkId,
    );
    this.db.run(
      `INSERT INTO config_versions(id, network_id, version, status, reason, topology_json, created_at, activated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      id, networkId, Number(next.version), status, reason,
      json({ links: compiled.links, paths: compiled.paths, pathPolicies, summary: compiled.summary }), timestamp,
      onlyCenter ? timestamp : null,
    );
    for (const node of state.nodes) {
      const phase = node.isCenter ? 'activated' : 'pending';
      this.db.run(
        `INSERT INTO node_configs(version_id, node_id, phase, config_json, prepared_at, activated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        id, node.id, phase, json({ ...compiled.configs[node.id], version: Number(next.version), versionId: id }),
        node.isCenter ? timestamp : null, node.isCenter ? timestamp : null,
      );
    }
    return id;
  }

  listConfigurations(networkId, limit = 20) {
    return this.db.all(
      'SELECT * FROM config_versions WHERE network_id = ? ORDER BY version DESC LIMIT ?', networkId, Number(limit),
    ).map((row) => this.configurationFromRow(row));
  }

  configurationFromRow(row) {
    return {
      id: row.id,
      networkId: row.network_id,
      version: Number(row.version),
      status: row.status,
      reason: row.reason,
      topology: JSON.parse(row.topology_json),
      createdAt: row.created_at,
      activatedAt: row.activated_at,
    };
  }

  getConfiguration(id) {
    const row = this.db.get('SELECT * FROM config_versions WHERE id = ?', id);
    if (!row) throw new Error('配置版本不存在');
    const result = this.configurationFromRow(row);
    result.nodes = this.db.all(
      `SELECT c.node_id, n.name, c.phase, c.error, c.prepared_at, c.activated_at
       FROM node_configs c JOIN nodes n ON n.id = c.node_id WHERE c.version_id = ? ORDER BY n.name`, id,
    ).map((item) => ({
      nodeId: item.node_id,
      name: item.name,
      phase: item.phase,
      error: item.error,
      preparedAt: item.prepared_at,
      activatedAt: item.activated_at,
    }));
    return result;
  }

  authenticateAgent(credential) {
    if (!credential) return null;
    return nodeFromRow(this.db.get('SELECT * FROM nodes WHERE credential_hash = ?', hashSecret(credential)));
  }

  heartbeat(nodeId, input = {}) {
    const timestamp = now();
    const node = this.getNode(nodeId);
    const dataListenPort = normalizePort(input.dataListenPort, `${node.name} 的 WireGuard 端口`, node.dataListenPort);
    const portChanged = dataListenPort !== node.dataListenPort;
    let versionId = null;
    this.db.transaction(() => {
      this.db.run(
        `UPDATE nodes SET status = 'online', last_seen = ?, agent_version = COALESCE(?, agent_version),
         control_endpoint = COALESCE(?, control_endpoint), data_endpoint = COALESCE(?, data_endpoint),
         data_listen_port = ?, updated_at = ? WHERE id = ?`,
        timestamp, input.agentVersion ?? null, input.controlEndpoint ?? null, input.dataEndpoint ?? null,
        dataListenPort, timestamp, nodeId,
      );
      if (portChanged) {
        versionId = this.createVersionInTransaction(node.networkId, `节点 ${node.name} 更新 WireGuard 端口`);
        this.audit('agent.data-port', 'node', nodeId, { before: node.dataListenPort, after: dataListenPort, versionId }, `node:${nodeId}`);
      }
    });
    return { acknowledgedAt: timestamp, dataListenPort, versionId };
  }

  getDesiredConfig(nodeId, currentVersion = 0) {
    const row = this.db.get(
      `SELECT v.*, c.phase, c.config_json FROM config_versions v
       JOIN node_configs c ON c.version_id = v.id
       WHERE c.node_id = ? AND v.status IN ('preparing', 'activating', 'active') AND v.version > ?
       ORDER BY v.version DESC LIMIT 1`, nodeId, Number(currentVersion),
    );
    if (!row) return null;
    return {
      versionId: row.id,
      version: Number(row.version),
      rolloutStatus: row.status,
      phase: row.status === 'preparing' ? 'prepare' : 'activate',
      config: JSON.parse(row.config_json),
    };
  }

  reportConfig(nodeId, versionId, phase, error = null) {
    const version = this.getConfiguration(versionId);
    const timestamp = now();
    const desiredPhase = error ? 'failed' : phase;
    const field = phase === 'activated' ? 'activated_at' : 'prepared_at';
    this.db.run(
      `UPDATE node_configs SET phase = ?, error = ?, ${field} = ? WHERE version_id = ? AND node_id = ?`,
      desiredPhase, error, timestamp, versionId, nodeId,
    );
    if (error) {
      this.db.run("UPDATE config_versions SET status = 'failed' WHERE id = ?", versionId);
      this.audit('config.failed', 'config-version', versionId, { nodeId, phase, error }, `node:${nodeId}`);
      return this.getConfiguration(versionId);
    }

    if (phase === 'prepared') {
      const pending = this.db.get(
        "SELECT COUNT(*) AS count FROM node_configs WHERE version_id = ? AND phase NOT IN ('prepared', 'activated')", versionId,
      );
      if (Number(pending.count) === 0) this.db.run("UPDATE config_versions SET status = 'activating' WHERE id = ?", versionId);
    }
    if (phase === 'activated') {
      const pending = this.db.get(
        "SELECT COUNT(*) AS count FROM node_configs WHERE version_id = ? AND phase != 'activated'", versionId,
      );
      if (Number(pending.count) === 0) {
        this.db.transaction(() => {
          this.db.run("UPDATE config_versions SET status = 'superseded' WHERE network_id = ? AND status = 'active' AND id != ?", version.networkId, versionId);
          this.db.run("UPDATE config_versions SET status = 'active', activated_at = ? WHERE id = ?", timestamp, versionId);
        });
      }
    }
    return this.getConfiguration(versionId);
  }

  enqueueCommand(nodeId, type, payload = {}) {
    this.getNode(nodeId);
    const id = randomUUID();
    this.db.run(
      "INSERT INTO commands(id, node_id, type, payload_json, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
      id, nodeId, type, json(payload), now(),
    );
    this.audit('command.create', 'command', id, { nodeId, type, payload });
    return { id, nodeId, type, payload, status: 'pending' };
  }

  claimCommand(nodeId) {
    return this.db.transaction(() => {
      const row = this.db.get("SELECT * FROM commands WHERE node_id = ? AND status = 'pending' ORDER BY created_at LIMIT 1", nodeId);
      if (!row) return null;
      this.db.run("UPDATE commands SET status = 'running', claimed_at = ? WHERE id = ?", now(), row.id);
      return { id: row.id, type: row.type, payload: JSON.parse(row.payload_json), createdAt: row.created_at };
    });
  }

  completeCommand(nodeId, commandId, input) {
    const row = this.db.get('SELECT * FROM commands WHERE id = ? AND node_id = ?', commandId, nodeId);
    if (!row) throw new Error('命令不存在');
    const status = input.ok ? 'completed' : 'failed';
    this.db.run(
      'UPDATE commands SET status = ?, result_json = ?, completed_at = ? WHERE id = ?',
      status, json(input), now(), commandId,
    );
    this.audit('command.complete', 'command', commandId, { status, result: input }, `node:${nodeId}`);
    if (row.type === 'prepare-link-probe' || row.type === 'execute-link-probe') {
      this.advanceLinkValidation(nodeId, row.type, JSON.parse(row.payload_json), input);
    }
    return { id: commandId, status };
  }

  advanceLinkValidation(nodeId, commandType, payload, result) {
    const link = this.db.get('SELECT * FROM topology_links WHERE id = ?', payload.validationId);
    if (!link || ['active', 'failed'].includes(link.validation_status)) return;
    const isUpstream = link.upstream_id === nodeId;
    if (!isUpstream && link.downstream_id !== nodeId) return;
    if (!result.ok) {
      this.db.run(
        `UPDATE topology_links SET validation_status = 'failed', validation_error = ?, validation_token = NULL WHERE id = ?`,
        result.error || '节点连通性探测失败', link.id,
      );
      this.audit('topology-link.failed', 'topology-link', link.id, { nodeId, error: result.error }, `node:${nodeId}`);
      return;
    }

    if (commandType === 'prepare-link-probe') {
      const field = isUpstream ? 'validation_prepared_upstream' : 'validation_prepared_downstream';
      this.db.run(`UPDATE topology_links SET ${field} = 1 WHERE id = ?`, link.id);
      const updated = this.db.get('SELECT * FROM topology_links WHERE id = ?', link.id);
      if (updated.validation_prepared_upstream && updated.validation_prepared_downstream) {
        this.db.run("UPDATE topology_links SET validation_status = 'probing' WHERE id = ?", link.id);
        this.enqueueCommand(updated.upstream_id, 'execute-link-probe', {
          validationId: link.id,
          probeId: randomUUID(),
          maxHops: 16,
          token: updated.validation_token,
          remoteUrl: `http://${endpointHost(updated.downstream_endpoint)}:8790`,
          expectedNodeId: updated.downstream_id,
        });
        this.enqueueCommand(updated.downstream_id, 'execute-link-probe', {
          validationId: link.id,
          probeId: randomUUID(),
          maxHops: 16,
          token: updated.validation_token,
          remoteUrl: `http://${endpointHost(updated.upstream_endpoint)}:8790`,
          expectedNodeId: updated.upstream_id,
        });
      }
      return;
    }

    const field = isUpstream ? 'validation_probed_upstream' : 'validation_probed_downstream';
    this.db.run(`UPDATE topology_links SET ${field} = 1 WHERE id = ?`, link.id);
    const updated = this.db.get('SELECT * FROM topology_links WHERE id = ?', link.id);
    if (updated.validation_probed_upstream && updated.validation_probed_downstream) {
      let versionId;
      this.db.transaction(() => {
        this.db.run(
          `UPDATE topology_links SET validation_status = 'active', validation_error = NULL,
           validation_token = NULL, validated_at = ? WHERE id = ?`, now(), link.id,
        );
        versionId = this.createVersionInTransaction(link.network_id, '新增已验证的数据通路');
        this.audit('topology-link.active', 'topology-link', link.id, { versionId });
      });
    }
  }

  dashboard() {
    const networks = this.listNetworks();
    const nodes = this.db.all('SELECT * FROM nodes ORDER BY last_seen DESC').map(nodeFromRow);
    const preparing = Number(this.db.get("SELECT COUNT(*) AS count FROM config_versions WHERE status IN ('preparing', 'activating')").count);
    const pendingCommands = Number(this.db.get("SELECT COUNT(*) AS count FROM commands WHERE status IN ('pending', 'running')").count);
    return {
      networks,
      totals: {
        networks: networks.length,
        nodes: nodes.length,
        online: nodes.filter((node) => node.status === 'online').length,
        preparing,
        pendingCommands,
      },
      recentNodes: nodes.slice(0, 8),
    };
  }
}
