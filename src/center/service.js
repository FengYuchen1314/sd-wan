import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { containsIPv4, parseCIDR, parseIPv4, usableHost } from '../core/ipv4.js';
import { enumerateSimplePaths } from '../core/paths.js';
import { validateAndCompileTopology } from '../core/topology.js';

const now = () => new Date().toISOString();
const hashSecret = (value) => createHash('sha256').update(String(value)).digest('hex');
const json = (value) => JSON.stringify(value ?? {});
const DEFAULT_DATA_PORT = 19801;
const PASSIVE_GITHUB_SOURCE = 'https://raw.githubusercontent.com/FengYuchen1314/sd-wan/main';
const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].map(parseCIDR);

function rangesOverlap(rangeA, rangeB) {
  return !(rangeA.broadcast < rangeB.network || rangeB.broadcast < rangeA.network);
}

function assertPrivateCidr(value) {
  const candidate = parseCIDR(value);
  if (!PRIVATE_RANGES.some((range) => candidate.network >= range.network && candidate.broadcast <= range.broadcast)) {
    throw new Error('业务网段必须完整位于 10.0.0.0/8、172.16.0.0/12 或 192.168.0.0/16 私有地址范围内');
  }
  if (candidate.prefix > 30) throw new Error('业务网段至少需要两个可用主机地址');
  return candidate;
}

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

function endpointDetails(endpoint) {
  if (!endpoint) return null;
  try {
    const parsed = new URL(endpoint);
    const hostname = parsed.hostname;
    return {
      protocol: parsed.protocol.replace(':', ''),
      host: hostname.startsWith('[') ? hostname : hostname.includes(':') ? `[${hostname}]` : hostname,
      port: Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80)),
    };
  } catch {
    return null;
  }
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

function hostFromEndpoint(endpoint) {
  if (!endpoint) return null;
  const value = String(endpoint).trim();
  const url = endpointDetails(value);
  if (url?.host) return url.host;
  const port = endpointPort(value);
  return port ? endpointHost(value) : value;
}

function controlHopUrl(node, link, nodeId) {
  const linkEndpoint = link.upstreamId === nodeId ? link.upstreamEndpoint : link.downstreamEndpoint;
  const linkedHost = hostFromEndpoint(linkEndpoint) || hostFromEndpoint(node.dataEndpoint);
  if (linkedHost) return `http://${linkedHost}:${node.controlListenPort || 8790}`;
  const details = endpointDetails(node.controlEndpoint);
  const host = details?.host;
  if (!host) return null;
  return `${details.protocol}://${host}:${details.port || node.controlListenPort || 8790}`;
}

function probeUrl(node, reachableEndpoint) {
  const host = hostFromEndpoint(reachableEndpoint);
  if (!host) throw new Error(`节点 ${node.name} 缺少可探测地址`);
  return `http://${host}:${node.controlListenPort || 8790}`;
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
    controlListenPort: Number(row.control_listen_port || endpointDetails(row.control_endpoint)?.port || (row.is_center ? 19773 : 8790)),
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

function linkForPair(links, nodeAId, nodeBId) {
  return links.find((link) =>
    (link.upstreamId === nodeAId && link.downstreamId === nodeBId) ||
    (link.upstreamId === nodeBId && link.downstreamId === nodeAId));
}

function compileControlPlans(nodes, links, coordinatorId, voterIds = []) {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const plans = {};
  const targets = [...new Set([coordinatorId, ...voterIds].filter((id) => nodeById.has(id)))];
  if (!targets.length) return plans;

  for (const source of nodes) {
    const forwarders = {};
    for (const link of links) {
      let peerId = null;
      if (link.upstreamId === source.id) peerId = link.downstreamId;
      else if (link.downstreamId === source.id) peerId = link.upstreamId;
      if (!peerId) continue;
      const peer = nodeById.get(peerId);
      const url = peer ? controlHopUrl(peer, link, peerId) : null;
      if (url) forwarders[peerId] = url;
    }

    const routesByTarget = {};
    let truncated = false;
    for (const targetId of targets) {
      if (source.id === targetId) {
        routesByTarget[targetId] = [];
        continue;
      }
      const enumerated = enumerateSimplePaths({
        nodes,
        links,
        sourceId: source.id,
        targetId,
        maxPaths: 64,
        searchLimit: 4096,
      });
      truncated ||= enumerated.truncated;
      routesByTarget[targetId] = enumerated.paths
        .filter((path) => path.linkIds.length <= 16)
        .map((path) => {
          const hops = path.nodeIds.slice(1).map((nodeId, index) => {
            const previousNodeId = path.nodeIds[index];
            const link = linkForPair(links, previousNodeId, nodeId);
            const node = nodeById.get(nodeId);
            const url = link && node ? controlHopUrl(node, link, nodeId) : null;
            return url ? { nodeId, url } : null;
          });
          if (hops.some((hop) => !hop)) return null;
          return { id: path.id, nodeIds: path.nodeIds, hops };
        })
        .filter(Boolean);
    }
    plans[source.id] = {
      maxHops: 16,
      forwarders,
      routes: routesByTarget[coordinatorId] ?? [],
      routesByTarget,
      truncated,
    };
  }
  return plans;
}

function applyPreferredPath(compiled, state, pathNodeIds) {
  const nodeById = new Map(state.nodes.map((node) => [node.id, node]));
  const destinationId = pathNodeIds.at(-1);
  const destination = nodeById.get(destinationId);
  if (!destination) return;
  const destinationCidr = `${destination.dataIp}/32`;
  for (let index = 0; index < pathNodeIds.length - 1; index += 1) {
    const sourceId = pathNodeIds[index];
    const nextHopId = pathNodeIds[index + 1];
    const config = compiled.configs[sourceId];
    const nextHop = nodeById.get(nextHopId);
    const link = linkForPair(state.links, sourceId, nextHopId);
    if (!config || !nextHop || !link) continue;
    for (const peer of config.data.peers) {
      peer.allowedIps = peer.allowedIps.filter((cidr) => cidr !== destinationCidr);
    }
    let peer = config.data.peers.find((item) => item.nodeId === nextHopId);
    if (!peer) {
      const endpoint = link.upstreamId === sourceId ? link.downstreamEndpoint : link.upstreamEndpoint;
      peer = {
        nodeId: nextHopId,
        name: nextHop.name,
        publicKey: nextHop.wgDataPublicKey ?? '',
        endpoint: endpoint || nextHop.dataEndpoint || null,
        allowedIps: [],
        persistentKeepalive: 25,
      };
      config.data.peers.push(peer);
    }
    if (!peer.allowedIps.includes(destinationCidr)) peer.allowedIps.push(destinationCidr);
    peer.allowedIps.sort();
    config.data.peers.sort((left, right) => String(left.nodeId).localeCompare(String(right.nodeId)));
    const route = config.routes.find((item) => item.targetNodeId === destinationId);
    if (route) route.viaNodeId = nextHopId;
  }
}

function createMultipathAliasAllocator(network, nodes) {
  const range = parseCIDR(network.controlCidr);
  const used = new Set(nodes.map((node) => node.controlIp));
  const capacity = range.broadcast - range.network - 1;
  let cursor = 1;
  return () => {
    while (cursor <= capacity) {
      const candidate = usableHost(range, cursor);
      cursor += 1;
      if (used.has(candidate)) continue;
      used.add(candidate);
      return candidate;
    }
    throw new Error(`控制网段 ${network.controlCidr} 没有足够地址承载多路径隧道，请扩大控制网段`);
  };
}

function addPeerAllowedIp(config, peerNodeId, cidr) {
  const peer = config?.data?.peers?.find((item) => item.nodeId === peerNodeId);
  if (!peer) throw new Error(`多路径隧道缺少到相邻节点 ${peerNodeId} 的 WireGuard Peer`);
  if (!peer.allowedIps.includes(cidr)) peer.allowedIps.push(cidr);
  peer.allowedIps.sort();
}

function routeCidrsThrough(compiled, nodeById, sourceId, waypointId) {
  const destinations = [];
  for (const [key, nodeIds] of Object.entries(compiled.paths)) {
    const separator = key.indexOf(':');
    if (separator < 0 || key.slice(0, separator) !== sourceId) continue;
    const targetId = key.slice(separator + 1);
    if (nodeIds.indexOf(waypointId) <= 0) continue;
    const target = nodeById.get(targetId);
    if (target) destinations.push(`${target.dataIp}/32`);
  }
  return [...new Set(destinations)].sort();
}

export class ControlService {
  constructor(database, options = {}) {
    this.db = database;
    this.publicUrl = String(options.publicUrl ?? 'http://127.0.0.1:19773').replace(/\/$/, '');
    this.defaultDataPort = normalizePort(options.defaultDataPort, '默认 WireGuard 端口', DEFAULT_DATA_PORT);
    this.manageLocalCenters = Boolean(options.manageLocalCenters);
    this.maintainLocalCenters = options.maintainLocalCenters !== false;
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
      `SELECT id, network_id, validation_status, validation_probed_upstream, validation_probed_downstream FROM topology_links
       WHERE validation_status IN ('preparing', 'probing')
         AND validation_expires_at IS NOT NULL AND validation_expires_at <= ?`,
      timestamp,
    );
    const expiredLinkIds = new Set(expiredLinks.map((link) => link.id));

    let cancelledCommands = 0;
    if (staleNodes.length || expiredLinks.length) {
      this.db.transaction(() => {
        for (const node of staleNodes) {
          this.db.run("UPDATE nodes SET status = 'offline', updated_at = ? WHERE id = ?", timestamp, node.id);
          this.db.run(
            `UPDATE node_configs SET required = 0
             WHERE node_id = ? AND phase != 'activated' AND version_id IN (
               SELECT id FROM config_versions WHERE status IN ('preparing', 'activating')
             )`,
            node.id,
          );
          this.audit('agent.offline', 'node', node.id, { lastSeenBefore: offlineBefore });
        }

        for (const link of expiredLinks) {
          const probeSucceeded = link.validation_status === 'probing' &&
            (Number(link.validation_probed_upstream) > 0 || Number(link.validation_probed_downstream) > 0);
          if (probeSucceeded) {
            this.activateValidatedLinkInTransaction(
              link, timestamp, '单向探测成功，激活数据通路', 'topology-link.active-on-timeout',
            );
            continue;
          }
          const error = link.validation_status === 'preparing'
            ? '验证超时：Agent 未在有效期内完成准备'
            : '验证超时：节点未在有效期内完成已填写方向的探测';
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
    }

    const advancedRollouts = this.advanceConfigurationRollouts(timestamp);
    return { offlineNodes: staleNodes.length, expiredLinks: expiredLinks.length, cancelledCommands, advancedRollouts };
  }

  audit(action, resourceType, resourceId, detail = {}, actor = 'admin') {
    const result = this.db.run(
      'INSERT INTO audit_log(actor, action, resource_type, resource_id, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      actor, action, resourceType, resourceId ?? null, json(detail), now(),
    );
    this.db.run(
      'UPDATE cluster_state SET revision = MAX(revision, ?), updated_at = ?',
      Number(result.lastInsertRowid || 0), now(),
    );
  }

  ensureDefaultNetwork() {
    const existing = this.db.get('SELECT id FROM networks ORDER BY created_at LIMIT 1');
    if (existing) {
      if (this.maintainLocalCenters) this.ensureCenterKeys();
      return existing.id;
    }
    return this.createNetwork({
      name: '默认网络',
      dataCidr: '10.77.0.0/16',
      controlCidr: '10.254.0.0/16',
      listenPort: this.defaultDataPort,
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
      const centerPort = endpointDetails(this.publicUrl)?.port || 19773;
      if (center.control_endpoint !== this.publicUrl || Number(center.control_listen_port) !== centerPort || center.name === '中心节点') {
        this.db.run(
          `UPDATE nodes SET name = CASE WHEN name = '中心节点' THEN '初始节点' ELSE name END,
           control_endpoint = ?, control_listen_port = ?, updated_at = ? WHERE id = ?`,
          this.publicUrl, centerPort, now(), center.id,
        );
      }
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
    const data = assertPrivateCidr(input.dataCidr ?? '10.77.0.0/16');
    const control = parseCIDR(input.controlCidr ?? '10.254.0.0/16');
    if (!(data.broadcast < control.network || control.broadcast < data.network)) {
      throw new Error('业务网段与控制网段不能重叠');
    }
    for (const existing of this.db.all('SELECT name, data_cidr, control_cidr FROM networks')) {
      if (rangesOverlap(data, parseCIDR(existing.data_cidr)) || rangesOverlap(data, parseCIDR(existing.control_cidr))) {
        throw new Error(`业务网段与已有节点组 ${existing.name} 的地址范围重叠`);
      }
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
      centerDataEndpoint = `${endpointDetails(this.publicUrl)?.host}:${listenPort}`;
    } catch {}
    this.db.transaction(() => {
      this.db.run(
        'INSERT INTO networks(id, name, data_cidr, control_cidr, listen_port, mtu, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        id, name, data.cidr, control.cidr, listenPort, mtu, timestamp,
      );
      this.db.run(
        `INSERT INTO nodes(id, network_id, name, status, is_center, can_relay, parent_id, control_ip, data_ip,
          control_endpoint, control_listen_port, data_endpoint, data_listen_port, wg_control_public_key, wg_data_public_key,
          created_at, updated_at, last_seen)
         VALUES (?, ?, ?, 'online', 1, 1, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        centerId, id, '初始节点', usableHost(control, 1), usableHost(data, 1), this.publicUrl,
        endpointDetails(this.publicUrl)?.port || 19773, centerDataEndpoint, listenPort,
        centerControlKeys.publicKey, centerDataKeys.publicKey, timestamp, timestamp, timestamp,
      );
      this.db.run(
        'INSERT INTO local_node_keys(node_id, control_private_key, data_private_key, created_at) VALUES (?, ?, ?, ?)',
        centerId, centerControlKeys.privateKey, centerDataKeys.privateKey, timestamp,
      );
      this.db.run(
        `INSERT INTO cluster_state(network_id, coordinator_node_id, term, revision, election_secret, voted_for, updated_at)
         VALUES (?, ?, 1, 0, ?, NULL, ?)`,
        id, centerId, randomBytes(32).toString('base64url'), timestamp,
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

  planDataCidrChange(networkId, input = {}) {
    const network = this.getNetwork(networkId);
    const candidate = assertPrivateCidr(input.dataCidr);
    const control = parseCIDR(network.controlCidr);
    if (rangesOverlap(candidate, control)) throw new Error('新业务网段与当前控制网段重叠');
    const otherNetworks = this.db.all('SELECT id, name, data_cidr, control_cidr FROM networks WHERE id != ?', networkId);
    for (const other of otherNetworks) {
      for (const [kind, cidr] of [['业务网段', other.data_cidr], ['控制网段', other.control_cidr]]) {
        if (rangesOverlap(candidate, parseCIDR(cidr))) throw new Error(`新业务网段与节点组 ${other.name} 的${kind} ${cidr} 重叠`);
      }
    }

    const nodes = this.listNodes(networkId);
    const capacity = candidate.broadcast - candidate.network - 1;
    if (capacity < nodes.length) throw new Error(`网段 ${candidate.cidr} 只有 ${capacity} 个可用地址，无法容纳 ${nodes.length} 个节点`);
    const preserved = new Set(nodes
      .map((node) => node.dataIp)
      .filter((address) => containsIPv4(candidate, address) && parseIPv4(address) !== candidate.network && parseIPv4(address) !== candidate.broadcast));
    const used = new Set(preserved);
    const assignments = [];
    for (const node of nodes) {
      let nextIp = containsIPv4(candidate, node.dataIp) && parseIPv4(node.dataIp) !== candidate.network && parseIPv4(node.dataIp) !== candidate.broadcast
        ? node.dataIp
        : null;
      if (!nextIp) {
        for (let offset = 1; offset <= capacity; offset += 1) {
          const available = usableHost(candidate, offset);
          if (!used.has(available)) { nextIp = available; break; }
        }
      }
      if (!preserved.has(nextIp)) used.add(nextIp);
      assignments.push({ nodeId: node.id, name: node.name, before: node.dataIp, after: nextIp, changed: node.dataIp !== nextIp });
    }
    return {
      networkId,
      before: network.dataCidr,
      after: candidate.cidr,
      changed: network.dataCidr !== candidate.cidr,
      assignments,
      checks: {
        privateRange: true,
        databaseOverlap: false,
        capacity,
        runtimeRouteProbe: '将在所有 Agent 准备配置时检查本机接口和路由冲突',
      },
    };
  }

  updateNetwork(networkId, input = {}) {
    const plan = this.planDataCidrChange(networkId, input);
    if (input.dryRun) return { preview: true, ...plan };
    if (!plan.changed && !plan.assignments.some((assignment) => assignment.changed)) {
      return { preview: false, ...plan, network: this.getNetwork(networkId), version: null };
    }
    const network = this.getNetwork(networkId);
    const assignments = new Map(plan.assignments.map((assignment) => [assignment.nodeId, assignment.after]));
    const candidateNetwork = { ...network, dataCidr: plan.after };
    const candidateNodes = this.listNodes(networkId).map((node) => ({
      ...node,
      dataIp: assignments.get(node.id) ?? node.dataIp,
    }));
    const compiled = validateAndCompileTopology({
      network: candidateNetwork,
      nodes: candidateNodes,
      links: this.listLinks(networkId, true),
    });
    let versionId;
    this.db.transaction(() => {
      this.db.run(
        "UPDATE network_cidr_changes SET status = 'superseded' WHERE network_id = ? AND status = 'pending'",
        networkId,
      );
      versionId = this.createVersionInTransaction(networkId, `业务网段调整为 ${plan.after}`, compiled);
      this.db.run(
        `INSERT INTO network_cidr_changes(
          version_id, network_id, before_cidr, after_cidr, assignments_json, status, created_at
        ) VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
        versionId, networkId, plan.before, plan.after, json(plan.assignments), now(),
      );
      const version = this.db.get('SELECT status FROM config_versions WHERE id = ?', versionId);
      if (version?.status === 'active') this.applyNetworkCidrChangeInTransaction(versionId, now());
      this.audit('network.data-cidr.stage', 'network', networkId, {
        before: plan.before,
        after: plan.after,
        assignments: plan.assignments,
        versionId,
      });
    });
    return {
      preview: false,
      ...plan,
      network: this.getNetwork(networkId),
      pendingNetwork: candidateNetwork,
      version: this.getConfiguration(versionId),
    };
  }

  applyNetworkCidrChangeInTransaction(versionId, timestamp = now()) {
    const change = this.db.get(
      "SELECT * FROM network_cidr_changes WHERE version_id = ? AND status = 'pending'",
      versionId,
    );
    if (!change) return false;
    const assignments = JSON.parse(change.assignments_json);
    this.db.run('UPDATE networks SET data_cidr = ? WHERE id = ?', change.after_cidr, change.network_id);
    for (const assignment of assignments) {
      this.db.run(
        'UPDATE nodes SET data_ip = ?, updated_at = ? WHERE id = ? AND network_id = ?',
        assignment.after, timestamp, assignment.nodeId, change.network_id,
      );
    }
    this.db.run(
      "UPDATE network_cidr_changes SET status = 'active', error = NULL, applied_at = ? WHERE version_id = ?",
      timestamp, versionId,
    );
    this.audit('network.data-cidr.activate', 'network', change.network_id, {
      before: change.before_cidr,
      after: change.after_cidr,
      versionId,
    });
    return true;
  }

  advanceConfigurationRollout(versionId, timestamp = now()) {
    let version = this.db.get('SELECT id, network_id, status FROM config_versions WHERE id = ?', versionId);
    if (!version || !['preparing', 'activating'].includes(version.status)) return version?.status ?? null;

    if (version.status === 'preparing') {
      const pending = this.db.get(
        `SELECT COUNT(*) AS count FROM node_configs
         WHERE version_id = ? AND required = 1 AND phase NOT IN ('prepared', 'activated')`,
        versionId,
      );
      if (Number(pending.count) > 0) return version.status;
      this.db.run("UPDATE config_versions SET status = 'activating' WHERE id = ? AND status = 'preparing'", versionId);
      version = { ...version, status: 'activating' };
    }

    const pendingActivation = this.db.get(
      `SELECT COUNT(*) AS count FROM node_configs
       WHERE version_id = ? AND required = 1 AND phase != 'activated'`,
      versionId,
    );
    if (Number(pendingActivation.count) > 0) return version.status;
    this.db.transaction(() => {
      this.db.run(
        "UPDATE config_versions SET status = 'superseded' WHERE network_id = ? AND status = 'active' AND id != ?",
        version.network_id, versionId,
      );
      this.db.run("UPDATE config_versions SET status = 'active', activated_at = ? WHERE id = ?", timestamp, versionId);
      this.applyNetworkCidrChangeInTransaction(versionId, timestamp);
    });
    return 'active';
  }

  advanceConfigurationRollouts(timestamp = now()) {
    let advanced = 0;
    const versions = this.db.all(
      "SELECT id, status FROM config_versions WHERE status IN ('preparing', 'activating') ORDER BY version",
    );
    for (const version of versions) {
      const status = this.advanceConfigurationRollout(version.id, timestamp);
      if (status !== version.status) advanced += 1;
    }
    return advanced;
  }

  getAddressChange(networkId) {
    const row = this.db.get(
      `SELECT c.*, v.version, v.status AS rollout_status, v.reason
       FROM network_cidr_changes c JOIN config_versions v ON v.id = c.version_id
       WHERE c.network_id = ? AND c.status IN ('pending', 'failed')
       ORDER BY c.created_at DESC LIMIT 1`,
      networkId,
    );
    if (!row) return null;
    return {
      versionId: row.version_id,
      version: Number(row.version),
      reason: row.reason,
      status: row.status,
      rolloutStatus: row.rollout_status,
      beforeCidr: row.before_cidr,
      afterCidr: row.after_cidr,
      assignments: JSON.parse(row.assignments_json),
      error: row.error,
      createdAt: row.created_at,
      rollout: this.getConfiguration(row.version_id),
    };
  }

  listNodes(networkId) {
    const coordinatorId = this.db.get('SELECT coordinator_node_id FROM cluster_state WHERE network_id = ?', networkId)?.coordinator_node_id;
    return this.db.all('SELECT * FROM nodes WHERE network_id = ? ORDER BY is_center DESC, created_at', networkId)
      .map((row) => ({ ...nodeFromRow(row), isCoordinator: row.id === coordinatorId }));
  }

  getNode(id) {
    const row = this.db.get('SELECT * FROM nodes WHERE id = ?', id);
    if (!row) throw new Error('节点不存在');
    const coordinatorId = this.db.get('SELECT coordinator_node_id FROM cluster_state WHERE network_id = ?', row.network_id)?.coordinator_node_id;
    return { ...nodeFromRow(row), isCoordinator: row.id === coordinatorId };
  }

  listLinks(networkId, activeOnly = false) {
    const condition = activeOnly ? " AND validation_status = 'active'" : '';
    return this.db.all(`SELECT * FROM topology_links WHERE network_id = ?${condition} ORDER BY priority, created_at`, networkId)
      .map((row) => {
        const upstreamProbe = Number(row.validation_probed_upstream ?? 0);
        const downstreamProbe = Number(row.validation_probed_downstream ?? 0);
        const upstreamRequested = Boolean(row.downstream_endpoint) || upstreamProbe !== 0;
        const downstreamRequested = Boolean(row.upstream_endpoint) || downstreamProbe !== 0;
        const directionStatus = (value, requested) => !requested ? 'not-requested' : value > 0 ? 'reachable' : value < 0 ? 'unreachable' : 'unknown';
        return ({
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
          requested: Number(upstreamRequested) + Number(downstreamRequested),
          probed: Number(upstreamProbe !== 0) + Number(downstreamProbe !== 0),
          successful: Number(upstreamProbe > 0) + Number(downstreamProbe > 0),
          failed: Number(upstreamProbe < 0) + Number(downstreamProbe < 0),
        },
        probeDirections: {
          upstreamToDownstream: {
            status: directionStatus(upstreamProbe, upstreamRequested),
            error: row.validation_probe_error_upstream ?? null,
          },
          downstreamToUpstream: {
            status: directionStatus(downstreamProbe, downstreamRequested),
            error: row.validation_probe_error_downstream ?? null,
          },
        },
        validationExpiresAt: row.validation_expires_at,
        validatedAt: row.validated_at,
      });
      });
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

  failedLinkIds(networkId) {
    return new Set(this.db.all(
      `SELECT DISTINCT h.link_id FROM link_health_reports h
       JOIN topology_links l ON l.id = h.link_id
       WHERE l.network_id = ? AND h.status = 'unreachable'`,
      networkId,
    ).map((row) => row.link_id));
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
    const failedLinkIds = this.failedLinkIds(networkId);
    const policyPathStates = (policy?.paths ?? []).map((path) => {
      const failed = (path.linkIds ?? []).filter((linkId) => failedLinkIds.has(linkId));
      return { ...path, available: failed.length === 0, failedLinkIds: failed };
    });
    const activeWeight = policy?.mode === 'weighted'
      ? policyPathStates.filter((path) => path.available).reduce((total, path) => total + Number(path.weight ?? 1), 0)
      : 0;

    return {
      source,
      target,
      paths: result.paths.map((path) => {
        const failed = path.linkIds.filter((linkId) => failedLinkIds.has(linkId));
        return {
          ...path,
          nodes: path.nodeIds.map((nodeId) => {
            const node = nodeById.get(nodeId);
            return { id: node.id, name: node.name, dataIp: node.dataIp, status: node.status };
          }),
          selected: selectedWeights.has(path.id),
          weight: selectedWeights.get(path.id) ?? 1,
          available: failed.length === 0,
          failedLinkIds: failed,
        };
      }),
      truncated: result.truncated,
      healthProbeIntervalSeconds: 20,
      effectiveDefaultPathId: policy?.mode === 'failover'
        ? policy.paths[0]?.pathId ?? result.paths[0]?.id ?? null
        : result.paths[0]?.id ?? null,
      policy: policy ? {
        id: policy.id,
        mode: policy.mode,
        defaultPathId: policy.mode === 'failover' ? policy.paths[0]?.pathId ?? null : null,
        paths: policyPathStates.map((path, index) => ({
          pathId: path.pathId,
          weight: Number(path.weight ?? 1),
          effectiveWeight: policy.mode === 'weighted' && !path.available ? 0 : Number(path.weight ?? 1),
          share: policy.mode === 'weighted'
            ? path.available && activeWeight ? Number((Number(path.weight ?? 1) / activeWeight).toFixed(4)) : 0
            : null,
          available: path.available,
          failedLinkIds: path.failedLinkIds,
          order: Number(path.order ?? index),
        })),
        updatedAt: policy.updatedAt,
      } : null,
    };
  }

  savePathPolicy(networkId, input) {
    const details = this.getPathOptions(networkId, input.sourceId, input.targetId);
    const mode = input.mode === 'failover' ? 'failover' : 'weighted';
    const requested = Array.isArray(input.paths) ? input.paths : [];
    const available = new Map(details.paths.map((path) => [path.id, path]));
    const seen = new Set();
    const [sourceId, targetId] = canonicalNodePair(details.source.id, details.target.id);
    let selectedPaths;
    if (mode === 'failover') {
      const defaultPathId = String(input.defaultPathId || requested[0]?.pathId || '');
      const preferred = available.get(defaultPathId);
      if (!preferred) throw new Error('默认线路不存在或已经失效');
      selectedPaths = [preferred, ...details.paths.filter((path) => path.id !== preferred.id)].map((option, order) => {
        const canonicalDirection = option.nodeIds[0] === sourceId;
        return {
          pathId: option.id,
          weight: 1,
          order,
          nodeIds: canonicalDirection ? option.nodeIds : [...option.nodeIds].reverse(),
          linkIds: canonicalDirection ? option.linkIds : [...option.linkIds].reverse(),
        };
      });
    } else {
      if (requested.length < 2) throw new Error('负载均衡至少需要选择两条无环路径');
      selectedPaths = requested.map((selection, order) => {
        const option = available.get(selection.pathId);
        if (!option || seen.has(selection.pathId)) throw new Error('所选路径不存在、已失效或重复');
        seen.add(selection.pathId);
        const weight = Number(selection.weight);
        if (!Number.isInteger(weight) || weight < 1 || weight > 1000) throw new Error('路径权重必须是 1 到 1000 的整数');
        const canonicalDirection = option.nodeIds[0] === sourceId;
        return {
          pathId: option.id,
          weight,
          order,
          nodeIds: canonicalDirection ? option.nodeIds : [...option.nodeIds].reverse(),
          linkIds: canonicalDirection ? option.linkIds : [...option.linkIds].reverse(),
        };
      });
    }
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
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(network_id, source_id, target_id) DO UPDATE SET
           mode = excluded.mode, paths_json = excluded.paths_json, updated_at = excluded.updated_at`,
        id, networkId, sourceId, targetId, mode, json(selectedPaths), existing?.created_at ?? timestamp, timestamp,
      );
      versionId = this.createVersionInTransaction(
        networkId,
        mode === 'weighted' ? '更新多路径负载均衡策略' : '更新默认线路与自动故障切换策略',
      );
      this.audit('path-policy.update', 'path-policy', id, { sourceId, targetId, mode, paths: selectedPaths, versionId });
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
    return { network, nodes, links, validation, addressChange: this.getAddressChange(networkId) };
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
    const nextControlListenPort = normalizePort(input.controlListenPort, `${node.name} 的控制中继端口`, node.controlListenPort);
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
          controlEndpoint: nextControlEndpoint, controlListenPort: nextControlListenPort,
          dataEndpoint: nextDataEndpoint, dataListenPort: nextDataListenPort,
        }
      : item);
    const links = this.listLinks(node.networkId, true);
    const compiled = validateAndCompileTopology({ network, nodes, links });
    const dataIpChanged = nextIp !== node.dataIp;
    let versionId;
    this.db.transaction(() => {
      this.db.run(
        `UPDATE nodes SET name = ?, data_ip = ?, can_relay = ?, control_endpoint = ?,
         control_listen_port = ?, data_endpoint = ?, data_listen_port = ?, updated_at = ? WHERE id = ?`,
        nextName, node.dataIp, nextRelay ? 1 : 0, nextControlEndpoint, nextControlListenPort,
        nextDataEndpoint, nextDataListenPort, now(), nodeId,
      );
      versionId = this.createVersionInTransaction(node.networkId, dataIpChanged ? '修改节点业务地址' : '修改节点配置', compiled);
      if (dataIpChanged) {
        this.db.run(
          `INSERT INTO network_cidr_changes(
            version_id, network_id, before_cidr, after_cidr, assignments_json, status, created_at
          ) VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
          versionId, node.networkId, network.dataCidr, network.dataCidr,
          json([{ nodeId, name: nextName, before: node.dataIp, after: nextIp, changed: true }]), now(),
        );
        const version = this.db.get('SELECT status FROM config_versions WHERE id = ?', versionId);
        if (version?.status === 'active') this.applyNetworkCidrChangeInTransaction(versionId, now());
      }
      this.audit('node.update', 'node', nodeId, {
        before: { name: node.name, dataIp: node.dataIp, controlEndpoint: node.controlEndpoint, controlListenPort: node.controlListenPort, dataEndpoint: node.dataEndpoint, dataListenPort: node.dataListenPort },
        after: { name: nextName, dataIp: nextIp, controlEndpoint: nextControlEndpoint, controlListenPort: nextControlListenPort, dataEndpoint: nextDataEndpoint, dataListenPort: nextDataListenPort }, versionId,
      });
    });
    return {
      node: this.getNode(nodeId),
      ...(dataIpChanged ? { pendingNode: { ...this.getNode(nodeId), dataIp: nextIp } } : {}),
      version: this.getConfiguration(versionId),
    };
  }

  inspectNodeDeletion(nodeId) {
    const node = this.getNode(nodeId);
    if (node.isCoordinator) {
      return { canDelete: false, node, reason: '当前配置协调节点不能直接删除；请先完成协调权迁移。' };
    }
    const network = this.getNetwork(node.networkId);
    const remainingNodes = this.listNodes(node.networkId).filter((item) => item.id !== nodeId);
    const remainingLinks = this.listLinks(node.networkId, true).filter((link) =>
      link.upstreamId !== nodeId && link.downstreamId !== nodeId);
    const proxies = this.db.all(
      'SELECT node_id, manager_node_id, relay_path_json FROM managed_node_proxies WHERE manager_node_id = ? OR relay_path_json LIKE ?',
      nodeId, `%${nodeId}%`,
    ).filter((row) => row.manager_node_id === nodeId || JSON.parse(row.relay_path_json || '[]').includes(nodeId));
    if (proxies.length) {
      const affected = proxies.map((row) => this.getNode(row.node_id).name);
      return {
        canDelete: false,
        node,
        reason: `该节点仍承担 ${affected.length} 台被认领设备的认证代理：${affected.join('、')}。请先迁移这些设备。`,
        affectedNodeIds: proxies.map((row) => row.node_id),
      };
    }
    let compiled;
    try {
      compiled = validateAndCompileTopology({ network, nodes: remainingNodes, links: remainingLinks });
    } catch (error) {
      const unreachable = error.details?.unreachable ?? [];
      const affected = unreachable.map((id) => remainingNodes.find((item) => item.id === id)?.name).filter(Boolean);
      return {
        canDelete: false,
        node,
        reason: affected.length
          ? `删除后会使这些节点失联：${affected.join('、')}。请先建立替代链路。`
          : `删除后剩余拓扑不再全网可达：${error.message}`,
        affectedNodeIds: unreachable,
      };
    }
    const incidentLinks = this.listLinks(node.networkId).filter((link) =>
      link.upstreamId === nodeId || link.downstreamId === nodeId);
    const children = remainingNodes.filter((item) => item.parentId === nodeId);
    return {
      canDelete: true,
      node,
      compiled,
      removedLinks: incidentLinks.length,
      reparentedNodeIds: children.map((item) => item.id),
      warning: `将删除节点“${node.name}”及 ${incidentLinks.length} 条相邻链路，并生成新的全网配置版本。`,
    };
  }

  deleteNode(nodeId) {
    const impact = this.inspectNodeDeletion(nodeId);
    if (!impact.canDelete) throw new Error(impact.reason);
    const node = impact.node;
    const center = this.listNodes(node.networkId).find((item) => item.isCoordinator) ||
      this.listNodes(node.networkId).find((item) => item.isCenter);
    let versionId;
    this.db.transaction(() => {
      if (center) this.db.run('UPDATE nodes SET parent_id = ? WHERE parent_id = ?', center.id, nodeId);
      if (center) this.db.run('UPDATE join_tokens SET parent_id = ? WHERE parent_id = ?', center.id, nodeId);
      for (const policy of this.listPathPolicies(node.networkId)) {
        if (policy.paths.some((path) => path.nodeIds?.includes(nodeId))) {
          this.db.run('DELETE FROM path_policies WHERE id = ?', policy.id);
        }
      }
      this.db.run('DELETE FROM nodes WHERE id = ?', nodeId);
      versionId = this.createVersionInTransaction(node.networkId, `删除节点 ${node.name}`, impact.compiled);
      this.audit('node.delete', 'node', nodeId, {
        name: node.name,
        removedLinks: impact.removedLinks,
        reparentedNodeIds: impact.reparentedNodeIds,
        versionId,
      });
    });
    return { deleted: true, nodeId, version: this.getConfiguration(versionId) };
  }

  createJoinToken(networkId, input = {}) {
    this.getNetwork(networkId);
    const parent = this.getNode(input.parentId);
    if (parent.networkId !== networkId) throw new Error('父节点不属于当前节点组');
    if (!parent.canRelay) throw new Error('所选父节点未启用下级接入能力');
    const mode = input.mode === 'passive' ? 'passive' : 'active';
    const ttlMinutes = Math.min(1440, Math.max(5, Number(input.ttlMinutes ?? 30)));
    const token = `pwj_${randomBytes(24).toString('base64url')}`;
    const id = randomUUID();
    const expiresAt = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
    let sourceUrl = null;
    let parentConnection = null;
    let publicSourceUrl = null;
    let command;
    if (mode === 'passive') {
      publicSourceUrl = PASSIVE_GITHUB_SOURCE;
      const installerUrl = `${publicSourceUrl}/scripts/install.sh?cache=${Date.now()}`;
      command = `curl -fsSL '${installerUrl}' | sudo bash -s -- --source '${publicSourceUrl}' --claim-token '${token}'`;
    } else {
      const requestedEndpoint = endpointDetails(input.sourceUrl) || endpointDetails(parent.controlEndpoint);
      const parentProtocol = String(input.parentProtocol || requestedEndpoint?.protocol || 'http').replace(':', '').toLowerCase();
      if (!['http', 'https'].includes(parentProtocol)) throw new Error('父节点接入协议只支持 HTTP 或 HTTPS');
      const parentHostValue = input.parentHost || requestedEndpoint?.host;
      if (!parentHostValue) throw new Error(`父节点 ${parent.name} 尚未配置新设备可访问的中继地址`);
      const parentHost = normalizeReachableHost(parentHostValue, `${parent.name} 的可达地址`);
      const parentPort = normalizePort(
        input.parentPort,
        `${parent.name} 的控制接入端口`,
        requestedEndpoint?.port || parent.controlListenPort || (parentProtocol === 'https' ? 443 : 8790),
      );
      sourceUrl = `${parentProtocol}://${parentHost}:${parentPort}`;
      parentConnection = { protocol: parentProtocol, host: parentHost, port: parentPort, url: sourceUrl };
      const installerUrl = `${sourceUrl}/install.sh`;
      command = `curl -fsSL '${installerUrl}' | sudo bash -s -- --source '${sourceUrl}' --join-token '${token}' --upstream '${sourceUrl}'`;
    }
    this.db.run(
      `INSERT INTO join_tokens(id, token_hash, network_id, parent_id, mode, expires_at, max_uses, used_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?)`,
      id, hashSecret(token), networkId, parent.id, mode, expiresAt, now(),
    );
    this.audit('join-token.create', 'join-token', id, { networkId, parentId: parent.id, mode, expiresAt, parentConnection });
    return { id, token, mode, expiresAt, parent, sourceUrl, publicSourceUrl, parentConnection, command };
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

    const upstreamAddress = String(input.nodeAAddress ?? '').trim();
    const downstreamAddress = String(input.nodeBAddress ?? '').trim();
    if (!upstreamAddress && !downstreamAddress) throw new Error('至少填写一个节点可被对方访问的 IP 或域名');
    const upstreamEndpoint = upstreamAddress
      ? `${normalizeReachableHost(upstreamAddress, `${upstream.name} 的可达地址`)}:${normalizePort(input.nodeAPort, `${upstream.name} 的 WireGuard 端口`, upstream.dataListenPort)}`
      : null;
    const downstreamEndpoint = downstreamAddress
      ? `${normalizeReachableHost(downstreamAddress, `${downstream.name} 的可达地址`)}:${normalizePort(input.nodeBPort, `${downstream.name} 的 WireGuard 端口`, downstream.dataListenPort)}`
      : null;
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
      const controlListenPort = normalizePort(
        input.controlListenPort,
        `${name} 的控制中继端口`,
        endpointDetails(input.controlEndpoint)?.port || 8790,
      );
      this.db.run(
        `INSERT INTO nodes(id, network_id, name, status, is_center, can_relay, parent_id, control_ip, data_ip,
          control_endpoint, control_listen_port, data_endpoint, data_listen_port,
          wg_control_public_key, wg_data_public_key, credential_hash,
          agent_version, last_seen, created_at, updated_at)
         VALUES (?, ?, ?, 'online', 0, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        nodeId, network.id, name, parent.id, controlIp, dataIp,
        input.controlEndpoint ?? null, controlListenPort, input.dataEndpoint ?? null, dataListenPort,
        input.wgControlPublicKey ?? '', input.wgDataPublicKey ?? '', hashSecret(credential),
        input.agentVersion ?? '0.1.0', timestamp, timestamp, timestamp,
      );
      if (token.mode === 'passive') {
        if (!input.dataEndpoint) throw new Error('被动认领节点必须提供父节点可访问的 WireGuard 地址');
        this.db.run(
          `INSERT INTO topology_links(
            id, network_id, upstream_id, downstream_id, priority, upstream_endpoint, downstream_endpoint, created_at
          ) VALUES (?, ?, ?, ?, 100, '', ?, ?)`,
          randomUUID(), network.id, parent.id, nodeId, input.dataEndpoint, timestamp,
        );
      } else {
        this.db.run(
          'INSERT INTO topology_links(id, network_id, upstream_id, downstream_id, priority, created_at) VALUES (?, ?, ?, ?, 100, ?)',
          randomUUID(), network.id, parent.id, nodeId, timestamp,
        );
      }
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

  listLocalCenters() {
    return this.db.all(
      `SELECT n.*, k.data_private_key FROM nodes n
       JOIN local_node_keys k ON k.node_id = n.id
       WHERE n.is_center = 1 ORDER BY n.created_at`,
    ).map((row) => ({ node: nodeFromRow(row), dataPrivateKey: row.data_private_key }));
  }

  getClusterState(networkId) {
    const row = this.db.get('SELECT * FROM cluster_state WHERE network_id = ?', networkId);
    if (!row) throw new Error('节点组缺少协调状态');
    return {
      networkId: row.network_id,
      coordinatorNodeId: row.coordinator_node_id,
      term: Number(row.term),
      revision: Number(row.revision),
      electionSecret: row.election_secret,
      votedFor: row.voted_for,
      updatedAt: row.updated_at,
    };
  }

  clusterVoterIds(networkId) {
    return this.db.all(
      `SELECT n.id FROM nodes n
       LEFT JOIN managed_node_proxies m ON m.node_id = n.id
       WHERE n.network_id = ? AND n.can_relay = 1 AND m.node_id IS NULL
       ORDER BY n.created_at, n.id`,
      networkId,
    ).map((row) => row.id);
  }

  getClusterRuntime(networkId, sourceNodeId = null) {
    const state = this.loadState(networkId);
    const cluster = this.getClusterState(networkId);
    const voterIds = this.clusterVoterIds(networkId);
    const plans = compileControlPlans(state.nodes, state.links, cluster.coordinatorNodeId, voterIds);
    return {
      cluster,
      voterIds,
      voters: voterIds.map((id) => state.nodes.find((node) => node.id === id)).filter(Boolean),
      control: plans[sourceNodeId || cluster.coordinatorNodeId] ?? { maxHops: 16, forwarders: {}, routesByTarget: {} },
    };
  }

  promoteCoordinator(nodeId, term) {
    const node = this.getNode(nodeId);
    const nextTerm = Number(term);
    if (!Number.isInteger(nextTerm) || nextTerm < 1) throw new Error('协调任期无效');
    let versionId = null;
    this.db.transaction(() => {
      const current = this.getClusterState(node.networkId);
      if (nextTerm === current.term && current.coordinatorNodeId === nodeId) return;
      if (nextTerm < current.term || (nextTerm === current.term && current.coordinatorNodeId !== nodeId)) {
        throw new Error('拒绝以过期任期接管配置协调权');
      }
      this.db.run(
        `UPDATE cluster_state SET coordinator_node_id = ?, term = ?, voted_for = ?, updated_at = ?
         WHERE network_id = ?`,
        nodeId, nextTerm, nodeId, now(), node.networkId,
      );
      versionId = this.createVersionInTransaction(node.networkId, `协调节点自动迁移到 ${node.name}`);
      this.audit('coordinator.promote', 'network', node.networkId, { nodeId, term: nextTerm, versionId }, `node:${nodeId}`);
    });
    return { cluster: this.getClusterState(node.networkId), versionId };
  }

  observeCoordinator(networkId, { coordinatorNodeId, term, revision = 0 }) {
    const current = this.getClusterState(networkId);
    const nextTerm = Number(term || 0);
    if (nextTerm < current.term) return current;
    if (nextTerm === current.term && current.coordinatorNodeId !== coordinatorNodeId) return current;
    this.db.run(
      `UPDATE cluster_state SET coordinator_node_id = ?, term = ?, revision = MAX(revision, ?),
       voted_for = NULL, updated_at = ? WHERE network_id = ?`,
      coordinatorNodeId, nextTerm, Number(revision || 0), now(), networkId,
    );
    return this.getClusterState(networkId);
  }

  createVersionInTransaction(networkId, reason, precompiled = null) {
    const state = this.loadState(networkId);
    const compiled = precompiled ?? validateAndCompileTopology(state);
    const pathPolicies = this.listPathPolicies(networkId);
    const nodeById = new Map(state.nodes.map((node) => [node.id, node]));
    const nextAlias = createMultipathAliasAllocator(state.network, state.nodes);
    const aliasAssignments = new Map();
    for (const policy of pathPolicies.filter((item) => item.mode === 'weighted')) {
      for (const path of policy.paths) {
        aliasAssignments.set(`${policy.id}:${path.pathId}`, {
          source: nextAlias(),
          target: nextAlias(),
        });
      }
    }
    const cluster = this.getClusterState(networkId);
    const voterIds = this.clusterVoterIds(networkId);
    const controlPlans = compileControlPlans(state.nodes, state.links, cluster.coordinatorNodeId, voterIds);
    for (const [nodeId, config] of Object.entries(compiled.configs)) {
      config.control = controlPlans[nodeId] ?? { maxHops: 16, forwarders: {}, routes: [], routesByTarget: {}, truncated: false };
      config.control.cluster = {
        networkId,
        coordinatorNodeId: cluster.coordinatorNodeId,
        term: cluster.term,
        revision: cluster.revision,
        electionSecret: cluster.electionSecret,
        voterIds,
      };
    }
    for (const config of Object.values(compiled.configs)) config.multipathPolicies = [];
    const failedLinkIds = this.failedLinkIds(networkId);
    const claimedWeightedRoutes = new Map();
    for (const policy of pathPolicies) {
      const availablePathIds = new Set(policy.paths.filter((path) =>
        !(path.linkIds ?? []).some((linkId) => failedLinkIds.has(linkId))).map((path) => path.pathId));
      const totalWeight = policy.mode === 'weighted'
        ? policy.paths.filter((path) => availablePathIds.has(path.pathId))
          .reduce((total, path) => total + Number(path.weight), 0)
        : 0;
      if (policy.mode === 'weighted') {
        for (const path of policy.paths) {
          const aliases = aliasAssignments.get(`${policy.id}:${path.pathId}`);
          const forwardNodes = path.nodeIds;
          for (let index = 0; index < forwardNodes.length - 1; index += 1) {
            addPeerAllowedIp(compiled.configs[forwardNodes[index]], forwardNodes[index + 1], `${aliases.target}/32`);
          }
          for (let index = forwardNodes.length - 1; index > 0; index -= 1) {
            addPeerAllowedIp(compiled.configs[forwardNodes[index]], forwardNodes[index - 1], `${aliases.source}/32`);
          }
        }
      }
      for (const [sourceId, targetId, reverse] of [
        [policy.sourceId, policy.targetId, false],
        [policy.targetId, policy.sourceId, true],
      ]) {
        const config = compiled.configs[sourceId];
        if (!config) continue;
        const routeCidrs = policy.mode === 'weighted'
          ? routeCidrsThrough(compiled, nodeById, sourceId, targetId)
          : [];
        for (const destination of routeCidrs) {
          const key = `${sourceId}:${destination}`;
          const owner = claimedWeightedRoutes.get(key);
          if (owner && owner !== policy.id) {
            throw new Error(`加权策略冲突：节点 ${nodeById.get(sourceId)?.name || sourceId} 的目的地址 ${destination} 同时被多个策略接管`);
          }
          claimedWeightedRoutes.set(key, policy.id);
        }
        config.multipathPolicies.push({
          policyId: policy.id,
          targetNodeId: targetId,
          mode: policy.mode,
          switchOnFailure: true,
          selection: policy.mode === 'weighted' ? 'weighted-random' : 'ordered-failover',
          healthProbeIntervalSeconds: 20,
          routeCidrs,
          activePathIds: policy.paths.filter((path) => availablePathIds.has(path.pathId)).map((path) => path.pathId),
          paths: policy.paths.map((path, index) => {
            const nodeIds = reverse ? [...path.nodeIds].reverse() : [...path.nodeIds];
            const linkIds = reverse ? [...path.linkIds].reverse() : [...path.linkIds];
            const available = availablePathIds.has(path.pathId);
            const aliases = aliasAssignments.get(`${policy.id}:${path.pathId}`);
            return {
              pathId: path.pathId,
              weight: Number(path.weight),
              effectiveWeight: policy.mode === 'weighted' && !available ? 0 : Number(path.weight),
              order: Number(path.order ?? 0),
              isDefault: policy.mode === 'failover' && index === 0,
              available,
              health: available ? 'active' : 'temporarily-excluded',
              failedLinkIds: linkIds.filter((linkId) => failedLinkIds.has(linkId)),
              share: policy.mode === 'weighted' && available && totalWeight
                ? Number((Number(path.weight) / totalWeight).toFixed(4))
                : policy.mode === 'weighted' ? 0 : null,
              nextHopId: nodeIds[1],
              localTunnelIp: reverse ? aliases?.target : aliases?.source,
              remoteTunnelIp: reverse ? aliases?.source : aliases?.target,
              nodeIds,
              linkIds,
            };
          }),
        });
      }
      if (policy.mode === 'failover' && policy.paths[0]?.nodeIds?.length > 1) {
        applyPreferredPath(compiled, state, policy.paths[0].nodeIds);
        applyPreferredPath(compiled, state, [...policy.paths[0].nodeIds].reverse());
      }
    }
    const next = this.db.get('SELECT COALESCE(MAX(version), 0) + 1 AS version FROM config_versions WHERE network_id = ?', networkId);
    const id = randomUUID();
    const timestamp = now();
    const requiredNodes = state.nodes.filter((node) => node.status === 'online');
    const autoActivated = !this.manageLocalCenters && requiredNodes.length > 0 && requiredNodes.every((node) => node.isCenter);
    const status = autoActivated ? 'active' : 'preparing';
    this.db.run(
      "UPDATE config_versions SET status = 'superseded' WHERE network_id = ? AND status IN ('preparing', 'activating')",
      networkId,
    );
    this.db.run(
      `UPDATE network_cidr_changes SET status = 'superseded'
       WHERE status = 'pending' AND version_id IN (
         SELECT id FROM config_versions WHERE network_id = ? AND status = 'superseded'
       )`,
      networkId,
    );
    this.db.run(
      `INSERT INTO config_versions(id, network_id, version, status, reason, topology_json, created_at, activated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      id, networkId, Number(next.version), status, reason,
      json({ links: compiled.links, paths: compiled.paths, pathPolicies, summary: compiled.summary }), timestamp,
      autoActivated ? timestamp : null,
    );
    for (const node of state.nodes) {
      const autoActivatedCenter = node.isCenter && !this.manageLocalCenters;
      const phase = autoActivatedCenter ? 'activated' : 'pending';
      const required = node.status === 'online';
      this.db.run(
        `INSERT INTO node_configs(version_id, node_id, phase, required, config_json, prepared_at, activated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        id, node.id, phase, required ? 1 : 0, json({ ...compiled.configs[node.id], version: Number(next.version), versionId: id }),
        autoActivatedCenter ? timestamp : null, autoActivatedCenter ? timestamp : null,
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
      `SELECT c.node_id, n.name, n.status AS node_status, c.phase, c.required, c.error, c.prepared_at, c.activated_at
       FROM node_configs c JOIN nodes n ON n.id = c.node_id WHERE c.version_id = ? ORDER BY n.name`, id,
    ).map((item) => ({
      nodeId: item.node_id,
      name: item.name,
      nodeStatus: item.node_status,
      phase: item.phase,
      required: Boolean(item.required),
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

  recordLinkHealthAndUpdatePolicies(node, linkHealth, timestamp) {
    const empty = { rotated: [], weightedChanges: [] };
    if (!linkHealth?.available || !Array.isArray(linkHealth.links)) return empty;
    const beforeFailedLinkIds = this.failedLinkIds(node.networkId);
    const incident = new Set(this.listLinks(node.networkId, true).filter((link) =>
      link.upstreamId === node.id || link.downstreamId === node.id).map((link) => link.id));
    for (const report of linkHealth.links) {
      if (!incident.has(report.linkId) || !['reachable', 'unreachable'].includes(report.status)) continue;
      this.db.run(
        `INSERT INTO link_health_reports(node_id, link_id, status, observed_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(node_id, link_id) DO UPDATE SET status = excluded.status, observed_at = excluded.observed_at`,
        node.id, report.linkId, report.status, timestamp,
      );
    }
    const failedLinkIds = this.failedLinkIds(node.networkId);
    const policies = this.listPathPolicies(node.networkId);
    const weightedChanges = [];
    for (const policy of policies.filter((item) => item.mode === 'weighted')) {
      const beforeActive = policy.paths.filter((path) =>
        !(path.linkIds ?? []).some((linkId) => beforeFailedLinkIds.has(linkId))).map((path) => path.pathId);
      const afterActive = policy.paths.filter((path) =>
        !(path.linkIds ?? []).some((linkId) => failedLinkIds.has(linkId))).map((path) => path.pathId);
      if (beforeActive.join('\n') === afterActive.join('\n')) continue;
      weightedChanges.push({
        policyId: policy.id,
        excludedPathIds: beforeActive.filter((pathId) => !afterActive.includes(pathId)),
        recoveredPathIds: afterActive.filter((pathId) => !beforeActive.includes(pathId)),
        activePathIds: afterActive,
      });
    }
    const rotated = [];
    for (const policy of policies.filter((item) => item.mode === 'failover')) {
      const current = policy.paths[0];
      if (!current?.linkIds?.some((linkId) => failedLinkIds.has(linkId))) continue;
      const replacement = policy.paths.find((path) => !path.linkIds?.some((linkId) => failedLinkIds.has(linkId)));
      if (!replacement || replacement.pathId === current.pathId) continue;
      const reordered = [replacement, ...policy.paths.filter((path) => path.pathId !== replacement.pathId)]
        .map((path, order) => ({ ...path, order }));
      this.db.run('UPDATE path_policies SET paths_json = ?, updated_at = ? WHERE id = ?', json(reordered), timestamp, policy.id);
      rotated.push({ policyId: policy.id, fromPathId: current.pathId, toPathId: replacement.pathId });
    }
    return { rotated, weightedChanges };
  }

  heartbeat(nodeId, input = {}) {
    const timestamp = now();
    const node = this.getNode(nodeId);
    const dataListenPort = normalizePort(input.dataListenPort, `${node.name} 的 WireGuard 端口`, node.dataListenPort);
    const controlListenPort = normalizePort(input.controlListenPort, `${node.name} 的控制中继端口`, node.controlListenPort);
    const portChanged = dataListenPort !== node.dataListenPort;
    let versionId = null;
    this.db.transaction(() => {
      this.db.run(
        `UPDATE nodes SET status = 'online', last_seen = ?, agent_version = COALESCE(?, agent_version),
         control_endpoint = COALESCE(?, control_endpoint), data_endpoint = COALESCE(?, data_endpoint),
         control_listen_port = ?, data_listen_port = ?, updated_at = ? WHERE id = ?`,
        timestamp, input.agentVersion ?? null, input.controlEndpoint ?? null, input.dataEndpoint ?? null,
        controlListenPort, dataListenPort, timestamp, nodeId,
      );
      const policyHealth = this.recordLinkHealthAndUpdatePolicies(node, input.linkHealth, timestamp);
      if (portChanged || policyHealth.rotated.length || policyHealth.weightedChanges.length) {
        const reasons = [
          portChanged ? `节点 ${node.name} 更新 WireGuard 端口` : '',
          policyHealth.rotated.length ? `检测到线路故障，自动切换 ${policyHealth.rotated.length} 项默认路径` : '',
          policyHealth.weightedChanges.length ? `检测到链路状态变化，更新 ${policyHealth.weightedChanges.length} 项负载均衡成员` : '',
        ].filter(Boolean);
        versionId = this.createVersionInTransaction(node.networkId, reasons.join('；'));
        if (policyHealth.rotated.length) this.audit('path-policy.failover', 'network', node.networkId, { nodeId, rotated: policyHealth.rotated, versionId }, `node:${nodeId}`);
        if (policyHealth.weightedChanges.length) this.audit('path-policy.weighted-health', 'network', node.networkId, {
          nodeId, changes: policyHealth.weightedChanges, versionId,
        }, `node:${nodeId}`);
      }
      if (portChanged) {
        this.audit('agent.data-port', 'node', nodeId, { before: node.dataListenPort, after: dataListenPort, versionId }, `node:${nodeId}`);
      }
    });
    const cluster = this.getClusterState(node.networkId);
    return {
      acknowledgedAt: timestamp,
      controlListenPort,
      dataListenPort,
      versionId,
      cluster: {
        networkId: cluster.networkId,
        coordinatorNodeId: cluster.coordinatorNodeId,
        term: cluster.term,
        revision: cluster.revision,
        voterIds: this.clusterVoterIds(node.networkId),
      },
    };
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
      this.db.transaction(() => {
        this.db.run("UPDATE config_versions SET status = 'failed' WHERE id = ?", versionId);
        this.db.run(
          "UPDATE network_cidr_changes SET status = 'failed', error = ? WHERE version_id = ? AND status = 'pending'",
          error, versionId,
        );
        this.audit('config.failed', 'config-version', versionId, { nodeId, phase, error }, `node:${nodeId}`);
      });
      return this.getConfiguration(versionId);
    }

    this.advanceConfigurationRollout(versionId, timestamp);
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
    if (!link || link.validation_status === 'failed') return;
    const isUpstream = link.upstream_id === nodeId;
    if (!isUpstream && link.downstream_id !== nodeId) return;
    if (commandType === 'prepare-link-probe' && !result.ok) {
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
        const upstream = this.getNode(updated.upstream_id);
        const downstream = this.getNode(updated.downstream_id);
        if (updated.downstream_endpoint) {
          this.enqueueCommand(updated.upstream_id, 'execute-link-probe', {
            validationId: link.id,
            probeId: randomUUID(),
            maxHops: 16,
            token: updated.validation_token,
            remoteUrl: probeUrl(downstream, updated.downstream_endpoint),
            expectedNodeId: updated.downstream_id,
          });
        }
        if (updated.upstream_endpoint) {
          this.enqueueCommand(updated.downstream_id, 'execute-link-probe', {
            validationId: link.id,
            probeId: randomUUID(),
            maxHops: 16,
            token: updated.validation_token,
            remoteUrl: probeUrl(upstream, updated.upstream_endpoint),
            expectedNodeId: updated.upstream_id,
          });
        }
      }
      return;
    }

    const field = isUpstream ? 'validation_probed_upstream' : 'validation_probed_downstream';
    const errorField = isUpstream ? 'validation_probe_error_upstream' : 'validation_probe_error_downstream';
    const probeValue = result.ok ? 1 : -1;
    this.db.run(
      `UPDATE topology_links SET ${field} = ?, ${errorField} = ? WHERE id = ?`,
      probeValue, result.ok ? null : (result.error || '该方向不可达'), link.id,
    );
    const updated = this.db.get('SELECT * FROM topology_links WHERE id = ?', link.id);
    const successes = Number(updated.validation_probed_upstream > 0) + Number(updated.validation_probed_downstream > 0);
    const completed = Number(updated.validation_probed_upstream !== 0) + Number(updated.validation_probed_downstream !== 0);
    const requested = Number(Boolean(updated.downstream_endpoint)) + Number(Boolean(updated.upstream_endpoint));
    if (link.validation_status === 'active') {
      return;
    }
    if (completed < requested) return;
    if (successes > 0) {
      this.db.transaction(() => {
        this.activateValidatedLinkInTransaction(link, now(), '新增已验证的数据通路', 'topology-link.active');
      });
      return;
    }
    if (completed === requested) {
      const errors = [updated.validation_probe_error_upstream, updated.validation_probe_error_downstream].filter(Boolean);
      this.db.run(
        `UPDATE topology_links SET validation_status = 'failed', validation_error = ?, validation_token = NULL WHERE id = ?`,
        errors.join('；') || '所有已填写方向均无法建立连接', link.id,
      );
      this.audit('topology-link.failed', 'topology-link', link.id, { errors }, `node:${nodeId}`);
    }
  }

  activateValidatedLinkInTransaction(link, timestamp, reason, auditAction) {
    this.db.run(
      `UPDATE topology_links SET validation_status = 'active', validation_error = NULL,
       upstream_endpoint = CASE WHEN validation_probed_downstream > 0 THEN upstream_endpoint ELSE '' END,
       downstream_endpoint = CASE WHEN validation_probed_upstream > 0 THEN downstream_endpoint ELSE '' END,
       validation_token = NULL, validated_at = ? WHERE id = ?`,
      timestamp, link.id,
    );
    const validated = this.db.get(
      'SELECT validation_probed_upstream, validation_probed_downstream FROM topology_links WHERE id = ?',
      link.id,
    );
    const versionId = this.createVersionInTransaction(link.network_id, reason);
    this.audit(auditAction, 'topology-link', link.id, {
      versionId,
      usableDirections: {
        upstreamToDownstream: Number(validated.validation_probed_upstream) > 0,
        downstreamToUpstream: Number(validated.validation_probed_downstream) > 0,
      },
    });
    return versionId;
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
