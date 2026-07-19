import { assertUsableHost } from './ipv4.js';

export class TopologyError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'TopologyError';
    this.details = details;
  }
}

function stableCompare(a, b) {
  return String(a).localeCompare(String(b));
}

function pathKey(path) {
  return path.join('\u0000');
}

function shortestPaths(sourceId, nodeIds, adjacency) {
  const best = new Map([[sourceId, { cost: 0, path: [sourceId] }]]);
  const pending = new Set(nodeIds);

  while (pending.size > 0) {
    let current = null;
    for (const candidate of pending) {
      const record = best.get(candidate);
      if (!record) continue;
      if (!current) {
        current = candidate;
        continue;
      }
      const chosen = best.get(current);
      if (record.cost < chosen.cost ||
          (record.cost === chosen.cost && pathKey(record.path) < pathKey(chosen.path))) {
        current = candidate;
      }
    }
    if (!current) break;
    pending.delete(current);
    const currentRecord = best.get(current);

    for (const edge of adjacency.get(current) ?? []) {
      if (!pending.has(edge.peerId)) continue;
      const candidate = {
        cost: currentRecord.cost + edge.cost,
        path: [...currentRecord.path, edge.peerId],
      };
      const previous = best.get(edge.peerId);
      if (!previous || candidate.cost < previous.cost ||
          (candidate.cost === previous.cost && pathKey(candidate.path) < pathKey(previous.path))) {
        best.set(edge.peerId, candidate);
      }
    }
  }
  return best;
}

export function validateAndCompileTopology({ network, nodes, links }) {
  if (!network?.id) throw new TopologyError('缺少节点组信息');
  if (!Array.isArray(nodes) || nodes.length === 0) throw new TopologyError('节点组至少需要一个节点');
  if (!Array.isArray(links)) throw new TopologyError('拓扑连接必须是数组');

  const nodeById = new Map();
  const ipOwners = new Map();
  for (const node of nodes) {
    if (!node.id || nodeById.has(node.id)) throw new TopologyError('节点 ID 缺失或重复');
    let dataIp;
    try {
      dataIp = assertUsableHost(network.dataCidr, node.dataIp, `节点 ${node.name} 的业务 IP`);
      assertUsableHost(network.controlCidr, node.controlIp, `节点 ${node.name} 的控制 IP`);
    } catch (error) {
      throw new TopologyError(error.message, { nodeId: node.id });
    }
    if (ipOwners.has(dataIp)) {
      throw new TopologyError(`业务 IP ${dataIp} 被多个节点使用`, {
        nodeIds: [ipOwners.get(dataIp), node.id],
      });
    }
    ipOwners.set(dataIp, node.id);
    nodeById.set(node.id, { ...node, dataIp });
  }

  const adjacency = new Map([...nodeById.keys()].map((id) => [id, []]));
  const linkKeys = new Set();
  const normalizedLinks = [];
  for (const link of links) {
    const upstreamId = link.upstreamId;
    const downstreamId = link.downstreamId;
    if (!nodeById.has(upstreamId) || !nodeById.has(downstreamId)) {
      throw new TopologyError('拓扑连接引用了不存在的节点', { link });
    }
    if (upstreamId === downstreamId) {
      throw new TopologyError('节点不能把自己设置为上游或下游', { nodeId: upstreamId });
    }
    const key = [upstreamId, downstreamId].sort(stableCompare).join(':');
    if (linkKeys.has(key)) throw new TopologyError('两个节点之间存在重复连接', { link });
    linkKeys.add(key);
    const priority = Number.isInteger(Number(link.priority)) ? Math.max(0, Number(link.priority)) : 100;
    const normalized = {
      ...(link.id ? { id: link.id } : {}),
      upstreamId,
      downstreamId,
      priority,
      upstreamEndpoint: link.upstreamEndpoint ?? null,
      downstreamEndpoint: link.downstreamEndpoint ?? null,
      validationStatus: link.validationStatus ?? 'active',
    };
    normalizedLinks.push(normalized);
    const cost = priority + 1;
    adjacency.get(upstreamId).push({
      peerId: downstreamId, cost, link: normalized, remoteEndpoint: normalized.downstreamEndpoint,
    });
    adjacency.get(downstreamId).push({
      peerId: upstreamId, cost, link: normalized, remoteEndpoint: normalized.upstreamEndpoint,
    });
  }

  for (const edges of adjacency.values()) {
    edges.sort((a, b) => a.cost - b.cost || stableCompare(a.peerId, b.peerId));
  }

  const nodeIds = [...nodeById.keys()].sort(stableCompare);
  const routes = {};
  const paths = {};
  for (const sourceId of nodeIds) {
    const best = shortestPaths(sourceId, nodeIds, adjacency);
    if (best.size !== nodeIds.length) {
      const unreachable = nodeIds.filter((id) => !best.has(id));
      throw new TopologyError(`拓扑不连通，${nodeById.get(sourceId).name} 无法到达 ${unreachable.map((id) => nodeById.get(id).name).join('、')}`, {
        sourceId,
        unreachable,
      });
    }
    routes[sourceId] = {};
    for (const targetId of nodeIds) {
      if (targetId === sourceId) continue;
      const path = best.get(targetId).path;
      routes[sourceId][targetId] = path[1];
      paths[`${sourceId}:${targetId}`] = path;
    }
  }

  const configs = {};
  for (const nodeId of nodeIds) {
    const node = nodeById.get(nodeId);
    const allowedByPeer = new Map();
    for (const [targetId, nextHopId] of Object.entries(routes[nodeId])) {
      const directEdge = adjacency.get(nodeId).find((edge) => edge.peerId === nextHopId);
      const record = allowedByPeer.get(nextHopId) ?? { allowedIps: [], endpoint: directEdge?.remoteEndpoint ?? null };
      record.allowedIps.push(`${nodeById.get(targetId).dataIp}/32`);
      allowedByPeer.set(nextHopId, record);
    }

    const peers = [...allowedByPeer.entries()]
      .sort(([a], [b]) => stableCompare(a, b))
      .map(([peerId, route]) => {
        const peer = nodeById.get(peerId);
        return {
          nodeId: peerId,
          name: peer.name,
          publicKey: peer.wgDataPublicKey ?? '',
          endpoint: route.endpoint ?? peer.dataEndpoint ?? null,
          probeIp: peer.dataIp,
          allowedIps: route.allowedIps.sort(),
          persistentKeepalive: 25,
        };
      });

    configs[nodeId] = {
      schemaVersion: 1,
      networkId: network.id,
      nodeId,
      data: {
        interfaceName: node.isCenter ? `pw-${network.id.replace(/-/g, '').slice(0, 10)}` : 'pw-data',
        networkCidr: network.dataCidr,
        address: `${node.dataIp}/32`,
        listenPort: node.dataListenPort ?? network.listenPort ?? 19801,
        mtu: network.mtu,
        peers,
        links: (adjacency.get(nodeId) ?? []).map((edge) => ({
          linkId: edge.link.id ?? null,
          peerNodeId: edge.peerId,
          peerPublicKey: nodeById.get(edge.peerId).wgDataPublicKey ?? '',
        })).filter((link) => link.linkId),
      },
      routes: Object.entries(routes[nodeId]).map(([targetId, viaNodeId]) => ({
        destination: `${nodeById.get(targetId).dataIp}/32`,
        targetNodeId: targetId,
        viaNodeId,
      })),
    };
  }

  return {
    links: normalizedLinks,
    routes,
    paths,
    configs,
    summary: {
      nodes: nodeIds.length,
      links: normalizedLinks.length,
      routes: nodeIds.length * Math.max(0, nodeIds.length - 1),
      fullyReachable: true,
    },
  };
}
