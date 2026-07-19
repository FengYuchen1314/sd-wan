import { createHash } from 'node:crypto';

function compare(valueA, valueB) {
  return String(valueA).localeCompare(String(valueB));
}

function stablePathId(linkIds) {
  const forward = linkIds.join('\u0000');
  const reverse = [...linkIds].reverse().join('\u0000');
  const canonical = forward < reverse ? forward : reverse;
  return `path_${createHash('sha256').update(canonical).digest('hex').slice(0, 20)}`;
}

export function enumerateSimplePaths({ nodes, links, sourceId, targetId, maxPaths = 24, searchLimit = 512 }) {
  if (!Array.isArray(nodes) || !Array.isArray(links)) throw new Error('节点和连接必须是数组');
  if (!sourceId || !targetId || sourceId === targetId) throw new Error('请选择两个不同的节点');
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  if (!nodeById.has(sourceId) || !nodeById.has(targetId)) throw new Error('所选节点不存在');

  const adjacency = new Map(nodes.map((node) => [node.id, []]));
  for (const link of links) {
    if (!adjacency.has(link.upstreamId) || !adjacency.has(link.downstreamId)) continue;
    const cost = Math.max(0, Number(link.priority) || 0) + 1;
    adjacency.get(link.upstreamId).push({ peerId: link.downstreamId, linkId: link.id, cost });
    adjacency.get(link.downstreamId).push({ peerId: link.upstreamId, linkId: link.id, cost });
  }
  for (const edges of adjacency.values()) {
    edges.sort((edgeA, edgeB) => edgeA.cost - edgeB.cost || compare(edgeA.peerId, edgeB.peerId));
  }

  const found = [];
  const visited = new Set([sourceId]);
  const nodeIds = [sourceId];
  const linkIds = [];
  const maximumDepth = nodes.length - 1;

  function visit(currentId, totalCost) {
    if (found.length >= searchLimit) return;
    if (currentId === targetId) {
      found.push({
        id: stablePathId(linkIds),
        nodeIds: [...nodeIds],
        linkIds: [...linkIds],
        hops: linkIds.length,
        totalCost,
      });
      return;
    }
    if (linkIds.length >= maximumDepth) return;
    for (const edge of adjacency.get(currentId) ?? []) {
      if (visited.has(edge.peerId)) continue;
      visited.add(edge.peerId);
      nodeIds.push(edge.peerId);
      linkIds.push(edge.linkId);
      visit(edge.peerId, totalCost + edge.cost);
      linkIds.pop();
      nodeIds.pop();
      visited.delete(edge.peerId);
      if (found.length >= searchLimit) return;
    }
  }

  visit(sourceId, 0);
  found.sort((pathA, pathB) =>
    pathA.totalCost - pathB.totalCost ||
    pathA.hops - pathB.hops ||
    compare(pathA.nodeIds.join('\u0000'), pathB.nodeIds.join('\u0000')),
  );
  return {
    paths: found.slice(0, Math.max(1, Number(maxPaths) || 24)),
    truncated: found.length > maxPaths || found.length >= searchLimit,
  };
}

