function normalizeEndpoint(value) {
  if (value === undefined || value === null || value === '') return null;
  return value;
}

function endpointFallback(node) {
  return node?.reachabilityType === 'public' ? (node.dataEndpoint ?? null) : null;
}

export function isParentChildLink(upstreamNode, downstreamNode) {
  return downstreamNode?.parentId === upstreamNode?.id;
}

/** 主动加入或纯 NAT 节点只主动拨出，对端应动态学习其 Endpoint。 */
export function isDialOutOnlyNode(node) {
  return node?.joinMode === 'active' || node?.reachabilityType === 'nat';
}

export function isActiveJoinLink(link, upstreamNode, downstreamNode) {
  if (!isParentChildLink(upstreamNode, downstreamNode)) return false;
  if (downstreamNode?.joinMode === 'active') return true;
  const rawDownstream = normalizeEndpoint(link.downstreamEndpoint);
  const rawUpstream = link.upstreamEndpoint;
  // 被动认领：父节点保存子节点 Endpoint，upstream 为空
  if (rawDownstream && !normalizeEndpoint(rawUpstream === undefined ? null : rawUpstream)) return false;
  const upstreamEndpoint = rawUpstream === undefined
    ? endpointFallback(upstreamNode)
    : normalizeEndpoint(rawUpstream);
  return Boolean(upstreamEndpoint);
}

export function resolveLinkEndpoints(link, upstreamNode, downstreamNode) {
  let upstreamEndpoint = link.upstreamEndpoint === undefined
    ? endpointFallback(upstreamNode)
    : link.upstreamEndpoint || null;
  let downstreamEndpoint = link.downstreamEndpoint === undefined
    ? endpointFallback(downstreamNode)
    : link.downstreamEndpoint || null;
  upstreamEndpoint = normalizeEndpoint(upstreamEndpoint);
  downstreamEndpoint = normalizeEndpoint(downstreamEndpoint);

  if (isActiveJoinLink(link, upstreamNode, downstreamNode)) {
    downstreamEndpoint = null;
  }
  if (isDialOutOnlyNode(downstreamNode)) {
    downstreamEndpoint = null;
  }
  if (isDialOutOnlyNode(upstreamNode)) {
    upstreamEndpoint = null;
  }

  return { upstreamEndpoint, downstreamEndpoint };
}

export function remoteEndpointForSource(link, sourceId, upstreamNode, downstreamNode) {
  const resolved = resolveLinkEndpoints(link, upstreamNode, downstreamNode);
  return link.upstreamId === sourceId ? resolved.downstreamEndpoint : resolved.upstreamEndpoint;
}
