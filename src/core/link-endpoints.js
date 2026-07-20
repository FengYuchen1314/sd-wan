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

/**
 * 初始化 B 连 A 的父子链路：WireGuard 层恒把 B（downstream）当 NAT，由 B 持续拨号 A。
 * 与 reachabilityType / IX / 公网等上层分类无关。
 */
export function isChildInitiatedJoinLink(link, upstreamNode, downstreamNode) {
  return isParentChildLink(upstreamNode, downstreamNode) && downstreamNode?.joinMode === 'active';
}

/** @deprecated 使用 isChildInitiatedJoinLink */
export function isActiveJoinLink(link, upstreamNode, downstreamNode) {
  return isChildInitiatedJoinLink(link, upstreamNode, downstreamNode);
}

/** 上层策略：纯 NAT 节点在后续手动拓扑里不可被对端 WG 拨入。与初始化 join 链路无关。 */
export function isDialOutOnlyNode(node) {
  return node?.reachabilityType === 'nat';
}

/** 面板手动连接两个公网节点且两端 Endpoint 均已填写时，才做双向 WG 探测。 */
export function isManualBidirectionalPublicLink(upstreamNode, downstreamNode, upstreamEndpoint, downstreamEndpoint) {
  if (!normalizeEndpoint(upstreamEndpoint) || !normalizeEndpoint(downstreamEndpoint)) return false;
  if (isParentChildLink(upstreamNode, downstreamNode)) return false;
  return upstreamNode?.reachabilityType === 'public' && downstreamNode?.reachabilityType === 'public';
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

  if (isChildInitiatedJoinLink(link, upstreamNode, downstreamNode)) {
    downstreamEndpoint = null;
  }
  if (isDialOutOnlyNode(downstreamNode) && !isChildInitiatedJoinLink(link, upstreamNode, downstreamNode)) {
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

/** WireGuard 拨号方向；控制面 ping/延迟沿同一方向，目标地址用 overlay 内网 IP。 */
export function selectLinkDialDirection(link, upstreamNode, downstreamNode) {
  if (isChildInitiatedJoinLink(link, upstreamNode, downstreamNode)) {
    return { dialerId: downstreamNode.id, targetId: upstreamNode.id };
  }
  if (isParentChildLink(upstreamNode, downstreamNode) && downstreamNode?.joinMode === 'passive') {
    return { dialerId: upstreamNode.id, targetId: downstreamNode.id };
  }
  const resolved = resolveLinkEndpoints(link, upstreamNode, downstreamNode);
  if (resolved.downstreamEndpoint) {
    return { dialerId: upstreamNode.id, targetId: downstreamNode.id };
  }
  if (resolved.upstreamEndpoint) {
    return { dialerId: downstreamNode.id, targetId: upstreamNode.id };
  }
  return { dialerId: upstreamNode.id, targetId: downstreamNode.id };
}

export function selectLinkBenchmarkDirection(link, upstreamNode, downstreamNode) {
  const { dialerId, targetId } = selectLinkDialDirection(link, upstreamNode, downstreamNode);
  return { sourceId: dialerId, targetId };
}

export function validationInternalProbePlan(linkRow, upstreamNode, downstreamNode) {
  const downstreamEndpoint = linkRow.downstream_endpoint ?? linkRow.downstreamEndpoint;
  const upstreamEndpoint = linkRow.upstream_endpoint ?? linkRow.upstreamEndpoint;
  const hasDown = Boolean(normalizeEndpoint(downstreamEndpoint));
  const hasUp = Boolean(normalizeEndpoint(upstreamEndpoint));
  const canOverlay = Boolean(upstreamNode?.dataIp && downstreamNode?.dataIp);
  const probe = (sourceId, targetId) => ({ sourceId, targetId });
  const link = {
    upstreamId: upstreamNode?.id ?? linkRow.upstream_id,
    downstreamId: downstreamNode?.id ?? linkRow.downstream_id,
    upstreamEndpoint,
    downstreamEndpoint,
  };

  if (isManualBidirectionalPublicLink(upstreamNode, downstreamNode, upstreamEndpoint, downstreamEndpoint) && canOverlay) {
    return {
      requested: 2,
      probes: [probe(upstreamNode.id, downstreamNode.id), probe(downstreamNode.id, upstreamNode.id)],
    };
  }
  if (hasDown !== hasUp) {
    const probes = [];
    if (hasDown) probes.push(probe(upstreamNode.id, downstreamNode.id));
    if (hasUp) probes.push(probe(downstreamNode.id, upstreamNode.id));
    return { requested: probes.length, probes };
  }
  if (!hasDown && !hasUp && canOverlay) {
    const { dialerId, targetId } = selectLinkDialDirection(link, upstreamNode, downstreamNode);
    return { requested: 1, probes: [probe(dialerId, targetId)] };
  }
  const probes = [];
  if (hasDown) probes.push(probe(upstreamNode.id, downstreamNode.id));
  if (hasUp) probes.push(probe(downstreamNode.id, upstreamNode.id));
  return { requested: probes.length, probes };
}

export function validationProbeRequestedFlags(linkRow, upstreamNode = null, downstreamNode = null) {
  const downstreamEndpoint = linkRow.downstream_endpoint ?? linkRow.downstreamEndpoint;
  const upstreamEndpoint = linkRow.upstream_endpoint ?? linkRow.upstreamEndpoint;
  const upstreamProbe = Number(linkRow.validation_probed_upstream ?? linkRow.validationProbedUpstream ?? 0);
  const downstreamProbe = Number(linkRow.validation_probed_downstream ?? linkRow.validationProbedDownstream ?? 0);
  if (upstreamNode && downstreamNode) {
    if (isManualBidirectionalPublicLink(upstreamNode, downstreamNode, upstreamEndpoint, downstreamEndpoint)) {
      return {
        upstreamRequested: true,
        downstreamRequested: true,
      };
    }
    const { dialerId } = selectLinkDialDirection(
      {
        upstreamId: upstreamNode.id,
        downstreamId: downstreamNode.id,
        upstreamEndpoint,
        downstreamEndpoint,
      },
      upstreamNode,
      downstreamNode,
    );
    return {
      upstreamRequested: dialerId === upstreamNode.id || upstreamProbe !== 0,
      downstreamRequested: dialerId === downstreamNode.id || downstreamProbe !== 0,
    };
  }
  return {
    upstreamRequested: Boolean(normalizeEndpoint(downstreamEndpoint)) || upstreamProbe !== 0,
    downstreamRequested: Boolean(normalizeEndpoint(upstreamEndpoint)) || downstreamProbe !== 0,
  };
}
