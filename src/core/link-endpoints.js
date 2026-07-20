/**
 * 链路 Endpoint 语义（两层架构）
 *
 * 底层 WireGuard：只描述谁 static-dial 谁，沿物理建链路径单向维持（B→A），与节点类型无关。
 * 控制层：overlay 虚拟内网 IP 上的 HTTP 中继与路由，由 compileControlPlans 单独编译。
 *
 * 规则摘要：
 * - 初始化 join（父子链路）：恒 B(downstream) 拨 A(upstream)，即使 B 是公网节点也不双向 WG
 * - 面板手动 NAT/IX→公网：单向 WG，非公网侧拨公网 Endpoint
 * - 面板手动双公网：双向 WG（两端 Endpoint 均填写），验证须两方向都成功
 */

function normalizeEndpoint(value) {
  if (value === undefined || value === null || value === '') return null;
  return value;
}

function endpointFallback(node) {
  return node?.reachabilityType === 'public' ? (node.dataEndpoint ?? null) : null;
}

function controlEndpointHost(value) {
  if (!value) return null;
  try {
    return new URL(String(value)).hostname || null;
  } catch {
    return null;
  }
}

/** 初始化 join 链路上父节点 WG 端点：优先链路/令牌，否则回退到父节点 dataEndpoint。 */
export function resolveInitializationJoinUpstreamEndpoint(link, upstreamNode, parentDataEndpoint = null) {
  const fromLink = normalizeEndpoint(link?.upstreamEndpoint ?? link?.upstream_endpoint);
  if (fromLink) return fromLink;
  const fromToken = normalizeEndpoint(parentDataEndpoint);
  if (fromToken) return fromToken;
  const fromNode = normalizeEndpoint(upstreamNode?.dataEndpoint);
  if (fromNode) return fromNode;
  const fromPublic = endpointFallback(upstreamNode);
  if (fromPublic) return normalizeEndpoint(fromPublic);
  const controlHost = controlEndpointHost(upstreamNode?.controlEndpoint);
  const dataPort = Number(upstreamNode?.dataListenPort);
  if (controlHost && Number.isInteger(dataPort) && dataPort > 0) {
    return `${controlHost}:${dataPort}`;
  }
  return null;
}

export function isParentChildLink(upstreamNode, downstreamNode) {
  return downstreamNode?.parentId === upstreamNode?.id;
}

/** 初始化 join 形成的父子链路（主动加入与被动认领均按 B→A 建 WG）。 */
export function isInitializationJoinLink(upstreamNode, downstreamNode) {
  return isParentChildLink(upstreamNode, downstreamNode);
}

/** @deprecated 使用 isInitializationJoinLink */
export function isChildInitiatedJoinLink(link, upstreamNode, downstreamNode) {
  return isInitializationJoinLink(upstreamNode, downstreamNode);
}

/** @deprecated 使用 isInitializationJoinLink */
export function isActiveJoinLink(link, upstreamNode, downstreamNode) {
  return isInitializationJoinLink(upstreamNode, downstreamNode);
}

/** 上层策略：纯 NAT 在后续手动拓扑里不可被 WG 拨入（与初始化 join 无关）。 */
export function isDialOutOnlyNode(node) {
  return node?.reachabilityType === 'nat';
}

/** 面板手动连接两个公网节点且两端 Endpoint 均已填写 → 底层双向 WG。 */
export function isManualBidirectionalPublicLink(upstreamNode, downstreamNode, upstreamEndpoint, downstreamEndpoint) {
  if (!normalizeEndpoint(upstreamEndpoint) || !normalizeEndpoint(downstreamEndpoint)) return false;
  if (isInitializationJoinLink(upstreamNode, downstreamNode)) return false;
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

  if (isInitializationJoinLink(upstreamNode, downstreamNode)) {
    downstreamEndpoint = null;
    upstreamEndpoint = resolveInitializationJoinUpstreamEndpoint(link, upstreamNode);
  }
  if (isDialOutOnlyNode(downstreamNode) && !isInitializationJoinLink(upstreamNode, downstreamNode)) {
    downstreamEndpoint = null;
  }
  if (isDialOutOnlyNode(upstreamNode) && !isInitializationJoinLink(upstreamNode, downstreamNode)) {
    upstreamEndpoint = null;
  }

  return { upstreamEndpoint, downstreamEndpoint };
}

export function remoteEndpointForSource(link, sourceId, upstreamNode, downstreamNode) {
  const resolved = resolveLinkEndpoints(link, upstreamNode, downstreamNode);
  return link.upstreamId === sourceId ? resolved.downstreamEndpoint : resolved.upstreamEndpoint;
}

/** 底层 WG 拨号方向；控制面 ping/延迟沿同一方向，目标用 overlay 内网 IP。 */
export function selectLinkDialDirection(link, upstreamNode, downstreamNode) {
  if (isInitializationJoinLink(upstreamNode, downstreamNode)) {
    return { dialerId: downstreamNode.id, targetId: upstreamNode.id };
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
  if (canOverlay) {
    const { dialerId, targetId } = selectLinkDialDirection(link, upstreamNode, downstreamNode);
    return { requested: 1, probes: [probe(dialerId, targetId)] };
  }
  return { requested: 0, probes: [] };
}

export function validationProbeRequestedFlags(linkRow, upstreamNode = null, downstreamNode = null) {
  const downstreamEndpoint = linkRow.downstream_endpoint ?? linkRow.downstreamEndpoint;
  const upstreamEndpoint = linkRow.upstream_endpoint ?? linkRow.upstreamEndpoint;
  const upstreamProbe = Number(linkRow.validation_probed_upstream ?? linkRow.validationProbedUpstream ?? 0);
  const downstreamProbe = Number(linkRow.validation_probed_downstream ?? linkRow.validationProbedDownstream ?? 0);
  if (upstreamNode && downstreamNode) {
    if (isManualBidirectionalPublicLink(upstreamNode, downstreamNode, upstreamEndpoint, downstreamEndpoint)) {
      return { upstreamRequested: true, downstreamRequested: true };
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
