const state = {
  token: sessionStorage.getItem('pathweaver-token') || '',
  dashboard: null,
  networkId: localStorage.getItem('pathweaver-network') || '',
  topology: null,
  configurations: [],
  view: (location.hash.slice(1).split('?')[0] || 'overview'),
  topologyDraft: [],
  selectedNodeIds: [],
  pathDetail: null,
  selectedPathIds: [],
  pathWeights: {},
  graph: {
    networkId: null,
    signature: '',
    positions: new Map(),
    manualNodeIds: new Set(),
    viewport: { x: 0, y: 0, scale: 1 },
    drag: null,
  },
  joinResult: null,
  runtimeRefreshInFlight: false,
};

const content = document.querySelector('#content');
const networkSelect = document.querySelector('#network-select');
const titles = {
  overview: ['NETWORK OVERVIEW', '网络总览'],
  nodes: ['NODE ADDRESSING', '节点与地址'],
  topology: ['ROUTE CONSTRAINTS', '数据拓扑'],
  'path-detail': ['PATH POLICY', '路径详情'],
  join: ['EDGE ENROLLMENT', '接入新节点'],
  rollouts: ['CONFIG ROLLOUTS', '配置发布'],
};

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

function formatDate(value) {
  if (!value) return '—';
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(value));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${state.token}`,
      ...(options.headers || {}),
    },
  });
  if (response.status === 204) return null;
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error || `HTTP ${response.status}`);
    error.details = result.details;
    error.status = response.status;
    throw error;
  }
  return result;
}

function toast(message, type = 'success') {
  const element = document.createElement('div');
  element.className = `toast ${type}`;
  element.textContent = message;
  document.querySelector('#toast-region').append(element);
  setTimeout(() => element.remove(), 3600);
}

async function load() {
  state.dashboard = await api('/api/v1/dashboard');
  const networks = state.dashboard.networks;
  if (!networks.some((network) => network.id === state.networkId)) state.networkId = networks[0]?.id || '';
  localStorage.setItem('pathweaver-network', state.networkId);
  networkSelect.innerHTML = networks.map((network) => `<option value="${network.id}">${escapeHtml(network.name)}</option>`).join('');
  networkSelect.value = state.networkId;
  if (state.networkId) {
    const [topology, configurations] = await Promise.all([
      api(`/api/v1/networks/${state.networkId}/topology`),
      api(`/api/v1/networks/${state.networkId}/configurations`),
    ]);
    state.topology = topology;
    state.topologyDraft = structuredClone(topology.links);
    state.selectedNodeIds = state.selectedNodeIds.filter((id) => topology.nodes.some((node) => node.id === id));
    state.configurations = configurations.configurations;
    if (state.view === 'path-detail') {
      const route = pathDetailRoute();
      if (route.sourceId && route.targetId) await loadPathDetail(route.sourceId, route.targetId, true);
    }
  }
  render();
}

function currentNetwork() {
  return state.dashboard?.networks.find((network) => network.id === state.networkId);
}

function render() {
  const [eyebrow, title] = titles[state.view] || titles.overview;
  document.querySelector('#view-eyebrow').textContent = eyebrow;
  document.querySelector('#view-title').textContent = title;
  document.querySelectorAll('[data-nav]').forEach((link) => {
    const activeView = state.view === 'path-detail' ? 'topology' : state.view;
    link.classList.toggle('active', link.dataset.nav === activeView);
  });
  const renderers = {
    overview: renderOverview,
    nodes: renderNodes,
    topology: renderTopology,
    'path-detail': renderPathDetail,
    join: renderJoin,
    rollouts: renderRollouts,
  };
  content.innerHTML = (renderers[state.view] || renderOverview)();
  bindViewEvents();
}

function renderOverview() {
  const totals = state.dashboard.totals;
  const network = currentNetwork();
  const nodes = state.topology?.nodes || [];
  const validation = state.topology?.validation;
  return `
    <div class="metric-grid">
      <article class="metric"><label>节点总数</label><strong>${nodes.length}</strong><small>${nodes.filter((node) => node.status === 'online').length} 台在线</small></article>
      <article class="metric"><label>数据连接</label><strong>${state.topology?.links.length || 0}</strong><small>仅允许声明的 WireGuard 邻接</small></article>
      <article class="metric"><label>业务网段</label><strong class="mono" style="font-size:22px">${escapeHtml(network?.dataCidr || '—')}</strong><small>地址可逐节点手动分配</small></article>
      <article class="metric"><label>全网可达</label><strong class="good">${validation?.fullyReachable ? 'YES' : 'NO'}</strong><small>${validation?.fullyReachable ? '拓扑校验已通过' : escapeHtml(validation?.error || '等待校验')}</small></article>
    </div>
    <div class="split">
      <article class="card">
        <div class="card-head"><div><h2>节点状态</h2><p>控制地址保持稳定，业务地址可版本化变更</p></div><a class="button ghost small" href="#nodes">管理地址</a></div>
        ${nodeTable(nodes.slice(0, 6), false)}
      </article>
      <article class="card">
        <div class="card-head"><div><h2>控制面</h2><p>中心服务与发布队列</p></div><span class="status online">正常</span></div>
        <div class="card-body section-stack">
          <div class="notice"><strong>双平面隔离</strong><span>数据拓扑变更通过首次接入控制树传递，不会因为业务 IP 切换失去管理连接。</span></div>
          <div class="metric" style="min-height:108px"><label>待推进配置</label><strong>${totals.preparing}</strong><small>${totals.pendingCommands} 条节点命令等待完成</small></div>
        </div>
      </article>
    </div>`;
}

function nodeTable(nodes, editable = true) {
  if (!nodes.length) return '<div class="empty"><strong>尚无节点</strong>从接入页面生成第一条安装命令。</div>';
  return `<div class="node-list">
    <div class="node-row header"><span>节点</span><span>业务 IP</span><span>控制 IP</span><span>状态</span><span></span></div>
    ${nodes.map((node) => `<div class="node-row">
      <span class="node-identity"><span class="node-glyph">${node.isCenter ? '◆' : '◇'}</span><span><strong>${escapeHtml(node.name)}</strong><small>${escapeHtml(node.id.slice(0, 12))}</small></span></span>
      <span class="mono">${escapeHtml(node.dataIp)}</span>
      <span class="mono">${escapeHtml(node.controlIp)}</span>
      <span class="status ${escapeHtml(node.status)}">${node.status === 'online' ? '在线' : escapeHtml(node.status)}</span>
      ${editable ? `<button class="button ghost small edit-node" data-id="${node.id}">编辑</button>` : '<span></span>'}
    </div>`).join('')}
  </div>`;
}

function renderNodes() {
  const network = currentNetwork();
  return `<div class="section-stack">
    <div class="notice"><strong>地址变更策略</strong><span>业务 IP 必须位于 ${escapeHtml(network?.dataCidr)}。保存前会检查冲突和全网路由；控制 IP 不随业务地址变化。</span></div>
    <article class="card"><div class="card-head"><div><h2>全部节点</h2><p>${state.topology.nodes.length} 台设备 · 点击编辑手动指定业务内网 IP</p></div></div>${nodeTable(state.topology.nodes)}</article>
  </div>`;
}

const graphWorld = { width: 1200, height: 700, nodeWidth: 160, nodeHeight: 80 };

function graphSignature(nodes, links) {
  return JSON.stringify({
    nodes: nodes.map((node) => node.id).sort(),
    links: links.map((link) => [link.upstreamId, link.downstreamId, link.validationStatus, link.priority]).sort(),
  });
}

function loadManualGraphPositions(networkId) {
  try {
    const saved = JSON.parse(localStorage.getItem(`pathweaver-graph-${networkId}`) || '{}');
    return new Map(Object.entries(saved).map(([id, position]) => [id, {
      x: Number(position.x),
      y: Number(position.y),
    }]));
  } catch {
    return new Map();
  }
}

function saveManualGraphPositions() {
  if (!state.graph.networkId) return;
  const saved = {};
  for (const nodeId of state.graph.manualNodeIds) {
    const position = state.graph.positions.get(nodeId);
    if (position) saved[nodeId] = { x: Math.round(position.x), y: Math.round(position.y) };
  }
  localStorage.setItem(`pathweaver-graph-${state.graph.networkId}`, JSON.stringify(saved));
}

function ensureGraphLayout(nodes, links) {
  const signature = graphSignature(nodes, links);
  if (state.graph.networkId !== state.networkId) {
    const manual = loadManualGraphPositions(state.networkId);
    state.graph.networkId = state.networkId;
    state.graph.signature = '';
    state.graph.positions = manual;
    state.graph.manualNodeIds = new Set(manual.keys());
    state.graph.viewport = { x: 0, y: 0, scale: 1 };
  }
  if (state.graph.signature === signature) return state.graph;

  const positions = new Map();
  const velocities = new Map();
  const centerX = graphWorld.width / 2 - graphWorld.nodeWidth / 2;
  const centerY = graphWorld.height / 2 - graphWorld.nodeHeight / 2;
  const radius = Math.min(260, 95 + nodes.length * 22);
  const sortedNodes = [...nodes].sort((nodeA, nodeB) =>
    Number(nodeB.isCenter) - Number(nodeA.isCenter) || nodeA.id.localeCompare(nodeB.id));
  sortedNodes.forEach((node, index) => {
    const previous = state.graph.positions.get(node.id);
    const angle = (Math.PI * 2 * index) / Math.max(1, sortedNodes.length) - Math.PI / 2;
    positions.set(node.id, previous ?? {
      x: node.isCenter ? centerX : centerX + Math.cos(angle) * radius,
      y: node.isCenter ? centerY : centerY + Math.sin(angle) * radius,
    });
    velocities.set(node.id, { x: 0, y: 0 });
  });

  const layoutLinks = links.filter((link) => link.validationStatus !== 'failed');
  for (let iteration = 0; iteration < 260; iteration += 1) {
    const forces = new Map(nodes.map((node) => [node.id, { x: 0, y: 0 }]));
    for (let indexA = 0; indexA < nodes.length; indexA += 1) {
      for (let indexB = indexA + 1; indexB < nodes.length; indexB += 1) {
        const nodeA = nodes[indexA];
        const nodeB = nodes[indexB];
        const positionA = positions.get(nodeA.id);
        const positionB = positions.get(nodeB.id);
        let dx = positionB.x - positionA.x;
        let dy = positionB.y - positionA.y;
        const distanceSquared = Math.max(900, dx * dx + dy * dy);
        const distance = Math.sqrt(distanceSquared);
        if (distance < 1) { dx = 1; dy = 0; }
        const repulsion = 76_000 / distanceSquared;
        const forceX = (dx / distance) * repulsion;
        const forceY = (dy / distance) * repulsion;
        forces.get(nodeA.id).x -= forceX;
        forces.get(nodeA.id).y -= forceY;
        forces.get(nodeB.id).x += forceX;
        forces.get(nodeB.id).y += forceY;
      }
    }
    for (const link of layoutLinks) {
      const from = positions.get(link.upstreamId);
      const to = positions.get(link.downstreamId);
      if (!from || !to) continue;
      const dx = to.x - from.x;
      const dy = to.y - from.y;
      const distance = Math.max(1, Math.hypot(dx, dy));
      const target = link.validationStatus === 'active' ? 205 : 245;
      const spring = (distance - target) * .0055;
      const forceX = (dx / distance) * spring;
      const forceY = (dy / distance) * spring;
      forces.get(link.upstreamId).x += forceX;
      forces.get(link.upstreamId).y += forceY;
      forces.get(link.downstreamId).x -= forceX;
      forces.get(link.downstreamId).y -= forceY;
    }
    for (const node of nodes) {
      if (state.graph.manualNodeIds.has(node.id)) continue;
      const position = positions.get(node.id);
      const velocity = velocities.get(node.id);
      const force = forces.get(node.id);
      force.x += (centerX - position.x) * .0009;
      force.y += (centerY - position.y) * .0009;
      velocity.x = (velocity.x + force.x) * .82;
      velocity.y = (velocity.y + force.y) * .82;
      position.x = Math.max(24, Math.min(graphWorld.width - graphWorld.nodeWidth - 24, position.x + velocity.x));
      position.y = Math.max(24, Math.min(graphWorld.height - graphWorld.nodeHeight - 24, position.y + velocity.y));
    }
  }
  state.graph.positions = positions;
  state.graph.signature = signature;
  return state.graph;
}

function graphPath(from, to) {
  const fromCenter = { x: from.x + graphWorld.nodeWidth / 2, y: from.y + graphWorld.nodeHeight / 2 };
  const toCenter = { x: to.x + graphWorld.nodeWidth / 2, y: to.y + graphWorld.nodeHeight / 2 };
  const dx = toCenter.x - fromCenter.x;
  const dy = toCenter.y - fromCenter.y;
  const length = Math.max(1, Math.hypot(dx, dy));
  const unitX = dx / length;
  const unitY = dy / length;
  const edgePadding = 58;
  const startX = fromCenter.x + unitX * edgePadding;
  const startY = fromCenter.y + unitY * edgePadding;
  const endX = toCenter.x - unitX * edgePadding;
  const endY = toCenter.y - unitY * edgePadding;
  const bend = Math.min(28, length * .08);
  const controlX = (startX + endX) / 2 - unitY * bend;
  const controlY = (startY + endY) / 2 + unitX * bend;
  return {
    d: `M ${startX} ${startY} Q ${controlX} ${controlY}, ${endX} ${endY}`,
    labelX: controlX,
    labelY: controlY - 8,
  };
}

function linkStatusText(link) {
  if (link.validationStatus === 'preparing') return `等待 Agent ${link.validationProgress?.prepared || 0}/2`;
  if (link.validationStatus === 'probing') return `双向探测 ${link.validationProgress?.probed || 0}/2`;
  if (link.validationStatus === 'failed') return link.validationError?.includes('超时') ? '验证超时' : '验证失败';
  return '';
}

function renderTopologyGraph() {
  const nodes = state.topology.nodes;
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const layout = ensureGraphLayout(nodes, state.topology.links);
  const edges = state.topology.links.map((link) => {
    const from = layout.positions.get(link.upstreamId);
    const to = layout.positions.get(link.downstreamId);
    if (!from || !to) return '';
    const path = graphPath(from, to);
    const status = link.validationStatus || 'active';
    const label = linkStatusText(link);
    return `<path class="graph-edge ${escapeHtml(status)}" data-link-id="${link.id}" data-from="${link.upstreamId}" data-to="${link.downstreamId}" d="${path.d}"></path>${label ? `<text class="graph-edge-label" data-link-label="${link.id}" data-from="${link.upstreamId}" data-to="${link.downstreamId}" x="${path.labelX}" y="${path.labelY}">${escapeHtml(label)}</text>` : ''}`;
  }).join('');
  const nodeMarkup = nodes.map((node, index) => {
    const position = layout.positions.get(node.id);
    const selected = state.selectedNodeIds.includes(node.id);
    const parent = node.parentId ? nodeById.get(node.parentId) : null;
    const offline = !node.isCenter && node.status !== 'online';
    const routeMeta = parent ? `初始上游 · ${escapeHtml(parent.name)}` : '控制根节点';
    return `<foreignObject data-node-container="${node.id}" x="${position.x}" y="${position.y}" width="${graphWorld.nodeWidth}" height="${graphWorld.nodeHeight}"><button class="graph-node svg-node ${node.isCenter ? 'center' : ''} ${offline ? 'offline' : ''}" data-node-id="${node.id}" aria-pressed="${selected}">
      <span class="graph-node-head"><strong>${escapeHtml(node.name)}</strong><span class="graph-node-index">${String(index + 1).padStart(2, '0')}</span></span>
      <span class="graph-node-address">${escapeHtml(node.dataIp)}</span>
      <span class="graph-node-meta">${offline ? 'Agent 离线 · ' : ''}${routeMeta}</span>
    </button></foreignObject>`;
  }).join('');
  const viewport = layout.viewport;
  return `<div class="graph-surface" id="topology-graph"><div class="graph-gesture-hint">Ctrl + 滚轮缩放 · 拖动画布平移 · 拖动节点调整位置</div><svg class="topology-svg" viewBox="0 0 ${graphWorld.width} ${graphWorld.height}" role="img" aria-label="可缩放、可拖动的节点数据连接拓扑"><g id="graph-world" transform="translate(${viewport.x} ${viewport.y}) scale(${viewport.scale})">${edges}${nodeMarkup}</g></svg></div>`;
}

function renderTopology() {
  const valid = state.topology.validation?.fullyReachable;
  const selected = state.selectedNodeIds.map((id) => state.topology.nodes.find((node) => node.id === id)).filter(Boolean);
  const waiting = state.topology.links.filter((link) => link.validationStatus === 'preparing').length;
  const probing = state.topology.links.filter((link) => link.validationStatus === 'probing').length;
  const validationText = [
    waiting ? `${waiting} 条等待 Agent` : '',
    probing ? `${probing} 条正在双向探测` : '',
  ].filter(Boolean).join(' · ') || '可建立直连或查看端到端路径';
  const selectionText = selected.length === 0
    ? '点击画布中的两个节点'
    : selected.length === 1
      ? `已选择 ${selected[0].name}，再选一个节点`
      : `${selected[0].name} ↔ ${selected[1].name}`;
  return `<article class="card">
    <div class="card-head"><div><h2>可视化拓扑编辑</h2><p>布局随连接关系自动收敛；拖动节点后会固定该节点的位置</p></div><span class="status ${valid ? 'active' : 'failed'}">${valid ? '全网可达' : '需要修复'}</span></div>
    <div class="graph-toolbar">
      <div class="graph-toolbar-main"><span class="selection-count">${selected.length}/2</span><span class="selection-copy"><strong>${escapeHtml(selectionText)}</strong><small>${validationText}</small></span></div>
      <div class="graph-actions"><button class="button ghost" id="clear-node-selection" ${selected.length ? '' : 'disabled'}>取消选择</button><button class="button ghost" id="connect-selected" ${selected.length === 2 ? '' : 'disabled'}>建立连接</button><button class="button primary" id="detail-selected" ${selected.length === 2 ? '' : 'disabled'}>详细配置</button></div>
    </div>
    ${renderTopologyGraph()}
    <div class="graph-legend"><span>已验证通路</span><span class="waiting">等待 Agent</span><span class="probing">正在双向探测</span><span class="failed">验证失败或超时</span><span style="margin-left:auto">点击节点进行选择</span></div>
  </article>`;
}

function pathDetailRoute() {
  const query = location.hash.includes('?') ? location.hash.slice(location.hash.indexOf('?') + 1) : '';
  const params = new URLSearchParams(query);
  return { sourceId: params.get('source'), targetId: params.get('target') };
}

async function loadPathDetail(sourceId, targetId, resetSelection = false) {
  const pairChanged = state.pathDetail?.source?.id !== sourceId || state.pathDetail?.target?.id !== targetId;
  state.pathDetail = await api(
    `/api/v1/networks/${state.networkId}/path-options?sourceId=${encodeURIComponent(sourceId)}&targetId=${encodeURIComponent(targetId)}`,
  );
  if (resetSelection || pairChanged) {
    state.selectedPathIds = (state.pathDetail.policy?.paths ?? []).map((path) => path.pathId);
    state.pathWeights = Object.fromEntries(
      (state.pathDetail.policy?.paths ?? []).map((path) => [path.pathId, Number(path.weight)]),
    );
  }
}

function openPathDetail() {
  if (state.selectedNodeIds.length !== 2) return;
  const [sourceId, targetId] = state.selectedNodeIds;
  location.hash = `path-detail?source=${encodeURIComponent(sourceId)}&target=${encodeURIComponent(targetId)}`;
}

function renderPathDetail() {
  const details = state.pathDetail;
  if (!details) return '<div class="loading-card"><span class="spinner"></span>正在计算无环路径…</div>';
  const selectedIds = new Set(state.selectedPathIds);
  const selectedPaths = details.paths.filter((path) => selectedIds.has(path.id));
  const totalWeight = selectedPaths.reduce((total, path) => total + Number(state.pathWeights[path.id] || 1), 0);
  const lanes = details.paths.length ? details.paths.map((path, index) => {
    const selected = selectedIds.has(path.id);
    const chain = path.nodes.map((node, nodeIndex) => `${nodeIndex ? '<span class="path-segment" aria-hidden="true"></span>' : ''}<span class="path-chain-node ${node.status === 'online' ? '' : 'offline'}"><strong>${escapeHtml(node.name)}</strong><small>${escapeHtml(node.dataIp)}</small></span>`).join('');
    return `<label class="path-lane ${selected ? 'selected' : ''}">
      <input class="path-option" type="checkbox" value="${path.id}" ${selected ? 'checked' : ''}>
      <span class="path-lane-index">P${String(index + 1).padStart(2, '0')}</span>
      <span class="path-chain">${chain}</span>
      <span class="path-lane-meta"><strong>${path.hops} 跳</strong><small>成本 ${path.totalCost}</small></span>
    </label>`;
  }).join('') : '<div class="empty"><strong>没有可用路径</strong>当前两个节点之间不存在由已验证连接组成的无环路径。</div>';
  const weights = selectedPaths.map((path, index) => {
    const weight = Number(state.pathWeights[path.id] || 1);
    const share = totalWeight ? Math.round((weight / totalWeight) * 1000) / 10 : 0;
    return `<label class="path-weight-row"><span>P${String(details.paths.indexOf(path) + 1).padStart(2, '0')}</span><input class="path-weight" data-path-id="${path.id}" type="number" min="1" max="1000" value="${weight}"><strong data-weight-share="${path.id}">${share}%</strong></label>`;
  }).join('');
  return `<article class="card path-detail-card">
    <div class="card-head"><div><p class="eyebrow">END-TO-END PATHS</p><h2>${escapeHtml(details.source.name)} ↔ ${escapeHtml(details.target.name)}</h2><p>${details.paths.length} 条无环路径${details.truncated ? ' · 仅显示优先级最高的一部分' : ''}；同一节点可在不同路径中重复出现</p></div><a class="button ghost" href="#topology">返回主拓扑</a></div>
    <div class="path-endpoints"><span><strong>${escapeHtml(details.source.name)}</strong><small>${escapeHtml(details.source.dataIp)}</small></span><span>${details.paths.length} 条路径</span><span><strong>${escapeHtml(details.target.name)}</strong><small>${escapeHtml(details.target.dataIp)}</small></span></div>
    <div class="path-lanes">${lanes}</div>
    <div class="path-policy-editor">
      <div><strong>负载均衡</strong><small>选择至少两条路径；权重越大，分配到该路径的连接越多。</small></div>
      <div class="path-weight-list">${weights || '<span class="muted">尚未选择路径</span>'}</div>
      <div class="path-policy-actions"><button class="button ghost" id="equalize-paths" ${selectedPaths.length ? '' : 'disabled'}>设为等权</button>${details.policy ? '<button class="button danger" id="disable-path-policy">关闭负载均衡</button>' : ''}<button class="button primary" id="save-path-policy" ${selectedPaths.length >= 2 ? '' : 'disabled'}>保存负载均衡</button></div>
    </div>
  </article>`;
}

function svgPoint(event, svg) {
  const point = svg.createSVGPoint();
  point.x = event.clientX;
  point.y = event.clientY;
  const matrix = svg.getScreenCTM();
  return matrix ? point.matrixTransform(matrix.inverse()) : { x: event.clientX, y: event.clientY };
}

function graphWorldPoint(event, svg) {
  const point = svgPoint(event, svg);
  const viewport = state.graph.viewport;
  return { x: (point.x - viewport.x) / viewport.scale, y: (point.y - viewport.y) / viewport.scale };
}

function applyGraphViewport() {
  const world = document.querySelector('#graph-world');
  if (!world) return;
  const viewport = state.graph.viewport;
  world.setAttribute('transform', `translate(${viewport.x} ${viewport.y}) scale(${viewport.scale})`);
}

function updateGraphGeometry() {
  for (const [nodeId, position] of state.graph.positions.entries()) {
    const container = document.querySelector(`[data-node-container="${CSS.escape(nodeId)}"]`);
    if (!container) continue;
    container.setAttribute('x', position.x);
    container.setAttribute('y', position.y);
  }
  document.querySelectorAll('[data-link-id]').forEach((edge) => {
    const path = graphPath(state.graph.positions.get(edge.dataset.from), state.graph.positions.get(edge.dataset.to));
    edge.setAttribute('d', path.d);
    const label = document.querySelector(`[data-link-label="${CSS.escape(edge.dataset.linkId)}"]`);
    if (label) {
      label.setAttribute('x', path.labelX);
      label.setAttribute('y', path.labelY);
    }
  });
}

function toggleGraphNode(nodeId) {
  if (state.selectedNodeIds.includes(nodeId)) state.selectedNodeIds = state.selectedNodeIds.filter((id) => id !== nodeId);
  else if (state.selectedNodeIds.length < 2) state.selectedNodeIds = [...state.selectedNodeIds, nodeId];
  else state.selectedNodeIds = [state.selectedNodeIds[1], nodeId];
  render();
}

function bindGraphInteractions() {
  const svg = document.querySelector('.topology-svg');
  const surface = document.querySelector('#topology-graph');
  if (!svg || !surface) return;

  svg.addEventListener('wheel', (event) => {
    if (!event.ctrlKey) return;
    event.preventDefault();
    const point = svgPoint(event, svg);
    const viewport = state.graph.viewport;
    const worldX = (point.x - viewport.x) / viewport.scale;
    const worldY = (point.y - viewport.y) / viewport.scale;
    const nextScale = Math.max(.45, Math.min(2.6, viewport.scale * Math.exp(-event.deltaY * .002)));
    viewport.x = point.x - worldX * nextScale;
    viewport.y = point.y - worldY * nextScale;
    viewport.scale = nextScale;
    applyGraphViewport();
  }, { passive: false });

  svg.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    const nodeButton = event.target.closest?.('.graph-node');
    const rootPoint = svgPoint(event, svg);
    if (nodeButton) {
      const nodeId = nodeButton.dataset.nodeId;
      const startPosition = state.graph.positions.get(nodeId);
      state.graph.drag = {
        type: 'node', nodeId, pointerId: event.pointerId,
        startPoint: graphWorldPoint(event, svg),
        startPosition: { ...startPosition }, moved: false,
      };
    } else {
      state.graph.drag = {
        type: 'pan', pointerId: event.pointerId, startPoint: rootPoint,
        startViewport: { ...state.graph.viewport }, moved: false,
      };
      surface.classList.add('dragging');
    }
    svg.setPointerCapture(event.pointerId);
    event.preventDefault();
  });

  svg.addEventListener('pointermove', (event) => {
    const drag = state.graph.drag;
    if (!drag || drag.pointerId !== event.pointerId) return;
    if (drag.type === 'node') {
      const point = graphWorldPoint(event, svg);
      const deltaX = point.x - drag.startPoint.x;
      const deltaY = point.y - drag.startPoint.y;
      drag.moved ||= Math.hypot(deltaX, deltaY) > 3;
      if (!drag.moved) return;
      state.graph.positions.set(drag.nodeId, {
        x: Math.max(0, Math.min(graphWorld.width - graphWorld.nodeWidth, drag.startPosition.x + deltaX)),
        y: Math.max(0, Math.min(graphWorld.height - graphWorld.nodeHeight, drag.startPosition.y + deltaY)),
      });
      state.graph.manualNodeIds.add(drag.nodeId);
      updateGraphGeometry();
    } else {
      const point = svgPoint(event, svg);
      const deltaX = point.x - drag.startPoint.x;
      const deltaY = point.y - drag.startPoint.y;
      drag.moved ||= Math.hypot(deltaX, deltaY) > 3;
      state.graph.viewport.x = drag.startViewport.x + deltaX;
      state.graph.viewport.y = drag.startViewport.y + deltaY;
      applyGraphViewport();
    }
  });

  const finishDrag = (event) => {
    const drag = state.graph.drag;
    if (!drag || drag.pointerId !== event.pointerId) return;
    if (svg.hasPointerCapture(event.pointerId)) svg.releasePointerCapture(event.pointerId);
    surface.classList.remove('dragging');
    state.graph.drag = null;
    if (drag.type === 'node') {
      if (drag.moved) saveManualGraphPositions();
      else if (event.type !== 'pointercancel') toggleGraphNode(drag.nodeId);
    }
  };
  svg.addEventListener('pointerup', finishDrag);
  svg.addEventListener('pointercancel', finishDrag);
  document.querySelectorAll('.graph-node').forEach((button) => button.addEventListener('click', (event) => {
    event.preventDefault();
    if (event.detail === 0) toggleGraphNode(button.dataset.nodeId);
  }));
}

async function savePathPolicy() {
  if (!state.pathDetail || state.selectedPathIds.length < 2) return;
  try {
    const result = await api(`/api/v1/networks/${state.networkId}/path-policies`, {
      method: 'PUT',
      body: JSON.stringify({
        sourceId: state.pathDetail.source.id,
        targetId: state.pathDetail.target.id,
        paths: state.selectedPathIds.map((pathId) => ({ pathId, weight: Number(state.pathWeights[pathId] || 1) })),
      }),
    });
    state.pathDetail = result.details;
    state.selectedPathIds = result.details.policy.paths.map((path) => path.pathId);
    state.pathWeights = Object.fromEntries(result.details.policy.paths.map((path) => [path.pathId, path.weight]));
    render();
    toast('负载均衡策略已保存并生成新的配置版本');
  } catch (error) { toast(error.message, 'error'); }
}

async function disablePathPolicy() {
  if (!state.pathDetail?.policy) return;
  try {
    const result = await api(
      `/api/v1/networks/${state.networkId}/path-policies?sourceId=${encodeURIComponent(state.pathDetail.source.id)}&targetId=${encodeURIComponent(state.pathDetail.target.id)}`,
      { method: 'DELETE' },
    );
    state.pathDetail = result.details;
    state.selectedPathIds = [];
    state.pathWeights = {};
    render();
    toast('负载均衡策略已关闭');
  } catch (error) { toast(error.message, 'error'); }
}

function renderJoin() {
  const nodes = state.topology.nodes.filter((node) => node.canRelay);
  const result = state.joinResult;
  return `<div class="join-layout">
    <article class="card"><div class="card-head"><div><h2>生成安装命令</h2><p>选择新设备实际能够访问的接入节点</p></div></div>
      <form class="card-body form-stack" id="join-form">
        <div class="segmented"><label><input type="radio" name="mode" value="active" ${!result || result.mode === 'active' ? 'checked' : ''}><span>设备主动加入</span></label><label><input type="radio" name="mode" value="passive" ${result?.mode === 'passive' ? 'checked' : ''}><span>已有节点主动认领</span></label></div>
        <label>控制父节点<select name="parentId">${nodes.map((node) => `<option value="${node.id}" data-endpoint="${escapeHtml(node.controlEndpoint || '')}">${escapeHtml(node.name)} · ${escapeHtml(node.controlIp)}</option>`).join('')}</select></label>
        <label>安装包与接入地址<input name="sourceUrl" placeholder="https://中心域名 或 http://边缘IP:8790"></label>
        <label>令牌有效时间（分钟）<input name="ttlMinutes" type="number" min="5" max="1440" value="30"></label>
        <button class="button primary" type="submit">生成一次性命令</button>
      </form>
    </article>
    <article class="card"><div class="card-head"><div><h2>可复制命令</h2><p>令牌仅显示一次，默认使用后立即失效</p></div>${result ? '<button class="button ghost small" id="copy-command">复制命令</button>' : ''}</div>
      <div class="card-body section-stack">
        <div class="command-box">${result ? `<code>${escapeHtml(result.command)}</code><div class="command-meta"><span>入口：${escapeHtml(result.parent.name)}</span><span>有效至 ${formatDate(result.expiresAt)}</span></div>` : '<div class="empty"><strong>等待生成</strong>命令将绑定节点组、父节点和短时效认证令牌。</div>'}</div>
        <div class="notice"><strong>${result?.mode === 'passive' ? '被动认领' : '传递式安装'}</strong><span>${result?.mode === 'passive' ? '目标 Agent 只监听认领请求；随后在面板命令指定的已入网节点主动连接它。' : '边缘入口可以缓存并转发同一份中心签名制品，新节点注册身份仍由中心验证。'}</span></div>
        ${result?.mode === 'passive' ? `<form id="adopt-form" class="form-stack">
          <label>待认领 Agent 地址<input name="targetUrl" required placeholder="http://目标服务器IP:8790"></label>
          <button class="button primary" type="submit">命令 ${escapeHtml(result.parent.name)} 主动连接</button>
          <p class="muted" style="margin:0">认领指令会沿控制树送到 ${escapeHtml(result.parent.name)}，由它连接目标并成为控制父节点。</p>
        </form>` : ''}
      </div>
    </article>
  </div>`;
}

function renderRollouts() {
  return `<article class="card"><div class="card-head"><div><h2>配置版本</h2><p>IP 和拓扑变更均通过准备、激活两个阶段发布</p></div></div>
    <div class="timeline">${state.configurations.length ? state.configurations.map((version) => `<div class="rollout"><span class="version">v${version.version}</span><span><strong>${escapeHtml(version.reason)}</strong><small style="display:block;color:var(--subtle);margin-top:4px">${escapeHtml(version.id.slice(0, 12))}</small></span><span class="status ${escapeHtml(version.status)}">${escapeHtml(version.status)}</span><span>${formatDate(version.activatedAt || version.createdAt)}</span></div>`).join('') : '<div class="empty">暂无配置版本</div>'}</div>
  </article>`;
}

function bindViewEvents() {
  document.querySelectorAll('.edit-node').forEach((button) => button.addEventListener('click', () => openNode(button.dataset.id)));
  bindGraphInteractions();
  document.querySelector('#clear-node-selection')?.addEventListener('click', () => { state.selectedNodeIds = []; render(); });
  document.querySelector('#connect-selected')?.addEventListener('click', openConnectionDialog);
  document.querySelector('#detail-selected')?.addEventListener('click', openPathDetail);
  document.querySelectorAll('.path-option').forEach((checkbox) => checkbox.addEventListener('change', () => {
    if (checkbox.checked) {
      state.selectedPathIds = [...new Set([...state.selectedPathIds, checkbox.value])];
      state.pathWeights[checkbox.value] = Number(state.pathWeights[checkbox.value] || 1);
    } else {
      state.selectedPathIds = state.selectedPathIds.filter((pathId) => pathId !== checkbox.value);
      delete state.pathWeights[checkbox.value];
    }
    render();
  }));
  document.querySelectorAll('.path-weight').forEach((input) => input.addEventListener('input', () => {
    state.pathWeights[input.dataset.pathId] = Math.max(1, Math.min(1000, Number(input.value) || 1));
    const total = state.selectedPathIds.reduce((sum, pathId) => sum + Number(state.pathWeights[pathId] || 1), 0);
    for (const pathId of state.selectedPathIds) {
      const share = document.querySelector(`[data-weight-share="${CSS.escape(pathId)}"]`);
      if (share) share.textContent = `${Math.round((Number(state.pathWeights[pathId] || 1) / total) * 1000) / 10}%`;
    }
  }));
  document.querySelector('#equalize-paths')?.addEventListener('click', () => {
    for (const pathId of state.selectedPathIds) state.pathWeights[pathId] = 1;
    render();
  });
  document.querySelector('#save-path-policy')?.addEventListener('click', savePathPolicy);
  document.querySelector('#disable-path-policy')?.addEventListener('click', disablePathPolicy);
  document.querySelector('#join-form')?.addEventListener('submit', createJoinToken);
  document.querySelector('#adopt-form')?.addEventListener('submit', enqueueAdoption);
  const parentSelect = document.querySelector('#join-form select[name="parentId"]');
  parentSelect?.addEventListener('change', () => {
    const sourceInput = document.querySelector('#join-form input[name="sourceUrl"]');
    sourceInput.value = parentSelect.selectedOptions[0]?.dataset.endpoint || '';
    sourceInput.placeholder = sourceInput.value ? sourceInput.placeholder : '必填：新设备可访问的边缘 IP 或域名';
  });
  document.querySelector('#copy-command')?.addEventListener('click', async () => {
    await navigator.clipboard.writeText(state.joinResult.command); toast('安装命令已复制');
  });
}

function reachableHost(node) {
  if (node.dataEndpoint) {
    if (node.dataEndpoint.startsWith('[')) return node.dataEndpoint.slice(0, node.dataEndpoint.indexOf(']') + 1);
    return node.dataEndpoint.slice(0, node.dataEndpoint.lastIndexOf(':'));
  }
  if (node.controlEndpoint) {
    try { return new URL(node.controlEndpoint).hostname; } catch {}
  }
  return '';
}

function openConnectionDialog() {
  if (state.selectedNodeIds.length !== 2) return;
  const [nodeA, nodeB] = state.selectedNodeIds.map((id) => state.topology.nodes.find((node) => node.id === id));
  const existing = state.topology.links.some((link) =>
    (link.upstreamId === nodeA.id && link.downstreamId === nodeB.id) ||
    (link.upstreamId === nodeB.id && link.downstreamId === nodeA.id));
  if (existing) return toast('这两个节点之间已经存在连接或正在验证', 'error');
  const form = document.querySelector('#connection-form');
  form.elements.nodeAId.value = nodeA.id;
  form.elements.nodeBId.value = nodeB.id;
  form.elements.nodeAAddress.value = reachableHost(nodeA);
  form.elements.nodeBAddress.value = reachableHost(nodeB);
  form.elements.priority.value = 10;
  document.querySelector('#connection-pair').innerHTML = `<strong>${escapeHtml(nodeA.name)}</strong><span>↔</span><strong>${escapeHtml(nodeB.name)}</strong>`;
  document.querySelector('#node-a-address-label').textContent = `${nodeA.name} 可被 ${nodeB.name} 访问的 IP 或域名`;
  document.querySelector('#node-b-address-label').textContent = `${nodeB.name} 可被 ${nodeA.name} 访问的 IP 或域名`;
  form.querySelector('[data-form-error]').textContent = '';
  document.querySelector('#connection-dialog').showModal();
}

function openNode(id) {
  const node = state.topology.nodes.find((item) => item.id === id);
  const form = document.querySelector('#node-form');
  form.elements.nodeId.value = node.id;
  form.elements.name.value = node.name;
  form.elements.dataIp.value = node.dataIp;
  form.elements.controlEndpoint.value = node.controlEndpoint || '';
  form.elements.dataEndpoint.value = node.dataEndpoint || '';
  form.elements.canRelay.checked = node.canRelay;
  form.querySelector('[data-form-error]').textContent = '';
  document.querySelector('#node-dialog').showModal();
}

async function saveTopology() {
  try {
    await api(`/api/v1/networks/${state.networkId}/topology`, { method: 'PUT', body: JSON.stringify({ links: state.topologyDraft }) });
    toast('拓扑校验通过，新的配置版本已进入准备阶段');
    await load();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function createJoinToken(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const parent = state.topology.nodes.find((node) => node.id === form.get('parentId'));
    const sourceUrl = String(form.get('sourceUrl') || parent?.controlEndpoint || '').trim();
    if (!sourceUrl) throw new Error('请选择或填写新设备能够访问的父节点中继地址');
    state.joinResult = await api(`/api/v1/networks/${state.networkId}/join-tokens`, {
      method: 'POST',
      body: JSON.stringify({
        mode: form.get('mode'), parentId: form.get('parentId'), sourceUrl, ttlMinutes: Number(form.get('ttlMinutes')),
      }),
    });
    render(); toast('一次性接入命令已生成');
  } catch (error) { toast(error.message, 'error'); }
}

async function enqueueAdoption(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const targetUrl = String(form.get('targetUrl') || '').trim();
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('目标地址只支持 HTTP 或 HTTPS');
    await api(`/api/v1/nodes/${state.joinResult.parent.id}/commands`, {
      method: 'POST',
      body: JSON.stringify({
        type: 'adopt-node',
        payload: {
          targetUrl: parsed.href.replace(/\/$/, ''),
          claimToken: state.joinResult.token,
          upstream: state.joinResult.sourceUrl,
        },
      }),
    });
    toast(`认领指令已发送给 ${state.joinResult.parent.name}`);
    event.currentTarget.querySelector('button').disabled = true;
  } catch (error) { toast(error.message, 'error'); }
}

async function authenticate(token) {
  state.token = token;
  await load();
  sessionStorage.setItem('pathweaver-token', token);
}

window.addEventListener('hashchange', async () => {
  state.view = location.hash.slice(1).split('?')[0] || 'overview';
  if (state.view === 'path-detail') {
    const route = pathDetailRoute();
    state.pathDetail = null;
    render();
    try {
      await loadPathDetail(route.sourceId, route.targetId, true);
    } catch (error) {
      toast(error.message, 'error');
      location.hash = 'topology';
      return;
    }
  }
  render();
});
document.querySelector('#refresh').addEventListener('click', () => load().then(() => toast('状态已刷新')).catch((error) => toast(error.message, 'error')));
document.querySelector('#lock-console').addEventListener('click', () => {
  sessionStorage.removeItem('pathweaver-token'); state.token = ''; document.querySelector('#login-dialog').showModal();
});
networkSelect.addEventListener('change', () => {
  state.networkId = networkSelect.value;
  state.joinResult = null;
  state.pathDetail = null;
  state.selectedNodeIds = [];
  state.graph.networkId = null;
  if (state.view === 'path-detail') location.hash = 'topology';
  load().catch((error) => toast(error.message, 'error'));
});
document.querySelector('#new-network').addEventListener('click', () => document.querySelector('#network-dialog').showModal());

document.querySelector('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = document.querySelector('#login-error'); error.textContent = '';
  try { await authenticate(document.querySelector('#admin-token').value); document.querySelector('#login-dialog').close(); }
  catch (reason) { error.textContent = reason.message; }
});

document.querySelector('#network-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (event.submitter?.value === 'cancel') return document.querySelector('#network-dialog').close();
  const form = new FormData(event.currentTarget);
  const error = event.currentTarget.querySelector('[data-form-error]');
  try {
    const network = await api('/api/v1/networks', { method: 'POST', body: JSON.stringify(Object.fromEntries(form)) });
    state.networkId = network.id; document.querySelector('#network-dialog').close(); await load(); toast('节点组已创建');
  } catch (reason) { error.textContent = reason.message; }
});

document.querySelector('#node-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (event.submitter?.value === 'cancel') return document.querySelector('#node-dialog').close();
  const form = new FormData(event.currentTarget);
  const error = event.currentTarget.querySelector('[data-form-error]');
  try {
    await api(`/api/v1/nodes/${form.get('nodeId')}`, {
      method: 'PATCH',
      body: JSON.stringify({
        name: form.get('name'), dataIp: form.get('dataIp'), controlEndpoint: form.get('controlEndpoint'),
        dataEndpoint: form.get('dataEndpoint'), canRelay: form.get('canRelay') === 'on',
      }),
    });
    document.querySelector('#node-dialog').close(); await load(); toast('节点地址已校验并生成新配置版本');
  } catch (reason) { error.textContent = reason.message; }
});

document.querySelector('#connection-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (event.submitter?.value === 'cancel') return document.querySelector('#connection-dialog').close();
  const form = new FormData(event.currentTarget);
  const error = event.currentTarget.querySelector('[data-form-error]');
  error.textContent = '';
  try {
    await api(`/api/v1/networks/${state.networkId}/links`, {
      method: 'POST',
      body: JSON.stringify({
        nodeAId: form.get('nodeAId'),
        nodeBId: form.get('nodeBId'),
        nodeAAddress: form.get('nodeAAddress'),
        nodeBAddress: form.get('nodeBAddress'),
        priority: Number(form.get('priority')),
      }),
    });
    document.querySelector('#connection-dialog').close();
    state.selectedNodeIds = [];
    await load();
    toast('逻辑校验通过，正在等待两个 Agent 完成双向探测');
  } catch (reason) { error.textContent = reason.message; }
});

setInterval(() => {
  document.querySelector('#clock').textContent = `${new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date())} CST`;
}, 1000);

setInterval(async () => {
  if (!state.token || state.view !== 'topology' || state.runtimeRefreshInFlight) return;
  if (state.selectedNodeIds.length || state.graph.drag || document.querySelector('dialog[open]')) return;
  state.runtimeRefreshInFlight = true;
  try { await load(); } catch {}
  finally { state.runtimeRefreshInFlight = false; }
}, 5000);

if (state.token) authenticate(state.token).catch(() => document.querySelector('#login-dialog').showModal());
else document.querySelector('#login-dialog').showModal();
