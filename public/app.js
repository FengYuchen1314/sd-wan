import { copyText } from './clipboard.js';

const state = {
  token: sessionStorage.getItem('pathweaver-token') || '',
  dashboard: null,
  panelStatus: null,
  networkId: localStorage.getItem('pathweaver-network') || '',
  topology: null,
  configurations: [],
  view: (location.hash.slice(1).split('?')[0] || 'overview'),
  topologyDraft: [],
  selectedNodeIds: [],
  pathDetail: null,
  selectedPathIds: [],
  pathWeights: {},
  pathMode: 'failover',
  defaultPathId: null,
  graph: {
    networkId: null,
    signature: '',
    positions: new Map(),
    manualNodeIds: new Set(),
    viewport: { x: 0, y: 0, scale: 1 },
    drag: null,
  },
  joinResult: null,
  joinMode: 'active',
  joinParentId: null,
  cidrPreview: null,
  runtimeRefreshInFlight: false,
};

const content = document.querySelector('#content');
const networkSelect = document.querySelector('#network-select');
const titles = {
  overview: ['NETWORK OVERVIEW', '网络总览'],
  nodes: ['NODE ADDRESSING', '节点与地址'],
  topology: ['ROUTE CONSTRAINTS', '数据拓扑'],
  'path-detail': ['PATH POLICY', '路径详情'],
  join: ['PEER ENROLLMENT', '接入新节点'],
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

const LATENCY_STALE_MS = 30 * 60 * 1000;

function formatLatency(value) {
  if (value == null || !Number.isFinite(Number(value))) return '—';
  const ms = Number(value);
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`;
}

function latencyQuality(ms) {
  if (ms == null || !Number.isFinite(Number(ms))) return 'unknown';
  if (ms <= 30) return 'excellent';
  if (ms <= 80) return 'good';
  if (ms <= 150) return 'fair';
  return 'poor';
}

function isLatencyStale(measuredAt) {
  if (!measuredAt) return true;
  return Date.now() - new Date(measuredAt).getTime() > LATENCY_STALE_MS;
}

function latencyAgeLabel(measuredAt) {
  if (!measuredAt) return '尚未探测';
  const minutes = Math.floor((Date.now() - new Date(measuredAt).getTime()) / 60_000);
  if (minutes < 1) return '刚刚';
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  return formatDate(measuredAt);
}

function latencyProbeLabel(benchmark) {
  if (!benchmark) return null;
  if (benchmark.status === 'preparing') return '准备探测';
  if (benchmark.status === 'testing') return '探测中';
  if (benchmark.status === 'failed') return '探测失败';
  return null;
}

function latencyDisplay(benchmark) {
  if (!benchmark || benchmark.status !== 'completed') return null;
  const avg = Number(benchmark.latencyMs);
  const min = Number(benchmark.latencyMinMs ?? avg);
  const p95 = Number(benchmark.latencyP95Ms ?? avg);
  if (!Number.isFinite(avg)) return null;
  if (Math.abs(p95 - min) < 0.5) return formatLatency(avg);
  const minText = min < 10 ? min.toFixed(1) : String(Math.round(min));
  const p95Text = p95 < 10 ? p95.toFixed(1) : String(Math.round(p95));
  return `${formatLatency(avg)} (${minText}–${p95Text} ms)`;
}

function pathLatencyStats(path, linkById) {
  const linkIds = path.linkIds || [];
  const segments = linkIds.map((linkId) => linkById.get(linkId)?.benchmark).filter((benchmark) => benchmark?.status === 'completed');
  if (!segments.length || segments.length !== linkIds.length) return null;
  const sum = (key) => Number(segments.reduce((total, benchmark) => total + Number(benchmark[key] ?? benchmark.latencyMs), 0).toFixed(2));
  return {
    typical: sum('latencyMs'),
    best: sum('latencyMinMs'),
    upper: sum('latencyP95Ms'),
    measuredAt: segments.map((benchmark) => benchmark.measuredAt).filter(Boolean).sort().at(-1) || null,
    segments,
  };
}

function pathLatencySummary(stats) {
  if (!stats) return null;
  if (Math.abs(stats.upper - stats.best) < 0.5) return formatLatency(stats.typical);
  const bestText = stats.best < 10 ? stats.best.toFixed(1) : String(Math.round(stats.best));
  const upperText = stats.upper < 10 ? stats.upper.toFixed(1) : String(Math.round(stats.upper));
  return `${formatLatency(stats.typical)} (${bestText}–${upperText} ms)`;
}

function summarizeLinkLatencies(links) {
  const active = links.filter((link) => link.validationStatus === 'active');
  const completed = active.filter((link) => link.benchmark?.status === 'completed');
  const running = active.filter((link) => latencyProbeLabel(link.benchmark));
  const failed = active.filter((link) => link.benchmark?.status === 'failed');
  const stale = completed.filter((link) => isLatencyStale(link.benchmark.measuredAt));
  const latencies = completed.map((link) => Number(link.benchmark.latencyMs)).filter(Number.isFinite);
  return {
    total: active.length,
    completed: completed.length,
    running: running.length,
    failed: failed.length,
    stale: stale.length,
    untested: active.length - completed.length - running.length - failed.length,
    average: latencies.length ? Number((latencies.reduce((sum, value) => sum + value, 0) / latencies.length).toFixed(1)) : null,
  };
}

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${state.token}`,
        ...(options.headers || {}),
      },
    });
  } catch (error) {
    throw new Error(error?.message === 'Failed to fetch'
      ? '无法连接本机面板或控制面（网络中断、协调节点不可写，或请求在快照同步时超时）。请刷新后重试'
      : (error?.message || '请求失败'));
  }
  if (response.status === 204) return null;
  const result = await response.json().catch(() => ({}));
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
  [state.dashboard, state.panelStatus] = await Promise.all([
    api('/api/v1/dashboard'),
    api('/api/v1/panel-status'),
  ]);
  const controlState = document.querySelector('.control-state');
  controlState?.classList.toggle('degraded', !state.panelStatus?.writable);
  if (controlState) {
    controlState.querySelector('strong').textContent = state.panelStatus?.writable ? '面板配置已同步' : '当前只读';
    controlState.querySelector('small').textContent = state.panelStatus?.writable ? '每个节点均可管理' : '等待协调多数派恢复';
  }
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
  const links = state.topology?.links || [];
  const latencySummary = summarizeLinkLatencies(links);
  return `
    <div class="metric-grid">
      <article class="metric"><label>节点总数</label><strong>${nodes.length}</strong><small>${nodes.filter((node) => node.status === 'online').length} 台在线</small></article>
      <article class="metric"><label>数据连接</label><strong>${links.length}</strong><small>${latencySummary.completed} 条已探测延迟</small></article>
      <article class="metric"><label>业务网段</label><strong class="mono metric-cidr">${escapeHtml(network?.dataCidr || '—')}</strong><small>地址可逐节点手动分配</small></article>
      <article class="metric"><label>全网可达</label><strong class="good">${validation?.fullyReachable ? 'YES' : 'NO'}</strong><small>${validation?.fullyReachable ? '拓扑校验已通过' : escapeHtml(validation?.error || '等待校验')}</small></article>
    </div>
    <div class="split">
      <article class="card">
        <div class="card-head"><div><h2>节点状态</h2><p>控制地址保持稳定，业务地址可版本化变更</p></div><a class="button ghost small" href="#nodes">管理地址</a></div>
        ${nodeTable(nodes.slice(0, 6), false)}
      </article>
      <article class="card">
        <div class="card-head"><div><h2>链路延迟概览</h2><p>10 次 RTT 采样，展示典型值与波动区间</p></div><a class="button ghost small" href="#topology">打开拓扑</a></div>
        <div class="card-body section-stack">
          ${renderLatencyOverview(latencySummary, links)}
          <div class="metric metric-compact"><label>待推进配置</label><strong>${totals.preparing}</strong><small>${totals.pendingCommands} 条节点命令等待完成</small></div>
        </div>
      </article>
    </div>`;
}

function renderLatencyOverview(summary, links) {
  if (!summary.total) {
    return '<div class="notice"><strong>尚无已验证链路</strong><span>建立并验证节点连接后，可在数据拓扑页发起延迟探测。</span></div>';
  }
  const parts = [
    `${summary.completed}/${summary.total} 已探测`,
    summary.running ? `${summary.running} 进行中` : '',
    summary.failed ? `${summary.failed} 失败` : '',
    summary.stale ? `${summary.stale} 结果过期` : '',
    summary.untested ? `${summary.untested} 未探测` : '',
  ].filter(Boolean).join(' · ');
  const average = summary.average == null ? '—' : formatLatency(summary.average);
  const recent = links
    .filter((link) => link.validationStatus === 'active' && link.benchmark?.status === 'completed')
    .sort((linkA, linkB) => new Date(linkB.benchmark.measuredAt) - new Date(linkA.benchmark.measuredAt))
    .slice(0, 4);
  const rows = recent.length ? recent.map((link) => {
    const upstream = state.topology.nodes.find((node) => node.id === link.upstreamId);
    const downstream = state.topology.nodes.find((node) => node.id === link.downstreamId);
    const label = `${upstream?.name || '—'} ↔ ${downstream?.name || '—'}`;
    const stale = isLatencyStale(link.benchmark.measuredAt);
    return `<div class="latency-overview-row ${stale ? 'stale' : ''}"><span>${escapeHtml(label)}</span><strong class="latency-${latencyQuality(link.benchmark.latencyMs)}">${escapeHtml(latencyDisplay(link.benchmark))}</strong><small>${escapeHtml(latencyAgeLabel(link.benchmark.measuredAt))}</small></div>`;
  }).join('') : '<div class="muted">尚未完成任何相邻链路探测。</div>';
  return `<div class="notice"><strong>相邻链路平均 ${average}</strong><span>${parts}。每条链路独立采样 10 次 RTT（含 2 次预热），界面展示截尾平均与波动区间。</span></div><div class="latency-overview-list">${rows}</div>`;
}

function nodeTable(nodes, editable = true) {
  if (!nodes.length) return '<div class="empty"><strong>尚无节点</strong>从接入页面生成第一条安装命令。</div>';
  const addressChange = state.topology?.addressChange;
  const pendingAddresses = new Map((addressChange?.status === 'pending' ? addressChange.assignments : [])
    .filter((assignment) => assignment.changed)
    .map((assignment) => [assignment.nodeId, assignment.after]));
  return `<div class="node-list">
    <div class="node-row header"><span>节点</span><span>业务 IP</span><span>控制 IP</span><span>状态</span><span></span></div>
    ${nodes.map((node) => `<div class="node-row">
      <span class="node-identity"><span class="node-glyph">◇</span><span><strong>${escapeHtml(node.name)}</strong><small>${escapeHtml(node.id.slice(0, 12))}</small></span></span>
      <span class="mono">${escapeHtml(node.dataIp)}${pendingAddresses.has(node.id) && pendingAddresses.get(node.id) !== node.dataIp
        ? `<small class="pending-ip">→ ${escapeHtml(pendingAddresses.get(node.id))}</small>` : ''}</span>
      <span class="mono">${escapeHtml(node.controlIp)}</span>
      <span><span class="status ${escapeHtml(node.status)}">${node.status === 'online' ? '在线' : escapeHtml(node.status)}</span><small>${escapeHtml(reachabilityLabel(node))}</small></span>
      ${editable ? `<button class="button ghost small edit-node" data-id="${node.id}">编辑</button>` : '<span></span>'}
    </div>`).join('')}
  </div>`;
}

function renderAddressChange(change) {
  if (!change) return '';
  const nodes = change.rollout?.nodes || [];
  const required = nodes.filter((node) => node.required);
  const deferred = nodes.filter((node) => !node.required && node.phase !== 'activated');
  const completed = required.filter((node) => change.rolloutStatus === 'preparing'
    ? ['prepared', 'activated'].includes(node.phase)
    : node.phase === 'activated');
  const assignment = change.assignments?.find((item) => item.changed);
  const subject = change.beforeCidr !== change.afterCidr
    ? `业务网段 ${change.beforeCidr} → ${change.afterCidr}`
    : `${assignment?.name || '节点'} 业务 IP ${assignment?.before || '—'} → ${assignment?.after || '—'}`;
  if (change.status === 'failed') {
    return `<div class="notice warning"><strong>地址切换失败</strong><span>${escapeHtml(subject)}：${escapeHtml(change.error || '节点未能应用配置')}。当前业务地址未改变。</span></div>`;
  }
  return `<div class="notice warning"><strong>正在切换地址</strong><span>${escapeHtml(subject)} · v${change.version} ${escapeHtml(change.rolloutStatus)} · 在线节点 ${completed.length}/${required.length}。${deferred.length ? `${deferred.length} 台离线节点不会阻塞切换，恢复后会自动追赶当前配置。` : '所有在线节点必须完成准备和激活。'}</span></div>`;
}

function renderNodes() {
  const network = currentNetwork();
  const preview = state.cidrPreview;
  const changedAssignments = preview?.assignments?.filter((assignment) => assignment.changed) || [];
  return `<div class="section-stack">
    <div class="notice"><strong>地址变更策略</strong><span>业务 IP 必须位于 ${escapeHtml(network?.dataCidr)}。保存前会检查冲突和全网路由；控制 IP 不随业务地址变化。</span></div>
    ${state.panelStatus?.writable ? '' : `<div class="notice warning"><strong>当前不能发布</strong><span>${escapeHtml(state.panelStatus?.message || '配置协调节点尚未取得多数派租约')}。地址预检仍可使用，恢复多数派后再确认发布。</span></div>`}
    ${renderAddressChange(state.topology?.addressChange)}
    <article class="card"><div class="card-head"><div><h2>业务网段</h2><p>选择私有地址范围或手动输入；先检测，再生成全网配置版本</p></div></div>
      <form class="card-body form-stack" id="cidr-form">
        <div class="form-grid">
          <label>常用私有网段<select name="preset"><option value="">自定义</option><option value="10.77.0.0/16">10.77.0.0/16</option><option value="10.0.0.0/16">10.0.0.0/16</option><option value="172.20.0.0/16">172.20.0.0/16</option><option value="192.168.240.0/20">192.168.240.0/20</option></select></label>
          <label>候选业务网段<input name="dataCidr" required value="${escapeHtml(preview?.after || network?.dataCidr || '')}" placeholder="例如 10.77.0.0/16"></label>
        </div>
        <button class="button primary" type="submit">检测地址占用</button>
      </form>
      ${preview ? `<div class="card-body section-stack"><div class="notice"><strong>静态检测通过</strong><span>${escapeHtml(preview.after)} 可容纳 ${preview.checks.capacity} 个地址；发布准备阶段还会由各 Agent 检查本机接口和路由。</span></div>
        <div class="command-box"><code>${changedAssignments.length ? changedAssignments.map((assignment) => `${escapeHtml(assignment.name)}：${escapeHtml(assignment.before)} → ${escapeHtml(assignment.after)}`).join('<br>') : '现有节点地址均可保留'}</code></div>
        <button class="button primary" id="apply-cidr" type="button" ${state.panelStatus?.writable ? '' : 'disabled'}>确认修改并发布</button></div>` : ''}
    </article>
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
    Number(nodeB.isCoordinator) - Number(nodeA.isCoordinator) || nodeA.id.localeCompare(nodeB.id));
  sortedNodes.forEach((node, index) => {
    const previous = state.graph.positions.get(node.id);
    const angle = (Math.PI * 2 * index) / Math.max(1, sortedNodes.length) - Math.PI / 2;
    positions.set(node.id, previous ?? {
      x: node.isCoordinator ? centerX : centerX + Math.cos(angle) * radius,
      y: node.isCoordinator ? centerY : centerY + Math.sin(angle) * radius,
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
  if (link.validationStatus === 'probing') return `连通性探测 ${link.validationProgress?.probed || 0}/${link.validationProgress?.requested || 1}`;
  if (link.validationStatus === 'failed') return link.validationError?.includes('超时') ? '验证超时' : '验证失败';
  const probe = latencyProbeLabel(link.benchmark);
  if (probe) return probe;
  if (link.benchmark?.status === 'completed') return latencyDisplay(link.benchmark);
  if (link.validationProgress?.successful === 1) return '单向可用';
  return '';
}

function linkLatencyClass(link) {
  if (link.benchmark?.status !== 'completed') return '';
  const stale = isLatencyStale(link.benchmark.measuredAt);
  return `latency-${latencyQuality(link.benchmark.latencyMs)}${stale ? ' stale' : ''}`;
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
    const latencyClass = linkLatencyClass(link);
    return `<path class="graph-edge ${escapeHtml(status)} ${latencyClass}" data-link-id="${link.id}" data-from="${link.upstreamId}" data-to="${link.downstreamId}" d="${path.d}"></path>${label ? `<text class="graph-edge-label ${latencyClass}" data-link-label="${link.id}" data-from="${link.upstreamId}" data-to="${link.downstreamId}" x="${path.labelX}" y="${path.labelY}">${escapeHtml(label)}</text>` : ''}`;
  }).join('');
  const nodeMarkup = nodes.map((node, index) => {
    const position = layout.positions.get(node.id);
    const selected = state.selectedNodeIds.includes(node.id);
    const parent = node.parentId ? nodeById.get(node.parentId) : null;
    const offline = !node.isCoordinator && node.status !== 'online';
    const routeMeta = node.isCoordinator
      ? '当前协调节点'
      : parent ? `初始上游 · ${escapeHtml(parent.name)}` : '无初始上游';
    return `<foreignObject data-node-container="${node.id}" x="${position.x}" y="${position.y}" width="${graphWorld.nodeWidth}" height="${graphWorld.nodeHeight}"><button class="graph-node svg-node ${node.isCoordinator ? 'center' : ''} ${offline ? 'offline' : ''}" data-node-id="${node.id}" aria-pressed="${selected}">
      <span class="graph-node-head"><strong>${escapeHtml(node.name)}</strong><span class="graph-node-index">${String(index + 1).padStart(2, '0')}</span></span>
      <span class="graph-node-address">${escapeHtml(node.dataIp)}</span>
      <span class="graph-node-meta">${offline ? 'Agent 离线 · ' : ''}${routeMeta}</span>
    </button></foreignObject>`;
  }).join('');
  const viewport = layout.viewport;
  return `<div class="graph-surface" id="topology-graph"><div class="graph-gesture-hint">Ctrl + 滚轮缩放 · 拖动画布平移 · 拖动节点调整位置</div><svg class="topology-svg" viewBox="0 0 ${graphWorld.width} ${graphWorld.height}" role="img" aria-label="可缩放、可拖动的节点数据连接拓扑"><g id="graph-world" transform="translate(${viewport.x} ${viewport.y}) scale(${viewport.scale})">${edges}${nodeMarkup}</g></svg></div>`;
}

function renderLatencyLinkTable(links, nodes) {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const activeLinks = links.filter((link) => link.validationStatus === 'active');
  if (!activeLinks.length) {
    return '<div class="empty compact"><strong>尚无已验证链路</strong>建立连接并完成验证后，可在此查看各段延迟。</div>';
  }
  const sorted = [...activeLinks].sort((linkA, linkB) => {
    const latencyA = linkA.benchmark?.status === 'completed' ? Number(linkA.benchmark.latencyMs) : Infinity;
    const latencyB = linkB.benchmark?.status === 'completed' ? Number(linkB.benchmark.latencyMs) : Infinity;
    return latencyA - latencyB;
  });
  return `<div class="latency-link-table">
    <div class="latency-link-row header"><span>链路</span><span>状态</span><span>典型延迟</span><span>更新时间</span></div>
    ${sorted.map((link) => {
      const upstream = nodeById.get(link.upstreamId);
      const downstream = nodeById.get(link.downstreamId);
      const probe = latencyProbeLabel(link.benchmark);
      const status = probe
        ? `<span class="latency-status running">${probe}</span>`
        : link.benchmark?.status === 'failed'
          ? `<span class="latency-status failed" title="${escapeHtml(link.benchmark.error || '')}">失败</span>`
          : link.benchmark?.status === 'completed'
            ? `<span class="latency-status done">已完成</span>`
            : '<span class="latency-status idle">未探测</span>';
      const latency = link.benchmark?.status === 'completed'
        ? `<strong class="latency-${latencyQuality(link.benchmark.latencyMs)}">${escapeHtml(latencyDisplay(link.benchmark))}</strong>`
        : '<span class="muted">—</span>';
      const age = link.benchmark?.status === 'completed'
        ? `<small class="${isLatencyStale(link.benchmark.measuredAt) ? 'stale-age' : ''}">${escapeHtml(latencyAgeLabel(link.benchmark.measuredAt))}</small>`
        : '<span class="muted">—</span>';
      return `<div class="latency-link-row ${link.benchmark?.status === 'completed' && isLatencyStale(link.benchmark.measuredAt) ? 'stale' : ''}"><span>${escapeHtml(upstream?.name || '—')} ↔ ${escapeHtml(downstream?.name || '—')}</span><span>${status}</span><span>${latency}</span><span>${age}</span></div>`;
    }).join('')}
  </div>`;
}

function renderTopology() {
  const valid = state.topology.validation?.fullyReachable;
  const selected = state.selectedNodeIds.map((id) => state.topology.nodes.find((node) => node.id === id)).filter(Boolean);
  const links = state.topology.links;
  const latencySummary = summarizeLinkLatencies(links);
  const waiting = links.filter((link) => link.validationStatus === 'preparing').length;
  const probing = links.filter((link) => link.validationStatus === 'probing').length;
  const latencyRunning = latencySummary.running;
  const validationText = [
    waiting ? `${waiting} 条等待 Agent` : '',
    probing ? `${probing} 条正在探测已填写方向（任一成功即可）` : '',
    latencyRunning ? `${latencyRunning} 条延迟探测进行中` : '',
    latencySummary.completed ? `${latencySummary.completed} 条已有延迟结果` : '',
  ].filter(Boolean).join(' · ') || '可建立直连或查看端到端路径';
  const selectionText = selected.length === 0
    ? '点击画布中的两个节点'
    : selected.length === 1
      ? `已选择 ${selected[0].name}，再选一个节点`
      : `${selected[0].name} ↔ ${selected[1].name}`;
  const canProbe = links.some((link) => link.validationStatus === 'active') && !latencyRunning;
  return `<article class="card">
    <div class="card-head"><div><h2>可视化拓扑编辑</h2><p>布局随连接关系自动收敛；每条链路独立进行 10 次 RTT 采样</p></div><span class="status ${valid ? 'active' : 'failed'}">${valid ? '全网可达' : '需要修复'}</span></div>
    <div class="graph-toolbar">
      <div class="graph-toolbar-main"><span class="selection-count">${selected.length}/2</span><span class="selection-copy"><strong>${escapeHtml(selectionText)}</strong><small>${validationText}</small></span></div>
      <div class="graph-actions"><button class="button ghost" id="benchmark-adjacent" ${canProbe ? '' : 'disabled'}>${latencyRunning ? '探测进行中' : '探测全部相邻链路'}</button><button class="button ghost" id="clear-node-selection" ${selected.length ? '' : 'disabled'}>取消选择</button><button class="button ghost" id="connect-selected" ${selected.length === 2 ? '' : 'disabled'}>建立连接</button><button class="button primary" id="detail-selected" ${selected.length === 2 ? '' : 'disabled'}>详细配置</button></div>
    </div>
    ${renderTopologyGraph()}
    <div class="graph-legend"><span>已验证通路</span><span class="waiting">等待 Agent</span><span class="probing">按填写方向探测 · 任一成功可用</span><span class="failed">所填方向均失败</span><span class="latency-excellent">≤ 30 ms</span><span class="latency-good">31–80 ms</span><span class="latency-fair">81–150 ms</span><span class="latency-poor">&gt; 150 ms</span><span class="graph-legend-hint">点击节点进行选择</span></div>
    <div class="latency-panel"><div class="latency-panel-head"><div><strong>相邻链路延迟</strong><small>${latencySummary.completed}/${latencySummary.total || 0} 已探测${latencySummary.average == null ? '' : ` · 平均 ${formatLatency(latencySummary.average)}`}</small></div><small class="muted">典型值为截尾平均，括号内为最小–最大波动</small></div>${renderLatencyLinkTable(links, state.topology.nodes)}</div>
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
    state.pathMode = state.pathDetail.policy?.mode || 'failover';
    state.defaultPathId = state.pathDetail.policy?.defaultPathId || state.pathDetail.effectiveDefaultPathId || null;
    state.selectedPathIds = state.pathMode === 'weighted'
      ? (state.pathDetail.policy?.paths ?? []).map((path) => path.pathId)
      : (state.defaultPathId ? [state.defaultPathId] : []);
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

function renderPathChain(path, linkById) {
  return path.nodes.map((node, nodeIndex) => {
    const segment = nodeIndex === 0 ? '' : (() => {
      const linkId = path.linkIds?.[nodeIndex - 1];
      const benchmark = linkById.get(linkId)?.benchmark;
      const latency = benchmark?.status === 'completed' ? latencyDisplay(benchmark) : latencyProbeLabel(benchmark);
      const quality = benchmark?.status === 'completed' ? latencyQuality(benchmark.latencyMs) : 'unknown';
      return `<span class="path-segment-wrap">${latency ? `<span class="path-segment-latency latency-${quality}">${escapeHtml(latency)}</span>` : ''}<span class="path-segment" aria-hidden="true"></span></span>`;
    })();
    return `${segment}<span class="path-chain-node ${node.status === 'online' ? '' : 'offline'}"><strong>${escapeHtml(node.name)}</strong><small>${escapeHtml(node.dataIp)}</small></span>`;
  }).join('');
}

function renderPathLatencyBadge(path, linkById) {
  const linkIds = path.linkIds || [];
  const segmentBenchmarks = linkIds.map((linkId) => linkById.get(linkId)?.benchmark).filter(Boolean);
  if (segmentBenchmarks.some((benchmark) => ['preparing', 'testing'].includes(benchmark.status))) {
    return '<span class="path-latency running">各段探测中…</span>';
  }
  if (segmentBenchmarks.some((benchmark) => benchmark.status === 'failed') || path.benchmark?.status === 'failed') {
    const error = segmentBenchmarks.find((benchmark) => benchmark.error)?.error || path.benchmark?.error || '';
    return `<span class="path-latency failed" title="${escapeHtml(error)}">探测失败</span>`;
  }
  const stats = pathLatencyStats(path, linkById);
  if (stats) {
    const stale = isLatencyStale(stats.measuredAt);
    return `<span class="path-latency success latency-${latencyQuality(stats.typical)}${stale ? ' stale' : ''}" title="各段典型延迟之和 · 括号内为全路径波动区间">${escapeHtml(pathLatencySummary(stats))}</span><small class="path-latency-age${stale ? ' stale-age' : ''}">${escapeHtml(latencyAgeLabel(stats.measuredAt))}</small>`;
  }
  return '<span class="path-latency idle">尚未探测</span>';
}

function renderPathComparison(paths, linkById) {
  const ranked = paths
    .map((path) => ({ path, stats: pathLatencyStats(path, linkById) }))
    .filter((item) => item.stats)
    .sort((itemA, itemB) => itemA.stats.typical - itemB.stats.typical);
  if (ranked.length < 2) return '';
  const maxUpper = Math.max(...ranked.map((item) => item.stats.upper));
  return `<div class="path-comparison"><div class="path-comparison-head"><strong>通路延迟对比</strong><small>按典型总延迟排序 · 柱长对应波动上限</small></div>${ranked.map((item, index) => {
    const width = maxUpper ? Math.max(8, Math.round((item.stats.upper / maxUpper) * 100)) : 0;
    const innerWidth = maxUpper ? Math.max(6, Math.round((item.stats.typical / maxUpper) * 100)) : 0;
    return `<div class="path-comparison-row"><span class="path-comparison-index">P${String(paths.indexOf(item.path) + 1).padStart(2, '0')}</span><div class="path-comparison-bar"><span class="path-comparison-range latency-${latencyQuality(item.stats.typical)}" style="width:${width}%"><span class="path-comparison-typical" style="width:${innerWidth}%"></span></span></div><strong>${escapeHtml(pathLatencySummary(item.stats))}</strong>${index === 0 ? '<small>最快</small>' : ''}</div>`;
  }).join('')}</div>`;
}

function renderPathDetail() {
  const details = state.pathDetail;
  if (!details) return '<div class="loading-card"><span class="spinner"></span>正在计算无环路径…</div>';
  const linkById = new Map((state.topology?.links || []).map((link) => [link.id, link]));
  const failoverMode = state.pathMode !== 'weighted';
  const selectedIds = new Set(state.selectedPathIds);
  const selectedPaths = details.paths.filter((path) => selectedIds.has(path.id));
  const activeSelectedPaths = selectedPaths.filter((path) => path.available !== false);
  const totalWeight = activeSelectedPaths.reduce((total, path) => total + Number(state.pathWeights[path.id] || 1), 0);
  const latencyRunning = details.paths.some((path) => path.benchmark?.status === 'testing'
    || (path.linkIds || []).some((linkId) => latencyProbeLabel(linkById.get(linkId)?.benchmark)));
  const lanes = details.paths.length ? details.paths.map((path, index) => {
    const selected = failoverMode ? state.defaultPathId === path.id : selectedIds.has(path.id);
    const unavailable = path.available === false;
    const weight = Number(state.pathWeights[path.id] || 1);
    const share = !failoverMode && selected && !unavailable && totalWeight
      ? Math.round((weight / totalWeight) * 1000) / 10
      : 0;
    const chain = renderPathChain(path, linkById);
    const status = unavailable
      ? '<strong>故障暂时剔除</strong><small>每 20 秒复检 · 保留原权重</small>'
      : !failoverMode && selected
        ? `<strong>运行中 · ${share}%</strong><small>链路恢复后会自动加入</small>`
        : `<strong>${selected && failoverMode ? '默认线路' : `${path.hops} 跳`}</strong><small>${failoverMode && !selected ? `故障候选 · 成本 ${path.totalCost}` : `成本 ${path.totalCost}`}</small>`;
    const latency = renderPathLatencyBadge(path, linkById);
    return `<label class="path-lane ${selected ? 'selected' : ''} ${unavailable ? 'unavailable' : ''}">
      <input class="path-option" type="${failoverMode ? 'radio' : 'checkbox'}" ${failoverMode ? 'name="defaultPath"' : ''} value="${path.id}" ${selected ? 'checked' : ''}>
      <span class="path-lane-index">P${String(index + 1).padStart(2, '0')}</span>
      <span class="path-chain">${chain}</span>
      <span class="path-lane-meta">${status}<span class="path-latency-block">${latency}</span></span>
    </label>`;
  }).join('') : '<div class="empty"><strong>没有可用路径</strong>当前两个节点之间不存在由已验证连接组成的无环路径。</div>';
  const weights = selectedPaths.map((path) => {
    const weight = Number(state.pathWeights[path.id] || 1);
    const share = path.available !== false && totalWeight ? Math.round((weight / totalWeight) * 1000) / 10 : 0;
    return `<label class="path-weight-row ${path.available === false ? 'unavailable' : ''}"><span>P${String(details.paths.indexOf(path) + 1).padStart(2, '0')}</span><input class="path-weight" data-path-id="${path.id}" type="number" min="1" max="1000" value="${weight}"><strong data-weight-share="${path.id}">${path.available === false ? '暂时剔除' : `${share}%`}</strong></label>`;
  }).join('');
  return `<article class="card path-detail-card">
    <div class="card-head"><div><p class="eyebrow">END-TO-END PATHS</p><h2>${escapeHtml(details.source.name)} ↔ ${escapeHtml(details.target.name)}</h2><p>${details.paths.length} 条无环路径${details.truncated ? ' · 已按安全上限截断' : ''}；端到端延迟为各段典型 RTT 之和，括号内为全路径波动区间</p></div><div class="graph-actions"><button class="button primary small" id="benchmark-paths" ${latencyRunning || !details.paths.length ? 'disabled' : ''}>${latencyRunning ? '通路探测中' : '探测全部通路'}</button><a class="button ghost" href="#topology">返回主拓扑</a></div></div>
    <div class="path-endpoints"><span><strong>${escapeHtml(details.source.name)}</strong><small>${escapeHtml(details.source.dataIp)}</small></span><span>${details.paths.length} 条路径</span><span><strong>${escapeHtml(details.target.name)}</strong><small>${escapeHtml(details.target.dataIp)}</small></span></div>
    ${renderPathComparison(details.paths, linkById)}
    <div class="path-mode-bar segmented"><label><input class="path-mode" type="radio" name="pathMode" value="failover" ${failoverMode ? 'checked' : ''}><span>默认线路与故障切换</span></label><label title="${details.paths.length < 2 ? '至少需要两条无环路径' : ''}"><input class="path-mode" type="radio" name="pathMode" value="weighted" ${failoverMode ? '' : 'checked'} ${details.paths.length < 2 ? 'disabled' : ''}><span>负载均衡</span></label></div>
    <div class="path-lanes">${lanes}</div>
    <div class="path-policy-editor">
      <div><strong>${failoverMode ? '主备线路' : '负载均衡'}</strong><small>${failoverMode ? '流量优先走所选默认线路；不可达时按成本依次尝试其他无环路径。' : '故障路径保留原权重但暂时不参与分流；每 20 秒复检，恢复后自动按原权重加入。'}</small></div>
      <div class="path-weight-list">${failoverMode ? `<span class="muted">已选择 ${state.defaultPathId ? `P${String(details.paths.findIndex((path) => path.id === state.defaultPathId) + 1).padStart(2, '0')}` : '—'} 为默认线路</span>` : (weights || '<span class="muted">尚未选择路径</span>')}</div>
      <div class="path-policy-actions">${failoverMode ? '' : `<button class="button ghost" id="equalize-paths" ${selectedPaths.length ? '' : 'disabled'}>设为等权</button>`}${details.policy ? '<button class="button danger" id="disable-path-policy">恢复系统自动选择</button>' : ''}<button class="button primary" id="save-path-policy" ${(failoverMode ? state.defaultPathId : selectedPaths.length >= 2) ? '' : 'disabled'}>${failoverMode ? '保存默认线路' : '保存负载均衡'}</button></div>
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
  if (!state.pathDetail) return;
  if (state.pathMode === 'weighted' && state.selectedPathIds.length < 2) return;
  if (state.pathMode !== 'weighted' && !state.defaultPathId) return;
  try {
    const result = await api(`/api/v1/networks/${state.networkId}/path-policies`, {
      method: 'PUT',
      body: JSON.stringify({
        sourceId: state.pathDetail.source.id,
        targetId: state.pathDetail.target.id,
        mode: state.pathMode,
        defaultPathId: state.defaultPathId,
        paths: state.selectedPathIds.map((pathId) => ({ pathId, weight: Number(state.pathWeights[pathId] || 1) })),
      }),
    });
    state.pathDetail = result.details;
    state.pathMode = result.details.policy.mode;
    state.defaultPathId = result.details.policy.defaultPathId || result.details.effectiveDefaultPathId;
    state.selectedPathIds = state.pathMode === 'weighted'
      ? result.details.policy.paths.map((path) => path.pathId)
      : [state.defaultPathId];
    state.pathWeights = Object.fromEntries(result.details.policy.paths.map((path) => [path.pathId, path.weight]));
    render();
    toast(state.pathMode === 'weighted' ? '负载均衡策略已保存并生成新的配置版本' : '默认线路与故障切换顺序已保存');
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
    state.pathMode = 'failover';
    state.defaultPathId = result.details.effectiveDefaultPathId || null;
    state.selectedPathIds = state.defaultPathId ? [state.defaultPathId] : [];
    state.pathWeights = {};
    render();
    toast('已恢复系统按路径成本自动选择');
  } catch (error) { toast(error.message, 'error'); }
}

function reachabilityTypeOf(node) {
  return node?.reachabilityType || (node?.hasPublicEndpoint ? 'public' : 'nat');
}

function reachabilityLabel(node) {
  const type = reachabilityTypeOf(node);
  if (type === 'ix') return 'IX（上行 NAT）';
  if (type === 'public') return '公网可拨入';
  return '仅主动拨出';
}

function canJoinAsParent(node) {
  const type = reachabilityTypeOf(node);
  return Boolean(node?.canRelay && (type === 'public' || type === 'ix'));
}

function renderJoin() {
  const result = state.joinResult;
  const mode = state.joinMode || result?.mode || 'active';
  const nodes = state.topology.nodes.filter((node) => node.status === 'online' && (
    mode === 'passive' ? node.canRelay : canJoinAsParent(node)
  ));
  const selectedParent = nodes.find((node) => node.id === (state.joinParentId || result?.parent?.id)) || nodes[0];
  const parentConnection = controlConnection(selectedParent);
  const parentDataConnection = wireGuardConnection(selectedParent, parentConnection.host);
  return `<div class="join-layout">
    <article class="card"><div class="card-head"><div><h2>生成安装命令</h2><p>${mode === 'passive' ? '选择负责主动连接待认领设备的已入网节点' : '选择新设备实际能够访问的接入节点'}</p></div></div>
      <form class="card-body form-stack" id="join-form">
        <div class="segmented"><label><input type="radio" name="mode" value="active" ${mode === 'active' ? 'checked' : ''}><span>设备主动加入</span></label><label><input type="radio" name="mode" value="passive" ${mode === 'passive' ? 'checked' : ''}><span>已入网节点主动认领</span></label></div>
        <div class="notice"><strong>${mode === 'passive' ? '连接方向：认领节点 → 待认领设备' : '新设备主动拨号可接入父节点'}</strong><span>${mode === 'passive' ? '待认领设备只监听，不会反向连接接入节点；认领节点将代理它的注册、心跳和配置下发。公网与 IX 节点均可发起认领。' : '安装时会询问拨入类型：公网、纯 NAT 或 IX。IX 发布内网入口供新节点接入，上行仍按 NAT；NAT/IX 后续都可主动连接有公网的节点。'}</span></div>
        <label>${mode === 'passive' ? '执行认领的已入网节点' : '接入节点'}<select name="parentId">${nodes.map((node) => {
          const connection = controlConnection(node);
          const dataConnection = wireGuardConnection(node, connection.host);
          return `<option value="${node.id}" data-host="${escapeHtml(connection.host)}" data-port="${connection.port}" data-protocol="${connection.protocol}" data-data-host="${escapeHtml(dataConnection.host)}" data-data-port="${dataConnection.port}" ${node.id === selectedParent?.id ? 'selected' : ''}>${escapeHtml(node.name)} · ${escapeHtml(node.controlIp)}</option>`;
        }).join('')}</select></label>
        ${mode === 'active' ? `<div class="form-grid">
          <label>接入协议<select name="parentProtocol"><option value="http" ${parentConnection.protocol === 'http' ? 'selected' : ''}>HTTP</option><option value="https" ${parentConnection.protocol === 'https' ? 'selected' : ''}>HTTPS</option></select></label>
          <label>父节点控制端口<input name="parentPort" type="number" min="1" max="65535" required value="${parentConnection.port || ''}"></label>
          <label class="span-2">新设备能访问的父节点 IP 或域名<input name="parentHost" required value="${escapeHtml(parentConnection.host)}" placeholder="选择父节点后自动填充，也可覆盖"></label>
          <label>父节点 WireGuard IP 或域名<input name="parentDataHost" required value="${escapeHtml(parentDataConnection.host)}" placeholder="默认跟随父节点入口，也可覆盖"></label>
          <label>父节点 WireGuard UDP 端口<input name="parentDataPort" type="number" min="1" max="65535" required value="${parentDataConnection.port || ''}"></label>
        </div>` : '<div class="notice"><strong>固定 GitHub 安装源</strong><span><a href="https://github.com/FengYuchen1314/sd-wan" target="_blank" rel="noreferrer">FengYuchen1314/sd-wan</a> · main。目标设备下载与其他设备完全相同的节点服务、面板和 Agent。</span></div>'}
        <label>令牌有效时间（分钟）<input name="ttlMinutes" type="number" min="5" max="1440" value="30"></label>
        <button class="button primary" type="submit" ${nodes.length ? '' : 'disabled'}>${mode === 'passive' ? '生成 GitHub 节点安装命令' : '生成一次性命令'}</button>
      </form>
    </article>
    <article class="card"><div class="card-head"><div><h2>可复制命令</h2><p>令牌仅显示一次，默认使用后立即失效</p></div>${result ? '<button class="button ghost small" id="copy-command">复制命令</button>' : ''}</div>
      <div class="card-body section-stack">
        <div class="command-box">${result ? `<code>${escapeHtml(result.command)}</code><div class="command-meta"><span>入口：${escapeHtml(result.parent.name)}</span>${result.parentDataConnection ? `<span>WireGuard：${escapeHtml(result.parentDataConnection.endpoint)}</span>` : ''}<span>有效至 ${formatDate(result.expiresAt)}</span></div>` : '<div class="empty"><strong>等待生成</strong>命令将绑定节点组、父节点和短时效认证令牌。</div>'}</div>
        <div class="notice"><strong>${mode === 'passive' ? '单向被动认领' : '传递式安装'}</strong><span>${mode === 'passive' ? '目标节点不需要反向访问接入节点；认领方会持续代理控制通信，目标本机仍提供完整面板。' : '任意已入网节点都能传递同一份安装包；新设备加入后立即拥有本机面板，所有操作实时写入全网版本化配置。'}</span></div>
        ${result?.mode === 'passive' ? `<form id="adopt-form" class="form-stack">
          <div class="form-grid"><label>待认领节点 IP 或域名<input name="targetHost" required placeholder="安装脚本最后显示的地址"></label><label>待认领节点控制端口<input name="targetPort" type="number" min="1" max="65535" required placeholder="由目标节点安装时选择"></label></div>
          <button class="button primary" type="submit">命令 ${escapeHtml(result.parent.name)} 主动连接</button>
          <p class="muted flush">认领指令会沿控制树送到 ${escapeHtml(result.parent.name)}，由它连接目标并成为控制父节点。</p>
        </form>` : ''}
      </div>
    </article>
  </div>`;
}

function controlConnection(node) {
  let protocol = 'http';
  let host = '';
  let port = Number(node?.controlListenPort || 8790);
  if (node?.controlEndpoint) {
    try {
      const parsed = new URL(node.controlEndpoint);
      protocol = parsed.protocol.replace(':', '');
      host = parsed.hostname;
      port = Number(parsed.port || (protocol === 'https' ? 443 : port));
    } catch {}
  }
  return { protocol, host, port };
}

function wireGuardConnection(node, fallbackHost = '') {
  let host = fallbackHost;
  let port = Number(node?.dataListenPort || currentNetwork()?.listenPort || 19801);
  const endpoint = String(node?.dataEndpoint || '').trim();
  if (endpoint.startsWith('[')) {
    const closing = endpoint.indexOf(']');
    if (closing > 0) {
      host = endpoint.slice(0, closing + 1);
      const parsedPort = Number(endpoint.slice(closing + 2));
      if (Number.isInteger(parsedPort)) port = parsedPort;
    }
  } else if (endpoint.lastIndexOf(':') > 0) {
    host = endpoint.slice(0, endpoint.lastIndexOf(':'));
    const parsedPort = Number(endpoint.slice(endpoint.lastIndexOf(':') + 1));
    if (Number.isInteger(parsedPort)) port = parsedPort;
  }
  return { host, port };
}

function renderRollouts() {
  return `<div class="section-stack"><article class="card"><div class="card-head"><div><h2>配置版本</h2><p>IP 和拓扑变更均通过准备、激活两个阶段发布</p></div></div>
    <div class="timeline">${state.configurations.length ? state.configurations.map((version) => `<div class="rollout"><span class="version">v${version.version}</span><span><strong>${escapeHtml(version.reason)}</strong><small class="rollout-id">${escapeHtml(version.id.slice(0, 12))}</small></span><span class="status ${escapeHtml(version.status)}">${escapeHtml(version.status)}</span><span>${formatDate(version.activatedAt || version.createdAt)}</span></div>`).join('') : '<div class="empty">暂无配置版本</div>'}</div>
  </article></div>`;
}

function bindViewEvents() {
  document.querySelectorAll('.edit-node').forEach((button) => button.addEventListener('click', () => openNode(button.dataset.id)));
  bindGraphInteractions();
  document.querySelector('#clear-node-selection')?.addEventListener('click', () => { state.selectedNodeIds = []; render(); });
  document.querySelector('#connect-selected')?.addEventListener('click', openConnectionDialog);
  document.querySelector('#detail-selected')?.addEventListener('click', openPathDetail);
  document.querySelector('#benchmark-adjacent')?.addEventListener('click', () => startLinkBenchmarks());
  document.querySelector('#benchmark-paths')?.addEventListener('click', () => startLinkBenchmarks({
    sourceId: state.pathDetail?.source.id,
    targetId: state.pathDetail?.target.id,
  }));
  document.querySelectorAll('.path-mode').forEach((radio) => radio.addEventListener('change', () => {
    state.pathMode = radio.value;
    if (state.pathMode === 'failover') {
      state.defaultPathId ||= state.pathDetail?.effectiveDefaultPathId || state.pathDetail?.paths?.[0]?.id || null;
      state.selectedPathIds = state.defaultPathId ? [state.defaultPathId] : [];
    }
    render();
  }));
  document.querySelectorAll('.path-option').forEach((checkbox) => checkbox.addEventListener('change', () => {
    if (state.pathMode === 'failover') {
      state.defaultPathId = checkbox.value;
      state.selectedPathIds = [checkbox.value];
      render();
      return;
    }
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
  document.querySelectorAll('#join-form input[name="mode"]').forEach((radio) => radio.addEventListener('change', () => {
    state.joinMode = radio.value;
    state.joinResult = null;
    render();
  }));
  document.querySelector('#cidr-form')?.addEventListener('submit', previewDataCidr);
  document.querySelector('#cidr-form select[name="preset"]')?.addEventListener('change', (event) => {
    if (event.target.value) document.querySelector('#cidr-form input[name="dataCidr"]').value = event.target.value;
  });
  document.querySelector('#apply-cidr')?.addEventListener('click', applyDataCidr);
  document.querySelector('#adopt-form')?.addEventListener('submit', enqueueAdoption);
  const parentSelect = document.querySelector('#join-form select[name="parentId"]');
  parentSelect?.addEventListener('change', () => {
    const option = parentSelect.selectedOptions[0];
    state.joinParentId = parentSelect.value;
    const form = document.querySelector('#join-form');
    if (form.elements.parentHost) form.elements.parentHost.value = option?.dataset.host || '';
    if (form.elements.parentPort) form.elements.parentPort.value = option?.dataset.port || '';
    if (form.elements.parentProtocol) form.elements.parentProtocol.value = option?.dataset.protocol || 'http';
    if (form.elements.parentDataHost) form.elements.parentDataHost.value = option?.dataset.dataHost || option?.dataset.host || '';
    if (form.elements.parentDataPort) form.elements.parentDataPort.value = option?.dataset.dataPort || '';
  });
  document.querySelector('#copy-command')?.addEventListener('click', async () => {
    try {
      await copyText(state.joinResult.command);
      toast('安装命令已复制到剪贴板');
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

async function startLinkBenchmarks(scope = {}) {
  const button = document.querySelector(scope.sourceId ? '#benchmark-paths' : '#benchmark-adjacent');
  if (button) button.disabled = true;
  try {
    await api(`/api/v1/networks/${state.networkId}/link-benchmarks`, {
      method: 'POST',
      body: JSON.stringify(scope),
    });
    if (state.view === 'path-detail' && scope.sourceId && scope.targetId) {
      await loadPathDetail(scope.sourceId, scope.targetId);
      render();
      toast('已开始探测这些通路涉及的每一段链路；端到端延迟会自动汇总');
    } else {
      await load();
      toast('已开始探测全部相邻链路；每条链路独立采样 10 次 RTT');
    }
  } catch (error) {
    if (button) button.disabled = false;
    toast(error.message, 'error');
  }
}

async function previewDataCidr(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    state.cidrPreview = await api(`/api/v1/networks/${state.networkId}/data-cidr-preview?dataCidr=${encodeURIComponent(form.get('dataCidr'))}`);
    render();
    toast('静态冲突与容量检测通过');
  } catch (error) { toast(error.message, 'error'); }
}

async function applyDataCidr() {
  if (!state.cidrPreview) return;
  try {
    const result = await api(`/api/v1/networks/${state.networkId}`, {
      method: 'PATCH',
      body: JSON.stringify({ dataCidr: state.cidrPreview.after }),
    });
    state.cidrPreview = null;
    await load();
    const deferred = result.version?.nodes?.filter((node) => !node.required).length || 0;
    toast(deferred ? `业务网段开始切换；${deferred} 台离线节点将在恢复后自动追赶` : '业务网段已进入全网准备与本机路由冲突检测阶段');
  } catch (error) { toast(error.message, 'error'); }
}

function reachablePort(node) {
  if (Number.isInteger(Number(node.dataListenPort))) return Number(node.dataListenPort);
  const endpointMatch = String(node.dataEndpoint || '').match(/:(\d+)$/);
  if (endpointMatch) return Number(endpointMatch[1]);
  return Number(currentNetwork()?.listenPort || 19801);
}

function syncConnectionEndpointInputs(form) {
  for (const suffix of ['A', 'B']) {
    const address = form.elements[`node${suffix}Address`];
    const port = form.elements[`node${suffix}Port`];
    const enabled = Boolean(String(address.value || '').trim());
    port.disabled = !enabled;
    port.required = enabled;
  }
}

function syncNodePublicFields(form) {
  const type = form.elements.reachabilityType.value;
  const enabled = type === 'public' || type === 'ix';
  form.elements.controlEndpoint.disabled = !enabled;
  form.elements.dataEndpoint.disabled = !enabled;
  form.elements.dataEndpoint.required = enabled;
  form.elements.canRelay.disabled = !enabled;
  form.elements.dataEndpoint.placeholder = type === 'ix' ? '供新节点拨入的内网 IP:端口' : '公网 IP 或域名:19801';
  form.elements.controlEndpoint.placeholder = type === 'ix' ? 'http://内网IP:中继端口' : 'http://公网或内网IP:8790';
  if (!enabled) {
    form.elements.controlEndpoint.value = '';
    form.elements.dataEndpoint.value = '';
    form.elements.canRelay.checked = false;
  }
}

function openConnectionDialog() {
  if (state.selectedNodeIds.length !== 2) return;
  const [nodeA, nodeB] = state.selectedNodeIds.map((id) => state.topology.nodes.find((node) => node.id === id));
  const existing = state.topology.links.some((link) =>
    link.validationStatus !== 'failed' && (
      (link.upstreamId === nodeA.id && link.downstreamId === nodeB.id) ||
      (link.upstreamId === nodeB.id && link.downstreamId === nodeA.id)
    ));
  if (existing) return toast('这两个节点之间已经存在连接或正在验证', 'error');
  if (reachabilityTypeOf(nodeA) !== 'public' && reachabilityTypeOf(nodeB) !== 'public') {
    return toast('NAT/IX 只能和有公网入口的节点建立后续直连', 'error');
  }
  const form = document.querySelector('#connection-form');
  form.elements.nodeAId.value = nodeA.id;
  form.elements.nodeBId.value = nodeB.id;
  form.elements.nodeAAddress.value = reachabilityTypeOf(nodeA) === 'public' ? wireGuardConnection(nodeA).host : '';
  form.elements.nodeBAddress.value = reachabilityTypeOf(nodeB) === 'public' ? wireGuardConnection(nodeB).host : '';
  form.elements.nodeAPort.value = reachablePort(nodeA);
  form.elements.nodeBPort.value = reachablePort(nodeB);
  syncConnectionEndpointInputs(form);
  for (const [node, suffix] of [[nodeA, 'A'], [nodeB, 'B']]) {
    const address = form.elements[`node${suffix}Address`];
    const port = form.elements[`node${suffix}Port`];
    const isPublic = reachabilityTypeOf(node) === 'public';
    address.disabled = !isPublic;
    port.disabled = !isPublic;
    address.placeholder = isPublic ? '公网 IP 或域名' : `${reachabilityTypeOf(node) === 'ix' ? 'IX' : 'NAT'}：此侧仅主动拨出`;
  }
  form.elements.priority.value = 10;
  document.querySelector('#connection-pair').innerHTML = `<strong>${escapeHtml(nodeA.name)}</strong><span>↔</span><strong>${escapeHtml(nodeB.name)}</strong>`;
  document.querySelector('#node-a-address-label').textContent = reachabilityTypeOf(nodeA) === 'public'
    ? `${nodeA.name} 的公网 IP 或域名`
    : `${nodeA.name}（${reachabilityTypeOf(nodeA) === 'ix' ? 'IX' : 'NAT'}，仅主动拨出）`;
  document.querySelector('#node-b-address-label').textContent = reachabilityTypeOf(nodeB) === 'public'
    ? `${nodeB.name} 的公网 IP 或域名`
    : `${nodeB.name}（${reachabilityTypeOf(nodeB) === 'ix' ? 'IX' : 'NAT'}，仅主动拨出）`;
  document.querySelector('#connection-capability-note').innerHTML = reachabilityTypeOf(nodeA) === 'public' && reachabilityTypeOf(nodeB) === 'public'
    ? '<strong>两端均可被拨入</strong><span>系统会执行双向探测；任一方向成功即可建链，失败方向会被丢弃。</span>'
    : `<strong>固定单向拨号</strong><span>${escapeHtml(reachabilityTypeOf(nodeA) === 'public' ? nodeB.name : nodeA.name)} 将主动拨号 ${escapeHtml(reachabilityTypeOf(nodeA) === 'public' ? nodeA.name : nodeB.name)}；NAT/IX 出口由 WireGuard 握手动态学习。</span>`;
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
  form.elements.controlListenPort.value = node.controlListenPort || 8790;
  form.elements.dataEndpoint.value = node.dataEndpoint || '';
  form.elements.dataListenPort.value = reachablePort(node);
  form.elements.canRelay.checked = node.canRelay;
  form.elements.reachabilityType.value = reachabilityTypeOf(node);
  syncNodePublicFields(form);
  const deleteButton = document.querySelector('#delete-node');
  deleteButton.disabled = node.isCoordinator;
  deleteButton.textContent = node.isCoordinator ? '协调节点需先迁移' : '删除节点';
  form.querySelector('[data-form-error]').textContent = state.panelStatus?.writable
    ? ''
    : `${state.panelStatus?.message || '当前配置面板只读'}，暂时不能发布业务 IP。`;
  form.querySelector('button.primary[value="default"]').disabled = !state.panelStatus?.writable;
  form.querySelector('#delete-node').disabled = !state.panelStatus?.writable;
  document.querySelector('#node-dialog').showModal();
}

async function deleteSelectedNode() {
  const form = document.querySelector('#node-form');
  const nodeId = form.elements.nodeId.value;
  const error = form.querySelector('[data-form-error]');
  error.textContent = '';
  try {
    const impact = await api(`/api/v1/nodes/${encodeURIComponent(nodeId)}/deletion-impact`);
    if (!impact.canDelete) {
      window.alert(impact.reason);
      error.textContent = impact.reason;
      return;
    }
    if (!window.confirm(`${impact.warning}\n\n确认继续删除吗？`)) return;
    await api(`/api/v1/nodes/${encodeURIComponent(nodeId)}`, { method: 'DELETE' });
    document.querySelector('#node-dialog').close();
    state.selectedNodeIds = state.selectedNodeIds.filter((id) => id !== nodeId);
    await load();
    toast('节点已删除，替代拓扑配置正在下发');
  } catch (reason) {
    error.textContent = reason.message;
    window.alert(reason.message);
  }
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
    state.joinMode = form.get('mode');
    state.joinParentId = form.get('parentId');
    state.joinResult = await api(`/api/v1/networks/${state.networkId}/join-tokens`, {
      method: 'POST',
      body: JSON.stringify({
        mode: form.get('mode'), parentId: form.get('parentId'),
        parentProtocol: form.get('parentProtocol') || undefined,
        parentHost: form.get('parentHost') || undefined,
        parentPort: form.get('parentPort') ? Number(form.get('parentPort')) : undefined,
        parentDataHost: form.get('parentDataHost') || undefined,
        parentDataPort: form.get('parentDataPort') ? Number(form.get('parentDataPort')) : undefined,
        ttlMinutes: Number(form.get('ttlMinutes')),
      }),
    });
    render(); toast('一次性接入命令已生成');
  } catch (error) { toast(error.message, 'error'); }
}

async function enqueueAdoption(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const targetHost = String(form.get('targetHost') || '').trim();
    const targetPort = Number(form.get('targetPort'));
    const targetUrl = `http://${targetHost.includes(':') && !targetHost.startsWith('[') ? `[${targetHost}]` : targetHost}:${targetPort}`;
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('目标地址只支持 HTTP 或 HTTPS');
    const result = await api(`/api/v1/nodes/${state.joinResult.parent.id}/commands`, {
      method: 'POST',
      body: JSON.stringify({
        type: 'adopt-node',
        payload: {
          targetUrl: parsed.href.replace(/\/$/, ''),
          claimToken: state.joinResult.token,
        },
      }),
    });
    if (result.node) {
      toast(result.targetConfirmationPending
        ? `${result.node.name} 已登记；目标确认将在后台自动重试`
        : `${result.node.name} 已认领并加入节点组`);
      await load();
    } else {
      toast(`认领指令已发送给 ${state.joinResult.parent.name}`);
    }
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
  state.joinMode = 'active';
  state.joinParentId = null;
  state.cidrPreview = null;
  state.pathDetail = null;
  state.pathMode = 'failover';
  state.defaultPathId = null;
  state.selectedNodeIds = [];
  state.graph.networkId = null;
  if (state.view === 'path-detail') location.hash = 'topology';
  load().catch((error) => toast(error.message, 'error'));
});
document.querySelector('#new-network').addEventListener('click', () => document.querySelector('#network-dialog').showModal());
document.querySelectorAll('dialog button[value="cancel"]').forEach((button) => button.addEventListener('click', (event) => {
  event.preventDefault();
  button.closest('dialog')?.close();
}));
document.querySelector('#network-data-preset').addEventListener('change', (event) => {
  if (event.target.value) document.querySelector('#network-form input[name="dataCidr"]').value = event.target.value;
});

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
    const reachabilityType = event.currentTarget.elements.reachabilityType.value;
    const publishes = reachabilityType === 'public' || reachabilityType === 'ix';
    const result = await api(`/api/v1/nodes/${form.get('nodeId')}`, {
      method: 'PATCH',
      body: JSON.stringify({
        name: form.get('name'), dataIp: form.get('dataIp'), reachabilityType,
        controlEndpoint: publishes ? event.currentTarget.elements.controlEndpoint.value : '',
        controlListenPort: Number(form.get('controlListenPort')),
        dataEndpoint: publishes ? event.currentTarget.elements.dataEndpoint.value : '',
        dataListenPort: Number(form.get('dataListenPort')),
        canRelay: form.get('canRelay') === 'on',
      }),
    });
    document.querySelector('#node-dialog').close(); await load();
    const deferred = result.version?.nodes?.filter((node) => !node.required).length || 0;
    toast(deferred ? `业务地址开始切换；${deferred} 台离线节点将在恢复后自动追赶` : '节点地址已校验并生成新配置版本');
  } catch (reason) { error.textContent = reason.message; }
});
document.querySelector('#delete-node').addEventListener('click', deleteSelectedNode);
document.querySelector('#node-form [name="reachabilityType"]').addEventListener('change', (event) => {
  syncNodePublicFields(event.currentTarget.form);
});

for (const input of document.querySelectorAll('#connection-form [name="nodeAAddress"], #connection-form [name="nodeBAddress"]')) {
  input.addEventListener('input', (event) => syncConnectionEndpointInputs(event.currentTarget.form));
}

document.querySelector('#connection-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (event.submitter?.value === 'cancel') return document.querySelector('#connection-dialog').close();
  const form = new FormData(event.currentTarget);
  const error = event.currentTarget.querySelector('[data-form-error]');
  error.textContent = '';
  const nodeAAddress = String(form.get('nodeAAddress') || '').trim();
  const nodeBAddress = String(form.get('nodeBAddress') || '').trim();
  if (!nodeAAddress && !nodeBAddress) {
    error.textContent = '至少填写一个节点可被对方访问的 IP 或域名';
    return;
  }
  try {
    const result = await api(`/api/v1/networks/${state.networkId}/links`, {
      method: 'POST',
      body: JSON.stringify({
        nodeAId: form.get('nodeAId'),
        nodeBId: form.get('nodeBId'),
        nodeAAddress,
        nodeBAddress,
        nodeAPort: nodeAAddress ? Number(form.get('nodeAPort')) : undefined,
        nodeBPort: nodeBAddress ? Number(form.get('nodeBPort')) : undefined,
        priority: Number(form.get('priority')),
      }),
    });
    document.querySelector('#connection-dialog').close();
    state.selectedNodeIds = [];
    await load();
    toast(result.validationProgress?.requested === 1
      ? '正在探测唯一填写的方向；成功后即建立连接'
      : '正在执行双向探测；任一方向成功即可建链，失败方向不会保存');
  } catch (reason) { error.textContent = reason.message; }
});

setInterval(() => {
  document.querySelector('#clock').textContent = `${new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date())} CST`;
}, 1000);

setInterval(async () => {
  if (!state.token || !['topology', 'path-detail'].includes(state.view) || state.runtimeRefreshInFlight) return;
  if ((state.view === 'topology' && (state.selectedNodeIds.length || state.graph.drag)) || document.querySelector('dialog[open]')) return;
  if (state.view === 'path-detail' && document.activeElement?.matches('.path-weight')) return;
  state.runtimeRefreshInFlight = true;
  try {
    if (state.view === 'path-detail') {
      const route = pathDetailRoute();
      if (route.sourceId && route.targetId) {
        await loadPathDetail(route.sourceId, route.targetId);
        render();
      }
    } else await load();
  } catch {}
  finally { state.runtimeRefreshInFlight = false; }
}, 5000);

if (state.token) authenticate(state.token).catch(() => document.querySelector('#login-dialog').showModal());
else document.querySelector('#login-dialog').showModal();
