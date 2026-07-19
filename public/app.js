const state = {
  token: sessionStorage.getItem('pathweaver-token') || '',
  dashboard: null,
  networkId: localStorage.getItem('pathweaver-network') || '',
  topology: null,
  configurations: [],
  view: location.hash.slice(1) || 'overview',
  topologyDraft: [],
  selectedNodeIds: [],
  joinResult: null,
  runtimeRefreshInFlight: false,
};

const content = document.querySelector('#content');
const networkSelect = document.querySelector('#network-select');
const titles = {
  overview: ['NETWORK OVERVIEW', '网络总览'],
  nodes: ['NODE ADDRESSING', '节点与地址'],
  topology: ['ROUTE CONSTRAINTS', '数据拓扑'],
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
  document.querySelectorAll('[data-nav]').forEach((link) => link.classList.toggle('active', link.dataset.nav === state.view));
  const renderers = { overview: renderOverview, nodes: renderNodes, topology: renderTopology, join: renderJoin, rollouts: renderRollouts };
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

function graphLayout(nodes) {
  const nodeWidth = 150;
  const columnStep = 175;
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const levels = new Map();
  function resolveLevel(node, trail = new Set()) {
    if (levels.has(node.id)) return levels.get(node.id);
    if (!node.parentId || !nodeById.has(node.parentId) || trail.has(node.id)) {
      levels.set(node.id, 0);
      return 0;
    }
    trail.add(node.id);
    const level = resolveLevel(nodeById.get(node.parentId), trail) + 1;
    levels.set(node.id, level);
    return level;
  }
  nodes.forEach((node) => resolveLevel(node));
  const grouped = new Map();
  for (const node of nodes) {
    const level = levels.get(node.id);
    grouped.set(level, [...(grouped.get(level) || []), node]);
  }
  const maxLevel = Math.max(0, ...grouped.keys());
  const maxRows = Math.max(1, ...[...grouped.values()].map((group) => group.length));
  const width = Math.max(720, 80 + maxLevel * columnStep + nodeWidth);
  const height = Math.max(520, 120 + maxRows * 116);
  const positions = new Map();
  for (const [level, group] of grouped.entries()) {
    group.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));
    const usedHeight = (group.length - 1) * 112;
    const startY = Math.max(56, (height - usedHeight - 76) / 2);
    group.forEach((node, index) => positions.set(node.id, {
      x: 40 + level * columnStep,
      y: startY + index * 112,
      level,
    }));
  }
  return { width, height, positions, nodeWidth };
}

function graphPath(from, to, nodeWidth) {
  const startX = from.x < to.x ? from.x + nodeWidth : from.x;
  const endX = from.x < to.x ? to.x : to.x + nodeWidth;
  const startY = from.y + 38;
  const endY = to.y + 38;
  const distance = Math.abs(to.level - from.level);
  if (distance > 1) {
    const bend = Math.min(110, 55 + distance * 16);
    const direction = startY < 105 && endY < 105 ? 1 : -1;
    return {
      d: `M ${startX} ${startY} C ${startX + (endX - startX) * .32} ${startY + bend * direction}, ${endX - (endX - startX) * .32} ${endY + bend * direction}, ${endX} ${endY}`,
      labelX: (startX + endX) / 2,
      labelY: (startY + endY) / 2 + bend * direction * .72,
    };
  }
  const middle = (startX + endX) / 2;
  return {
    d: `M ${startX} ${startY} C ${middle} ${startY}, ${middle} ${endY}, ${endX} ${endY}`,
    labelX: middle,
    labelY: (startY + endY) / 2 - 9,
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
  const layout = graphLayout(nodes);
  const edges = state.topology.links.map((link) => {
    const from = layout.positions.get(link.upstreamId);
    const to = layout.positions.get(link.downstreamId);
    if (!from || !to) return '';
    const path = graphPath(from, to, layout.nodeWidth);
    const status = link.validationStatus || 'active';
    const label = linkStatusText(link);
    return `<path class="graph-edge ${escapeHtml(status)}" d="${path.d}"></path>${label ? `<text class="graph-edge-label" x="${path.labelX}" y="${path.labelY}">${escapeHtml(label)}</text>` : ''}`;
  }).join('');
  const nodeMarkup = nodes.map((node, index) => {
    const position = layout.positions.get(node.id);
    const selected = state.selectedNodeIds.includes(node.id);
    const parent = node.parentId ? nodeById.get(node.parentId) : null;
    const offline = !node.isCenter && node.status !== 'online';
    const routeMeta = parent ? `初始上游 · ${escapeHtml(parent.name)}` : '控制根节点';
    return `<foreignObject x="${position.x}" y="${position.y}" width="${layout.nodeWidth}" height="80"><button class="graph-node svg-node ${node.isCenter ? 'center' : ''} ${offline ? 'offline' : ''}" data-node-id="${node.id}" aria-pressed="${selected}">
      <span class="graph-node-head"><strong>${escapeHtml(node.name)}</strong><span class="graph-node-index">${String(index + 1).padStart(2, '0')}</span></span>
      <span class="graph-node-address">${escapeHtml(node.dataIp)}</span>
      <span class="graph-node-meta">${offline ? 'Agent 离线 · ' : ''}${routeMeta}</span>
    </button></foreignObject>`;
  }).join('');
  return `<div class="graph-surface"><svg class="topology-svg" width="${layout.width}" height="${layout.height}" viewBox="0 0 ${layout.width} ${layout.height}" role="img" aria-label="节点数据连接拓扑">${edges}${nodeMarkup}</svg></div>`;
}

function renderTopology() {
  const valid = state.topology.validation?.fullyReachable;
  const selected = state.selectedNodeIds.map((id) => state.topology.nodes.find((node) => node.id === id)).filter(Boolean);
  const waiting = state.topology.links.filter((link) => link.validationStatus === 'preparing').length;
  const probing = state.topology.links.filter((link) => link.validationStatus === 'probing').length;
  const validationText = [
    waiting ? `${waiting} 条等待 Agent` : '',
    probing ? `${probing} 条正在双向探测` : '',
  ].filter(Boolean).join(' · ') || '选择两个未直连节点后建立连接';
  const selectionText = selected.length === 0
    ? '点击画布中的两个节点'
    : selected.length === 1
      ? `已选择 ${selected[0].name}，再选一个节点`
      : `${selected[0].name} ↔ ${selected[1].name}`;
  return `<article class="card">
    <div class="card-head"><div><h2>可视化拓扑编辑</h2><p>节点位置按首次接入路径固定；新增通路不会改变原有布局</p></div><span class="status ${valid ? 'active' : 'failed'}">${valid ? '全网可达' : '需要修复'}</span></div>
    <div class="graph-toolbar">
      <div class="graph-toolbar-main"><span class="selection-count">${selected.length}/2</span><span class="selection-copy"><strong>${escapeHtml(selectionText)}</strong><small>${validationText}</small></span></div>
      <div class="graph-actions"><button class="button ghost" id="clear-node-selection" ${selected.length ? '' : 'disabled'}>取消选择</button><button class="button primary" id="connect-selected" ${selected.length === 2 ? '' : 'disabled'}>建立连接</button></div>
    </div>
    ${renderTopologyGraph()}
    <div class="graph-legend"><span>已验证通路</span><span class="waiting">等待 Agent</span><span class="probing">正在双向探测</span><span class="failed">验证失败或超时</span><span style="margin-left:auto">点击节点进行选择</span></div>
  </article>`;
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
  document.querySelectorAll('.graph-node').forEach((button) => button.addEventListener('click', () => {
    const id = button.dataset.nodeId;
    if (state.selectedNodeIds.includes(id)) state.selectedNodeIds = state.selectedNodeIds.filter((nodeId) => nodeId !== id);
    else if (state.selectedNodeIds.length < 2) state.selectedNodeIds = [...state.selectedNodeIds, id];
    else state.selectedNodeIds = [state.selectedNodeIds[1], id];
    render();
  }));
  document.querySelector('#clear-node-selection')?.addEventListener('click', () => { state.selectedNodeIds = []; render(); });
  document.querySelector('#connect-selected')?.addEventListener('click', openConnectionDialog);
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

window.addEventListener('hashchange', () => {
  state.view = location.hash.slice(1) || 'overview'; render();
});
document.querySelector('#refresh').addEventListener('click', () => load().then(() => toast('状态已刷新')).catch((error) => toast(error.message, 'error')));
document.querySelector('#lock-console').addEventListener('click', () => {
  sessionStorage.removeItem('pathweaver-token'); state.token = ''; document.querySelector('#login-dialog').showModal();
});
networkSelect.addEventListener('change', () => { state.networkId = networkSelect.value; state.joinResult = null; load().catch((error) => toast(error.message, 'error')); });
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
  if (state.selectedNodeIds.length || document.querySelector('dialog[open]')) return;
  state.runtimeRefreshInFlight = true;
  try { await load(); } catch {}
  finally { state.runtimeRefreshInFlight = false; }
}, 5000);

if (state.token) authenticate(state.token).catch(() => document.querySelector('#login-dialog').showModal());
else document.querySelector('#login-dialog').showModal();
