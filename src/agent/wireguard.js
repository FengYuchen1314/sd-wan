import { execFile } from 'node:child_process';
import { X_OK } from 'node:constants';
import { createHash } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { accessSync, chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

function sendWireGuardWarmup(address) {
  return new Promise((resolve) => {
    const socket = createSocket('udp4');
    let settled = false;
    let timeout;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      try { socket.close(); } catch {}
      resolve();
    };
    timeout = setTimeout(finish, 1_000);
    socket.once('error', finish);
    socket.send(Buffer.from('pathweaver-warmup'), 9, address, finish);
  });
}

export function dataPlaneWarmupTargets(config) {
  return [...new Set((config?.data?.peers ?? [])
    .filter((peer) => peer.endpoint)
    .map((peer) => String(peer.probeIp || peer.allowedIps?.find((cidr) => cidr.endsWith('/32')) || '').replace(/\/32$/, ''))
    .filter((address) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)))];
}

function tunnelName(policyId, pathId, targetNodeId) {
  const suffix = createHash('sha256').update(`${policyId}:${pathId}:${targetNodeId}`).digest('hex').slice(0, 11);
  return `pwm${suffix}`;
}

function normalizedKernelWeights(paths) {
  const maximum = Math.max(...paths.map((path) => Number(path.effectiveWeight || 0)), 1);
  return paths.map((path) => ({
    ...path,
    kernelWeight: maximum <= 256
      ? Number(path.effectiveWeight)
      : Math.max(1, Math.round((Number(path.effectiveWeight) / maximum) * 256)),
  }));
}

export function buildMultipathPlan(config) {
  const interfaceName = String(config?.data?.interfaceName || '');
  const mtu = Number(config?.data?.mtu || 1380);
  if (!interfaceName) throw new Error('多路径配置缺少 WireGuard 接口名称');
  const policies = Array.isArray(config?.multipathPolicies) ? config.multipathPolicies : [];
  const aliases = new Set();
  const tunnels = [];
  const routes = new Map();
  for (const policy of policies.filter((item) => item.mode === 'weighted')) {
    const activePaths = normalizedKernelWeights((policy.paths ?? []).filter((path) =>
      path.available !== false && Number(path.effectiveWeight) > 0));
    for (const path of activePaths) {
      if (!path.localTunnelIp || !path.remoteTunnelIp) throw new Error(`加权路径 ${path.pathId} 缺少隧道地址`);
      const name = tunnelName(policy.policyId, path.pathId, policy.targetNodeId);
      aliases.add(String(path.localTunnelIp));
      tunnels.push({
        name,
        policyId: policy.policyId,
        pathId: path.pathId,
        targetNodeId: policy.targetNodeId,
        interfaceName,
        local: String(path.localTunnelIp),
        remote: String(path.remoteTunnelIp),
        mtu: Math.max(576, mtu - 20),
        weight: path.kernelWeight,
      });
      for (const destination of policy.routeCidrs ?? []) {
        const members = routes.get(destination) ?? [];
        members.push({ name, weight: path.kernelWeight, pathId: path.pathId });
        routes.set(destination, members);
      }
    }
  }
  return {
    interfaceName,
    aliases: [...aliases].sort(),
    tunnels,
    routes: [...routes.entries()].map(([destination, members]) => ({ destination, members })),
  };
}

function parseIPv4Cidr(value) {
  const [address, prefixText] = String(value || '').split('/');
  const parts = address?.split('.').map(Number);
  const prefix = Number(prefixText);
  if (parts?.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const ip = parts.reduce((total, part) => ((total * 256) + part) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (ip & mask) >>> 0, broadcast: ((ip & mask) | (~mask >>> 0)) >>> 0 };
}

function overlaps(rangeA, rangeB) {
  return rangeA && rangeB && !(rangeA.broadcast < rangeB.network || rangeB.broadcast < rangeA.network);
}

export function detectLocalNetworkConflicts(candidateCidr, addresses = [], routes = [], interfaceName = 'pw-data') {
  const candidate = parseIPv4Cidr(candidateCidr);
  if (!candidate) throw new Error(`业务网段 ${candidateCidr} 无效`);
  const conflicts = [];
  for (const item of addresses) {
    if (item.ifname === interfaceName || item.ifname === 'lo') continue;
    for (const address of item.addr_info ?? []) {
      if (address.family !== 'inet') continue;
      const localRange = parseIPv4Cidr(`${address.local}/${address.prefixlen}`);
      if (overlaps(candidate, localRange)) conflicts.push({ type: 'interface', interface: item.ifname, cidr: `${address.local}/${address.prefixlen}` });
    }
  }
  for (const route of routes) {
    if (!route.dst || route.dst === 'default' || route.dev === interfaceName) continue;
    const routeRange = parseIPv4Cidr(route.dst.includes('/') ? route.dst : `${route.dst}/32`);
    if (overlaps(candidate, routeRange)) conflicts.push({ type: 'route', interface: route.dev ?? null, cidr: route.dst });
  }
  return conflicts;
}

function atomicWrite(filename, content, mode = 0o600) {
  mkdirSync(join(filename, '..'), { recursive: true });
  const temporary = `${filename}.tmp`;
  writeFileSync(temporary, content, { mode });
  chmodSync(temporary, mode);
  renameSync(temporary, filename);
}

export function renderWireGuardConfig(config, privateKey) {
  const lines = [
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${config.address}`,
    `ListenPort = ${config.listenPort}`,
    `MTU = ${config.mtu}`,
    'Table = auto',
  ];

  for (const peer of config.peers) {
    if (!peer.publicKey) throw new Error(`Peer ${peer.name || peer.nodeId} 缺少 WireGuard 公钥`);
    lines.push('', '[Peer]', `# ${peer.name || peer.nodeId}`, `PublicKey = ${peer.publicKey}`);
    if (peer.endpoint) lines.push(`Endpoint = ${peer.endpoint}`);
    if (peer.allowedIps?.length) lines.push(`AllowedIPs = ${peer.allowedIps.join(', ')}`);
    if (peer.persistentKeepalive) lines.push(`PersistentKeepalive = ${peer.persistentKeepalive}`);
  }
  return `${lines.join('\n')}\n`;
}

export class WireGuardManager {
  constructor(options) {
    this.dataDir = options.dataDir;
    this.privateKey = options.privateKey;
    this.applyNetwork = Boolean(options.applyNetwork);
    this.wireguardDir = options.wireguardDir ?? join(this.dataDir, 'wireguard');
    this.runtimeDir = options.runtimeDir ?? process.env.SDWAN_WIREGUARD_RUNTIME_DIR ?? '/opt/pathweaver-agent/runtime/wireguard-current';
    this.wgPath = join(this.runtimeDir, 'bin', 'wg');
    this.wgQuickPath = join(this.runtimeDir, 'bin', 'wg-quick');
    this.commandEnvironment = {
      ...process.env,
      PATH: `${join(this.runtimeDir, 'bin')}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
      PATHWEAVER_WG_QUICK_NO_AUTO_SU: '1',
    };
    this.preparedInterfaces = new Map();
    this.preparedConfigs = new Map();
    this.activeConfig = null;
    this.activatedAt = 0;
    this.linkHealthProbeIntervalMs = Math.max(1_000, Number(options.linkHealthProbeIntervalMs ?? 20_000));
    this.linkHealthCache = null;
    this.linkHealthCheckedAt = 0;
    this.activeMultipathPlan = { aliases: [], tunnels: [], routes: [] };
    this.warmupSender = options.warmupSender ?? sendWireGuardWarmup;
  }

  runtimeInfo() {
    const manifestFile = join(this.runtimeDir, 'runtime.json');
    if (!existsSync(manifestFile)) return null;
    try {
      const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
      return manifest?.managedBy === 'pathweaver' && Number(manifest.schemaVersion) === 1 ? manifest : null;
    } catch {
      return null;
    }
  }

  assertPrivateRuntime() {
    const runtime = this.runtimeInfo();
    if (!runtime) throw new Error(`PathWeaver 私有 WireGuard 运行时缺失或清单无效：${this.runtimeDir}`);
    for (const binary of [this.wgPath, this.wgQuickPath]) {
      try { accessSync(binary, X_OK); } catch { throw new Error(`PathWeaver 私有 WireGuard 程序不可执行：${binary}`); }
    }
    return runtime;
  }

  runWgQuick(args, timeout) {
    return execFileAsync(this.wgQuickPath, args, { timeout, env: this.commandEnvironment });
  }

  runIp(args, timeout = 10_000) {
    return execFileAsync('ip', args, { timeout, env: this.commandEnvironment });
  }

  runSystem(command, args, timeout = 10_000) {
    return execFileAsync(command, args, { timeout, env: this.commandEnvironment });
  }

  async warmDataPlane(config) {
    const targets = dataPlaneWarmupTargets(config);
    await Promise.allSettled(targets.map((address) => this.warmupSender(address)));
    return targets;
  }

  async ignoreMissing(operation) {
    try { await operation; } catch (error) {
      const detail = `${error.message || ''}\n${error.stderr || ''}`;
      if (!/Cannot find device|No such (?:process|file or directory)|Cannot assign requested address|not found/i.test(detail)) throw error;
    }
  }

  async cleanupMultipathPlan(plan = this.activeMultipathPlan) {
    for (const route of plan?.routes ?? []) {
      await this.ignoreMissing(this.runIp(['route', 'del', route.destination]));
    }
    for (const tunnel of plan?.tunnels ?? []) {
      await this.ignoreMissing(this.runIp(['link', 'delete', 'dev', tunnel.name]));
    }
    for (const alias of plan?.aliases ?? []) {
      await this.ignoreMissing(this.runIp(['address', 'del', `${alias}/32`, 'dev', 'lo']));
    }
  }

  async applyMultipathPlan(config) {
    const plan = buildMultipathPlan(config);
    if (!this.applyNetwork) return plan;
    for (const alias of plan.aliases) {
      await this.runIp(['address', 'replace', `${alias}/32`, 'dev', 'lo']);
    }
    for (const tunnel of plan.tunnels) {
      await this.ignoreMissing(this.runIp(['link', 'delete', 'dev', tunnel.name]));
      await this.runIp([
        'tunnel', 'add', tunnel.name, 'mode', 'ipip',
        'local', tunnel.local, 'remote', tunnel.remote,
        'dev', tunnel.interfaceName, 'ttl', '64', 'nopmtudisc',
      ]);
      await this.runIp(['link', 'set', 'dev', tunnel.name, 'mtu', String(tunnel.mtu), 'up']);
    }
    for (const route of plan.routes) {
      if (!route.members.length) continue;
      const args = ['route', 'replace', route.destination, 'proto', 'static', 'scope', 'link'];
      if (route.members.length === 1) {
        args.push('dev', route.members[0].name);
      } else {
        for (const member of route.members) {
          args.push('nexthop', 'dev', member.name, 'weight', String(member.weight));
        }
      }
      await this.runIp(args);
    }
    return plan;
  }

  async assertDataCidrAvailable(dataConfig) {
    if (!dataConfig.networkCidr) return;
    const [{ stdout: addressJson }, { stdout: routeJson }] = await Promise.all([
      execFileAsync('ip', ['-json', 'address', 'show'], { timeout: 10_000, env: this.commandEnvironment }),
      execFileAsync('ip', ['-json', 'route', 'show'], { timeout: 10_000, env: this.commandEnvironment }),
    ]);
    const conflicts = detectLocalNetworkConflicts(
      dataConfig.networkCidr,
      JSON.parse(addressJson),
      JSON.parse(routeJson),
      dataConfig.interfaceName,
    );
    if (conflicts.length) {
      const details = conflicts.slice(0, 4).map((conflict) => `${conflict.type === 'interface' ? '接口' : '路由'} ${conflict.interface || '-'} ${conflict.cidr}`).join('；');
      throw new Error(`业务网段 ${dataConfig.networkCidr} 已被本机网络使用：${details}`);
    }
  }

  stagedFile(version, interfaceName = 'pw-data') {
    return join(this.dataDir, 'staged', String(version), `${interfaceName}.conf`);
  }

  activeFile(interfaceName = 'pw-data') {
    return join(this.dataDir, 'active', `${interfaceName}.conf`);
  }

  async prepare(version, config) {
    if (!config?.data?.interfaceName || !Array.isArray(config.data.peers)) {
      throw new Error('配置缺少数据面接口或 Peer');
    }
    const rendered = renderWireGuardConfig(config.data, this.privateKey);
    buildMultipathPlan(config);
    const interfaceName = config.data.interfaceName;
    const filename = this.stagedFile(version, interfaceName);
    this.preparedInterfaces.set(Number(version), interfaceName);
    this.preparedConfigs.set(Number(version), structuredClone(config));
    atomicWrite(filename, rendered);
    if (this.applyNetwork) {
      this.assertPrivateRuntime();
      await this.assertDataCidrAvailable(config.data);
      await this.runWgQuick(['strip', filename], 10_000);
      await execFileAsync('ip', ['route', 'show'], { timeout: 10_000, env: this.commandEnvironment });
    }
    return { filename, peers: config.data.peers.length, dryRun: !this.applyNetwork };
  }

  async activate(version) {
    const interfaceName = this.preparedInterfaces.get(Number(version)) ?? 'pw-data';
    const staged = this.stagedFile(version, interfaceName);
    if (!existsSync(staged)) throw new Error(`配置版本 ${version} 尚未准备`);
    mkdirSync(join(this.dataDir, 'active'), { recursive: true });
    const previous = this.activeFile(interfaceName);
    if (existsSync(previous)) copyFileSync(previous, `${previous}.previous`);
    copyFileSync(staged, previous);
    chmodSync(previous, 0o600);

    const previousConfig = this.activeConfig ? structuredClone(this.activeConfig) : null;
    const previousPlan = this.activeMultipathPlan;
    const nextConfig = this.preparedConfigs.get(Number(version));
    const nextPlan = buildMultipathPlan(nextConfig);
    if (this.applyNetwork) {
      this.assertPrivateRuntime();
      const target = join(this.wireguardDir, `${interfaceName}.conf`);
      mkdirSync(this.wireguardDir, { recursive: true });
      await this.cleanupMultipathPlan(previousPlan);
      if (existsSync(target)) {
        try {
          await this.runWgQuick(['down', target], 20_000);
        } catch (error) {
          if (!String(error.stderr ?? '').includes('is not a WireGuard interface')) throw error;
        }
      }
      copyFileSync(staged, target);
      chmodSync(target, 0o600);
      try {
        await this.runWgQuick(['up', target], 20_000);
        this.activeMultipathPlan = await this.applyMultipathPlan(nextConfig);
        await this.warmDataPlane(nextConfig);
      } catch (error) {
        await this.cleanupMultipathPlan(nextPlan).catch(() => {});
        const backup = `${previous}.previous`;
        if (existsSync(backup)) {
          await this.runWgQuick(['down', target], 20_000).catch(() => {});
          copyFileSync(backup, target);
          await this.runWgQuick(['up', target], 20_000).catch(() => {});
          if (previousConfig) {
            this.activeMultipathPlan = await this.applyMultipathPlan(previousConfig).catch(() => previousPlan);
          }
        }
        throw error;
      }
    } else {
      this.activeMultipathPlan = nextPlan;
    }
    this.activeConfig = this.preparedConfigs.get(Number(version)) ?? null;
    this.activatedAt = Date.now();
    this.linkHealthCache = null;
    this.linkHealthCheckedAt = 0;
    return {
      version,
      activeFile: previous,
      dryRun: !this.applyNetwork,
      multipathTunnels: this.activeMultipathPlan.tunnels.length,
      multipathRoutes: this.activeMultipathPlan.routes.length,
    };
  }

  async linkHealth({ staleAfterMs = 180_000, graceMs = 90_000, force = false } = {}) {
    const nowMs = Date.now();
    if (!force && this.linkHealthCache && nowMs - this.linkHealthCheckedAt < this.linkHealthProbeIntervalMs) {
      return this.linkHealthCache;
    }
    const checkedAt = new Date().toISOString();
    const links = this.activeConfig?.data?.links ?? [];
    if (!this.applyNetwork || !this.activeConfig || !links.length) {
      const result = { available: false, checkedAt, links: [], failedLinkIds: [] };
      this.linkHealthCache = result;
      this.linkHealthCheckedAt = nowMs;
      return result;
    }
    this.assertPrivateRuntime();
    const interfaceName = this.activeConfig.data.interfaceName || 'pw-data';
    const { stdout } = await execFileAsync(
      this.wgPath,
      ['show', interfaceName, 'latest-handshakes'],
      { timeout: 10_000, env: this.commandEnvironment },
    );
    const handshakes = new Map(String(stdout || '').trim().split(/\r?\n/).filter(Boolean).map((line) => {
      const [publicKey, timestamp] = line.trim().split(/\s+/);
      return [publicKey, Number(timestamp || 0) * 1000];
    }));
    const inGrace = nowMs - this.activatedAt < graceMs;
    const reports = links.map((link) => {
      const handshakeAt = handshakes.get(link.peerPublicKey) || 0;
      const status = handshakeAt > 0 && nowMs - handshakeAt <= staleAfterMs
        ? 'reachable'
        : inGrace ? 'unknown' : 'unreachable';
      return {
        linkId: link.linkId,
        peerNodeId: link.peerNodeId,
        status,
        handshakeAt: handshakeAt ? new Date(handshakeAt).toISOString() : null,
      };
    });
    const result = {
      available: true,
      checkedAt,
      links: reports,
      failedLinkIds: reports.filter((report) => report.status === 'unreachable').map((report) => report.linkId),
    };
    this.linkHealthCache = result;
    this.linkHealthCheckedAt = nowMs;
    return result;
  }

  currentConfig(interfaceName = 'pw-data') {
    return existsSync(this.activeFile(interfaceName)) ? readFileSync(this.activeFile(interfaceName), 'utf8') : null;
  }
}
