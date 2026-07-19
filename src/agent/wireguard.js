import { execFile } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

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
    lines.push(`AllowedIPs = ${peer.allowedIps.join(', ')}`);
    if (peer.persistentKeepalive) lines.push(`PersistentKeepalive = ${peer.persistentKeepalive}`);
  }
  return `${lines.join('\n')}\n`;
}

export class WireGuardManager {
  constructor(options) {
    this.dataDir = options.dataDir;
    this.privateKey = options.privateKey;
    this.applyNetwork = Boolean(options.applyNetwork);
    this.wireguardDir = options.wireguardDir ?? '/etc/wireguard';
  }

  stagedFile(version) {
    return join(this.dataDir, 'staged', String(version), 'pw-data.conf');
  }

  activeFile() {
    return join(this.dataDir, 'active', 'pw-data.conf');
  }

  async prepare(version, config) {
    if (!config?.data?.interfaceName || !Array.isArray(config.data.peers)) {
      throw new Error('配置缺少数据面接口或 Peer');
    }
    const rendered = renderWireGuardConfig(config.data, this.privateKey);
    const filename = this.stagedFile(version);
    atomicWrite(filename, rendered);
    if (this.applyNetwork) {
      await execFileAsync('wg-quick', ['strip', filename], { timeout: 10_000 });
      await execFileAsync('ip', ['route', 'show'], { timeout: 10_000 });
    }
    return { filename, peers: config.data.peers.length, dryRun: !this.applyNetwork };
  }

  async activate(version) {
    const staged = this.stagedFile(version);
    if (!existsSync(staged)) throw new Error(`配置版本 ${version} 尚未准备`);
    mkdirSync(join(this.dataDir, 'active'), { recursive: true });
    const previous = this.activeFile();
    if (existsSync(previous)) copyFileSync(previous, `${previous}.previous`);
    copyFileSync(staged, previous);
    chmodSync(previous, 0o600);

    if (this.applyNetwork) {
      const target = join(this.wireguardDir, 'pw-data.conf');
      mkdirSync(this.wireguardDir, { recursive: true });
      copyFileSync(staged, target);
      chmodSync(target, 0o600);
      try {
        await execFileAsync('wg-quick', ['down', 'pw-data'], { timeout: 20_000 });
      } catch (error) {
        if (!String(error.stderr ?? '').includes('is not a WireGuard interface')) throw error;
      }
      try {
        await execFileAsync('wg-quick', ['up', 'pw-data'], { timeout: 20_000 });
      } catch (error) {
        const backup = `${previous}.previous`;
        if (existsSync(backup)) {
          copyFileSync(backup, target);
          await execFileAsync('wg-quick', ['up', 'pw-data'], { timeout: 20_000 }).catch(() => {});
        }
        throw error;
      }
    }
    return { version, activeFile: previous, dryRun: !this.applyNetwork };
  }

  currentConfig() {
    return existsSync(this.activeFile()) ? readFileSync(this.activeFile(), 'utf8') : null;
  }
}
