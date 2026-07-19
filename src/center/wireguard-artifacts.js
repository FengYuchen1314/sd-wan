import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const WIREGUARD_RUNTIME = Object.freeze({
  schemaVersion: 1,
  toolsVersion: '1.0.20260223',
  files: Object.freeze([
    Object.freeze({
      name: 'wireguard-tools-1.0.20260223.tar.xz',
      sha256: 'af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf',
      sourceUrl: 'https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-1.0.20260223.tar.xz',
      contentType: 'application/x-xz',
    }),
  ]),
});

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

export function wireGuardRuntimeManifest() {
  return {
    schemaVersion: WIREGUARD_RUNTIME.schemaVersion,
    toolsVersion: WIREGUARD_RUNTIME.toolsVersion,
    files: WIREGUARD_RUNTIME.files.map(({ name, sha256: digest, contentType }) => ({
      name,
      sha256: digest,
      contentType,
      url: `/artifacts/wireguard/${name}`,
    })),
  };
}

export class WireGuardArtifactStore {
  constructor(cacheDir, options = {}) {
    this.cacheDir = cacheDir;
    this.catalog = options.catalog ?? WIREGUARD_RUNTIME.files;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.pending = new Map();
    mkdirSync(cacheDir, { recursive: true });
  }

  descriptor(name) {
    const descriptor = this.catalog.find((item) => item.name === name);
    if (!descriptor) throw new Error('WireGuard 运行时制品不存在');
    return descriptor;
  }

  readVerified(filename, descriptor) {
    if (!existsSync(filename)) return null;
    const content = readFileSync(filename);
    if (sha256(content) === descriptor.sha256) return content;
    unlinkSync(filename);
    return null;
  }

  load(name) {
    if (this.pending.has(name)) return this.pending.get(name);
    const operation = this.loadOnce(name).finally(() => this.pending.delete(name));
    this.pending.set(name, operation);
    return operation;
  }

  async loadOnce(name) {
    const descriptor = this.descriptor(name);
    const filename = join(this.cacheDir, descriptor.name);
    const cached = this.readVerified(filename, descriptor);
    if (cached) return { descriptor, content: cached, cached: true };

    const response = await this.fetchImpl(descriptor.sourceUrl, { signal: AbortSignal.timeout(60_000) });
    if (!response.ok) throw new Error(`下载 WireGuard 运行时失败：HTTP ${response.status}`);
    const content = Buffer.from(await response.arrayBuffer());
    if (sha256(content) !== descriptor.sha256) throw new Error('WireGuard 运行时制品 SHA-256 校验失败');
    const temporary = `${filename}.${process.pid}.tmp`;
    writeFileSync(temporary, content, { mode: 0o644 });
    renameSync(temporary, filename);
    return { descriptor, content, cached: false };
  }
}
