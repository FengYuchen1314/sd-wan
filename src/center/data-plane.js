import { join } from 'node:path';
import { WireGuardManager } from '../agent/wireguard.js';

export class CenterDataPlane {
  constructor(service, options = {}) {
    this.service = service;
    this.dataDir = options.dataDir;
    this.applyNetwork = Boolean(options.applyNetwork);
    this.wireguardDir = options.wireguardDir;
    this.runtimeDir = options.runtimeDir;
    this.runtimes = new Map();
    this.running = false;
  }

  runtimeFor(center) {
    let runtime = this.runtimes.get(center.node.id);
    if (runtime) return runtime;
    const nodeDataDir = join(this.dataDir, 'center-data-plane', center.node.id);
    runtime = {
      currentVersion: 0,
      preparedVersion: 0,
      manager: new WireGuardManager({
        dataDir: nodeDataDir,
        privateKey: center.dataPrivateKey,
        applyNetwork: this.applyNetwork,
        ...(this.wireguardDir ? { wireguardDir: this.wireguardDir } : {}),
        ...(this.runtimeDir ? { runtimeDir: this.runtimeDir } : {}),
      }),
    };
    this.runtimes.set(center.node.id, runtime);
    return runtime;
  }

  async reconcileCenter(center) {
    const runtime = this.runtimeFor(center);
    const desired = this.service.getDesiredConfig(center.node.id, runtime.currentVersion);
    if (!desired) return;

    if (desired.phase === 'prepare') {
      if (runtime.preparedVersion === desired.version) return;
      try {
        await runtime.manager.prepare(desired.version, desired.config);
        runtime.preparedVersion = desired.version;
        this.service.reportConfig(center.node.id, desired.versionId, 'prepared');
      } catch (error) {
        this.service.reportConfig(center.node.id, desired.versionId, 'prepared', error.message);
      }
      return;
    }

    if (desired.phase === 'activate' && runtime.currentVersion !== desired.version) {
      try {
        if (runtime.preparedVersion !== desired.version) {
          await runtime.manager.prepare(desired.version, desired.config);
          runtime.preparedVersion = desired.version;
        }
        await runtime.manager.activate(desired.version);
        runtime.currentVersion = desired.version;
        this.service.reportConfig(center.node.id, desired.versionId, 'activated');
      } catch (error) {
        this.service.reportConfig(center.node.id, desired.versionId, 'activated', error.message);
      }
    }
  }

  async tick() {
    if (this.running) return;
    this.running = true;
    try {
      for (const center of this.service.listLocalCenters()) await this.reconcileCenter(center);
    } finally {
      this.running = false;
    }
  }

  runtimeInfo() {
    return {
      applyNetwork: this.applyNetwork,
      centers: this.runtimes.size,
    };
  }
}
