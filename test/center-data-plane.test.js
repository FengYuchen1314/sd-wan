import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from '../src/center/database.js';
import { CenterDataPlane } from '../src/center/data-plane.js';
import { ControlService } from '../src/center/service.js';

test('中心节点使用内置数据面参与配置准备、冲突检查与激活', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'pathweaver-center-'));
  const database = new Database(':memory:');
  try {
    const service = new ControlService(database, {
      publicUrl: 'http://center.example:8787',
      manageLocalCenters: true,
    });
    const network = service.createNetwork({
      name: '中心运行时测试',
      dataCidr: '10.90.0.0/24',
      controlCidr: '10.91.0.0/24',
      listenPort: 19801,
      mtu: 1380,
    });
    const initial = service.listConfigurations(network.id)[0];
    assert.equal(initial.status, 'preparing');

    const runtime = new CenterDataPlane(service, { dataDir: directory, applyNetwork: false });
    await runtime.tick();
    assert.equal(service.getConfiguration(initial.id).status, 'activating');
    await runtime.tick();
    assert.equal(service.getConfiguration(initial.id).status, 'active');

    const center = service.listNodes(network.id)[0];
    const config = database.get(
      'SELECT config_json FROM node_configs WHERE version_id = ? AND node_id = ?',
      initial.id,
      center.id,
    );
    assert.match(JSON.parse(config.config_json).data.interfaceName, /^pw-[a-f0-9]{10}$/);
  } finally {
    database.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
