import test from 'node:test';
import assert from 'node:assert/strict';
import { Database } from '../src/center/database.js';
import { ControlService } from '../src/center/service.js';

function populatedDatabase() {
  const database = new Database(':memory:');
  const service = new ControlService(database, { publicUrl: 'http://coordinator.example:19773' });
  const network = service.createNetwork({
    name: '副本测试',
    dataCidr: '10.190.0.0/24',
    controlCidr: '10.191.0.0/24',
    listenPort: 19801,
    mtu: 1380,
  });
  const center = service.listNodes(network.id)[0];
  const token = service.createJoinToken(network.id, { parentId: center.id });
  const edge = service.registerAgent({
    token: token.token,
    name: '候选协调节点',
    controlEndpoint: 'http://edge.example:8790',
    dataEndpoint: 'edge.example:19801',
    wgDataPublicKey: 'e'.repeat(44),
  }).node;
  return { database, service, network, center, edge };
}

test('逻辑快照完整复制协调状态并在导入前校验外键', () => {
  const source = populatedDatabase();
  const replica = new Database(':memory:');
  try {
    const snapshot = source.database.exportSnapshot();
    assert.equal(snapshot.revision > 0, true);
    replica.importSnapshot(snapshot);
    assert.deepEqual(
      replica.all('SELECT id, name FROM nodes ORDER BY created_at'),
      source.database.all('SELECT id, name FROM nodes ORDER BY created_at'),
    );
    assert.deepEqual(
      replica.get('SELECT coordinator_node_id, term, revision, election_secret FROM cluster_state'),
      source.database.get('SELECT coordinator_node_id, term, revision, election_secret FROM cluster_state'),
    );

    const broken = structuredClone(snapshot);
    broken.tables.nodes[0].network_id = 'missing-network';
    assert.throws(() => replica.importSnapshot(broken), /外键错误/);
    assert.equal(replica.get('SELECT COUNT(*) AS count FROM nodes').count, 2);
  } finally {
    source.database.close();
    replica.close();
  }
});

test('配置包含到全部选民的无环路由，且只有更新任期可迁移协调权', () => {
  const { database, service, network, center, edge } = populatedDatabase();
  try {
    const latest = database.get(
      `SELECT c.config_json FROM node_configs c
       JOIN config_versions v ON v.id = c.version_id
       WHERE c.node_id = ? ORDER BY v.version DESC LIMIT 1`,
      edge.id,
    );
    const config = JSON.parse(latest.config_json);
    assert.deepEqual(new Set(config.control.cluster.voterIds), new Set([center.id, edge.id]));
    assert.equal(Array.isArray(config.control.routesByTarget[center.id]), true);
    assert.equal(Array.isArray(config.control.routesByTarget[edge.id]), true);
    assert.equal(config.control.routesByTarget[edge.id].length, 0);

    const promoted = service.promoteCoordinator(edge.id, 2);
    assert.equal(promoted.cluster.coordinatorNodeId, edge.id);
    assert.equal(promoted.cluster.term, 2);
    assert.throws(() => service.promoteCoordinator(center.id, 1), /过期任期/);
  } finally { database.close(); }
});
