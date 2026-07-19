import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS networks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  data_cidr TEXT NOT NULL,
  control_cidr TEXT NOT NULL,
  listen_port INTEGER NOT NULL,
  mtu INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cluster_state (
  network_id TEXT PRIMARY KEY REFERENCES networks(id) ON DELETE CASCADE,
  coordinator_node_id TEXT NOT NULL,
  term INTEGER NOT NULL DEFAULT 1,
  revision INTEGER NOT NULL DEFAULT 0,
  election_secret TEXT NOT NULL,
  voted_for TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  is_center INTEGER NOT NULL DEFAULT 0,
  has_public_endpoint INTEGER NOT NULL DEFAULT 0,
  can_relay INTEGER NOT NULL DEFAULT 1,
  parent_id TEXT REFERENCES nodes(id),
  control_ip TEXT NOT NULL,
  data_ip TEXT NOT NULL,
  control_endpoint TEXT,
  control_listen_port INTEGER,
  data_endpoint TEXT,
  data_listen_port INTEGER,
  wg_control_public_key TEXT,
  wg_data_public_key TEXT,
  credential_hash TEXT,
  agent_version TEXT,
  last_seen TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS nodes_network_data_ip ON nodes(network_id, data_ip);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_network_control_ip ON nodes(network_id, control_ip);
CREATE INDEX IF NOT EXISTS nodes_parent ON nodes(parent_id);
CREATE INDEX IF NOT EXISTS nodes_credential ON nodes(credential_hash);

CREATE TABLE IF NOT EXISTS local_node_keys (
  node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  control_private_key TEXT NOT NULL,
  data_private_key TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS topology_links (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  upstream_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  downstream_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  priority INTEGER NOT NULL DEFAULT 100,
  upstream_endpoint TEXT,
  downstream_endpoint TEXT,
  validation_status TEXT NOT NULL DEFAULT 'active',
  validation_error TEXT,
  validation_token TEXT,
  validation_prepared_upstream INTEGER NOT NULL DEFAULT 0,
  validation_prepared_downstream INTEGER NOT NULL DEFAULT 0,
  validation_probed_upstream INTEGER NOT NULL DEFAULT 0,
  validation_probed_downstream INTEGER NOT NULL DEFAULT 0,
  validation_probe_error_upstream TEXT,
  validation_probe_error_downstream TEXT,
  validation_expires_at TEXT,
  validated_at TEXT,
  benchmark_status TEXT,
  benchmark_error TEXT,
  benchmark_source_id TEXT REFERENCES nodes(id) ON DELETE SET NULL,
  benchmark_target_id TEXT REFERENCES nodes(id) ON DELETE SET NULL,
  benchmark_token_hash TEXT,
  benchmark_expires_at TEXT,
  benchmark_latency_ms REAL,
  benchmark_latency_min_ms REAL,
  benchmark_latency_p95_ms REAL,
  benchmark_bandwidth_mbps REAL,
  benchmark_bytes INTEGER,
  benchmark_duration_ms REAL,
  benchmark_measured_at TEXT,
  endpoint_semantics_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS topology_link_direction
  ON topology_links(network_id, upstream_id, downstream_id);

CREATE TABLE IF NOT EXISTS path_policies (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  mode TEXT NOT NULL DEFAULT 'weighted',
  paths_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(network_id, source_id, target_id)
);

CREATE INDEX IF NOT EXISTS path_policies_network ON path_policies(network_id);

CREATE TABLE IF NOT EXISTS link_health_reports (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  link_id TEXT NOT NULL REFERENCES topology_links(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY(node_id, link_id)
);

CREATE INDEX IF NOT EXISTS link_health_reports_link
  ON link_health_reports(link_id, status, observed_at);

CREATE TABLE IF NOT EXISTS join_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  parent_id TEXT REFERENCES nodes(id),
  parent_data_endpoint TEXT,
  mode TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  max_uses INTEGER NOT NULL,
  used_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_versions (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  topology_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  activated_at TEXT,
  UNIQUE(network_id, version)
);

CREATE TABLE IF NOT EXISTS node_configs (
  version_id TEXT NOT NULL REFERENCES config_versions(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  phase TEXT NOT NULL,
  required INTEGER NOT NULL DEFAULT 1,
  config_json TEXT NOT NULL,
  error TEXT,
  prepared_at TEXT,
  activated_at TEXT,
  PRIMARY KEY(version_id, node_id)
);

CREATE TABLE IF NOT EXISTS network_cidr_changes (
  version_id TEXT PRIMARY KEY REFERENCES config_versions(id) ON DELETE CASCADE,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  before_cidr TEXT NOT NULL,
  after_cidr TEXT NOT NULL,
  assignments_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  created_at TEXT NOT NULL,
  applied_at TEXT
);

CREATE INDEX IF NOT EXISTS network_cidr_changes_network
  ON network_cidr_changes(network_id, status, created_at);

CREATE TABLE IF NOT EXISTS commands (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT,
  created_at TEXT NOT NULL,
  claimed_at TEXT,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS commands_pending ON commands(node_id, status, created_at);

CREATE TABLE IF NOT EXISTS update_rollouts (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  source_node_id TEXT REFERENCES nodes(id) ON DELETE SET NULL,
  source_kind TEXT,
  bundle_sha256 TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS update_rollouts_network
  ON update_rollouts(network_id, created_at);

CREATE TABLE IF NOT EXISTS update_rollout_nodes (
  rollout_id TEXT NOT NULL REFERENCES update_rollouts(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  command_id TEXT REFERENCES commands(id) ON DELETE SET NULL,
  error TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(rollout_id, node_id)
);

CREATE TABLE IF NOT EXISTS managed_node_proxies (
  node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  manager_node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  session_token TEXT NOT NULL,
  relay_path_json TEXT NOT NULL DEFAULT '[]',
  current_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS managed_node_proxies_manager
  ON managed_node_proxies(manager_node_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  detail_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`;

const SNAPSHOT_TABLES = [
  'networks',
  'nodes',
  'cluster_state',
  'local_node_keys',
  'topology_links',
  'path_policies',
  'link_health_reports',
  'join_tokens',
  'config_versions',
  'node_configs',
  'network_cidr_changes',
  'commands',
  'update_rollouts',
  'update_rollout_nodes',
  'managed_node_proxies',
  'audit_log',
];

export class Database {
  constructor(filename) {
    if (filename !== ':memory:') mkdirSync(dirname(filename), { recursive: true });
    this.handle = new DatabaseSync(filename);
    this.handle.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    this.handle.exec(SCHEMA);
    this.migrate();
  }

  migrate() {
    const columns = new Set(this.handle.prepare('PRAGMA table_info(topology_links)').all().map((column) => column.name));
    const additions = [
      ['upstream_endpoint', 'TEXT'],
      ['downstream_endpoint', 'TEXT'],
      ['validation_status', "TEXT NOT NULL DEFAULT 'active'"],
      ['validation_error', 'TEXT'],
      ['validation_token', 'TEXT'],
      ['validation_prepared_upstream', 'INTEGER NOT NULL DEFAULT 0'],
      ['validation_prepared_downstream', 'INTEGER NOT NULL DEFAULT 0'],
      ['validation_probed_upstream', 'INTEGER NOT NULL DEFAULT 0'],
      ['validation_probed_downstream', 'INTEGER NOT NULL DEFAULT 0'],
      ['validation_probe_error_upstream', 'TEXT'],
      ['validation_probe_error_downstream', 'TEXT'],
      ['validation_expires_at', 'TEXT'],
      ['validated_at', 'TEXT'],
      ['benchmark_status', 'TEXT'],
      ['benchmark_error', 'TEXT'],
      ['benchmark_source_id', 'TEXT REFERENCES nodes(id) ON DELETE SET NULL'],
      ['benchmark_target_id', 'TEXT REFERENCES nodes(id) ON DELETE SET NULL'],
      ['benchmark_token_hash', 'TEXT'],
      ['benchmark_expires_at', 'TEXT'],
      ['benchmark_latency_ms', 'REAL'],
      ['benchmark_latency_min_ms', 'REAL'],
      ['benchmark_latency_p95_ms', 'REAL'],
      ['benchmark_bandwidth_mbps', 'REAL'],
      ['benchmark_bytes', 'INTEGER'],
      ['benchmark_duration_ms', 'REAL'],
      ['benchmark_measured_at', 'TEXT'],
      ['endpoint_semantics_version', 'INTEGER NOT NULL DEFAULT 0'],
    ];
    for (const [name, definition] of additions) {
      if (!columns.has(name)) this.handle.exec(`ALTER TABLE topology_links ADD COLUMN ${name} ${definition}`);
    }
    this.handle.exec(`
      UPDATE topology_links
      SET upstream_endpoint = CASE
            WHEN upstream_endpoint IS NOT NULL THEN upstream_endpoint
            WHEN EXISTS (
              SELECT 1 FROM nodes child
              WHERE child.id = topology_links.downstream_id AND child.parent_id = topology_links.upstream_id
            ) THEN COALESCE((SELECT data_endpoint FROM nodes WHERE id = topology_links.upstream_id), '')
            WHEN EXISTS (
              SELECT 1 FROM nodes child
              WHERE child.id = topology_links.upstream_id AND child.parent_id = topology_links.downstream_id
            ) THEN ''
            ELSE COALESCE((SELECT data_endpoint FROM nodes WHERE id = topology_links.upstream_id), '')
          END,
          downstream_endpoint = CASE
            WHEN downstream_endpoint IS NOT NULL THEN downstream_endpoint
            WHEN EXISTS (
              SELECT 1 FROM nodes child
              WHERE child.id = topology_links.upstream_id AND child.parent_id = topology_links.downstream_id
            ) THEN COALESCE((SELECT data_endpoint FROM nodes WHERE id = topology_links.downstream_id), '')
            WHEN EXISTS (
              SELECT 1 FROM nodes child
              WHERE child.id = topology_links.downstream_id AND child.parent_id = topology_links.upstream_id
            ) THEN ''
            ELSE COALESCE((SELECT data_endpoint FROM nodes WHERE id = topology_links.downstream_id), '')
          END,
          endpoint_semantics_version = 1
      WHERE endpoint_semantics_version = 0
    `);

    const nodeColumns = new Set(this.handle.prepare('PRAGMA table_info(nodes)').all().map((column) => column.name));
    if (!nodeColumns.has('control_listen_port')) {
      this.handle.exec('ALTER TABLE nodes ADD COLUMN control_listen_port INTEGER');
    }
    if (!nodeColumns.has('data_listen_port')) {
      this.handle.exec('ALTER TABLE nodes ADD COLUMN data_listen_port INTEGER');
    }
    if (!nodeColumns.has('has_public_endpoint')) {
      this.handle.exec('ALTER TABLE nodes ADD COLUMN has_public_endpoint INTEGER NOT NULL DEFAULT 0');
      this.handle.exec('UPDATE nodes SET has_public_endpoint = 1 WHERE is_center = 1');
      this.handle.exec('UPDATE nodes SET can_relay = 0 WHERE is_center = 0');
    }
    const proxyColumns = new Set(this.handle.prepare('PRAGMA table_info(managed_node_proxies)').all().map((column) => column.name));
    if (!proxyColumns.has('relay_path_json')) {
      this.handle.exec("ALTER TABLE managed_node_proxies ADD COLUMN relay_path_json TEXT NOT NULL DEFAULT '[]'");
    }
    const nodeConfigColumns = new Set(this.handle.prepare('PRAGMA table_info(node_configs)').all().map((column) => column.name));
    if (!nodeConfigColumns.has('required')) {
      this.handle.exec('ALTER TABLE node_configs ADD COLUMN required INTEGER NOT NULL DEFAULT 1');
    }
    const joinTokenColumns = new Set(this.handle.prepare('PRAGMA table_info(join_tokens)').all().map((column) => column.name));
    if (!joinTokenColumns.has('parent_data_endpoint')) {
      this.handle.exec('ALTER TABLE join_tokens ADD COLUMN parent_data_endpoint TEXT');
    }
    this.handle.exec(`
      UPDATE node_configs
      SET required = 0
      WHERE node_id IN (SELECT id FROM nodes WHERE is_center = 0 AND status = 'offline')
        AND version_id IN (SELECT id FROM config_versions WHERE status IN ('preparing', 'activating'))
        AND phase != 'activated'
    `);
    const timestamp = new Date().toISOString();
    const revision = Number(this.get('SELECT COALESCE(MAX(id), 0) AS revision FROM audit_log')?.revision || 0);
    for (const network of this.all('SELECT id FROM networks')) {
      const coordinator = this.get(
        'SELECT id FROM nodes WHERE network_id = ? ORDER BY is_center DESC, created_at LIMIT 1',
        network.id,
      );
      if (!coordinator) continue;
      this.run(
        `INSERT INTO cluster_state(network_id, coordinator_node_id, term, revision, election_secret, voted_for, updated_at)
         VALUES (?, ?, 1, ?, ?, NULL, ?)
         ON CONFLICT(network_id) DO NOTHING`,
        network.id, coordinator.id, revision, randomBytes(32).toString('base64url'), timestamp,
      );
    }
    this.handle.exec(`
      UPDATE nodes
      SET control_listen_port = 8790
      WHERE control_listen_port IS NULL AND is_center = 0
    `);
    this.handle.exec(`
      UPDATE nodes
      SET data_listen_port = COALESCE(
        data_listen_port,
        (SELECT listen_port FROM networks WHERE networks.id = nodes.network_id),
        19801
      )
      WHERE data_listen_port IS NULL
    `);
  }

  run(sql, ...params) {
    return this.handle.prepare(sql).run(...params);
  }

  get(sql, ...params) {
    return this.handle.prepare(sql).get(...params);
  }

  all(sql, ...params) {
    return this.handle.prepare(sql).all(...params);
  }

  transaction(callback) {
    this.handle.exec('BEGIN IMMEDIATE');
    try {
      const result = callback();
      this.handle.exec('COMMIT');
      return result;
    } catch (error) {
      this.handle.exec('ROLLBACK');
      throw error;
    }
  }

  exportSnapshot() {
    const tables = Object.fromEntries(SNAPSHOT_TABLES.map((table) => [
      table,
      this.all(`SELECT * FROM ${table}`),
    ]));
    const revision = Math.max(0, ...tables.cluster_state.map((row) => Number(row.revision || 0)));
    return {
      schemaVersion: 1,
      revision,
      createdAt: new Date().toISOString(),
      tables,
    };
  }

  importSnapshot(snapshot) {
    if (!snapshot || Number(snapshot.schemaVersion) !== 1 || !snapshot.tables) {
      throw new Error('协调快照格式或版本无效');
    }
    const optionalTables = new Set(['update_rollouts', 'update_rollout_nodes']);
    for (const table of SNAPSHOT_TABLES) {
      if (optionalTables.has(table) && snapshot.tables[table] === undefined) continue;
      if (!Array.isArray(snapshot.tables[table])) throw new Error(`协调快照缺少数据表 ${table}`);
    }
    this.handle.exec('PRAGMA foreign_keys = OFF; BEGIN IMMEDIATE;');
    try {
      for (const table of [...SNAPSHOT_TABLES].reverse()) this.handle.exec(`DELETE FROM ${table}`);
      for (const table of SNAPSHOT_TABLES) {
        const columns = this.all(`PRAGMA table_info(${table})`).map((column) => column.name);
        const allowed = new Set(columns);
        for (const snapshotRow of snapshot.tables[table] || []) {
          let row = table === 'topology_links' && !Object.hasOwn(snapshotRow, 'endpoint_semantics_version')
            ? { ...snapshotRow, endpoint_semantics_version: 0 }
            : snapshotRow;
          if (table === 'nodes' && !Object.hasOwn(row, 'has_public_endpoint')) {
            row = { ...row, has_public_endpoint: row.is_center ? 1 : 0 };
          }
          const keys = Object.keys(row);
          if (!keys.length || keys.some((key) => !allowed.has(key))) throw new Error(`协调快照中的 ${table} 字段无效`);
          const placeholders = keys.map(() => '?').join(', ');
          this.run(
            `INSERT INTO ${table}(${keys.join(', ')}) VALUES (${placeholders})`,
            ...keys.map((key) => row[key]),
          );
        }
      }
      const violations = this.all('PRAGMA foreign_key_check');
      if (violations.length) throw new Error(`协调快照存在 ${violations.length} 项外键错误`);
      this.handle.exec('COMMIT');
    } catch (error) {
      this.handle.exec('ROLLBACK');
      throw error;
    } finally {
      this.handle.exec('PRAGMA foreign_keys = ON;');
    }
    this.migrate();
    return { revision: Number(snapshot.revision || 0) };
  }

  close() {
    this.handle.close();
  }
}
