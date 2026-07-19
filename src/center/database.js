import { DatabaseSync } from 'node:sqlite';
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

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  is_center INTEGER NOT NULL DEFAULT 0,
  can_relay INTEGER NOT NULL DEFAULT 1,
  parent_id TEXT REFERENCES nodes(id),
  control_ip TEXT NOT NULL,
  data_ip TEXT NOT NULL,
  control_endpoint TEXT,
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
  validation_expires_at TEXT,
  validated_at TEXT,
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

CREATE TABLE IF NOT EXISTS join_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  parent_id TEXT REFERENCES nodes(id),
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
  config_json TEXT NOT NULL,
  error TEXT,
  prepared_at TEXT,
  activated_at TEXT,
  PRIMARY KEY(version_id, node_id)
);

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
      ['validation_expires_at', 'TEXT'],
      ['validated_at', 'TEXT'],
    ];
    for (const [name, definition] of additions) {
      if (!columns.has(name)) this.handle.exec(`ALTER TABLE topology_links ADD COLUMN ${name} ${definition}`);
    }

    const nodeColumns = new Set(this.handle.prepare('PRAGMA table_info(nodes)').all().map((column) => column.name));
    if (!nodeColumns.has('data_listen_port')) {
      this.handle.exec('ALTER TABLE nodes ADD COLUMN data_listen_port INTEGER');
    }
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

  close() {
    this.handle.close();
  }
}
