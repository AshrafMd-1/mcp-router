import type { DatabaseClient } from '../client.js';

export type ConnectorMode = 'oauth_url' | 'json_config';
export type ConnectorTransport = 'http' | 'stdio';

export interface ConnectorEntity {
  id: string;
  name: string;
  mode: ConnectorMode;
  transport: ConnectorTransport;
  enabled: boolean;
  configJson: Record<string, unknown>;
  healthStatus: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  healthError: string | null;
  lastHealthAt: string | null;
  createdAt: string;
}

interface Row {
  id: string;
  name: string;
  mode: ConnectorMode;
  transport: ConnectorTransport;
  enabled: boolean;
  config_json: Record<string, unknown>;
  health_status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  health_error: string | null;
  last_health_at: string | null;
  created_at: string;
}

const map = (row: Row): ConnectorEntity => ({
  id: row.id,
  name: row.name,
  mode: row.mode,
  transport: row.transport,
  enabled: row.enabled,
  configJson: row.config_json,
  healthStatus: row.health_status,
  healthError: row.health_error,
  lastHealthAt: row.last_health_at,
  createdAt: row.created_at
});

export class ConnectorsRepository {
  constructor(private readonly db: DatabaseClient) {}

  async create(input: {
    name: string;
    mode: ConnectorMode;
    transport: ConnectorTransport;
    enabled: boolean;
    configJson: Record<string, unknown>;
  }): Promise<ConnectorEntity> {
    // Upsert on name: if the connector already exists (e.g. a previous Save attempt
    // failed after the DB row was written), update its fields instead of erroring.
    const rows = await this.db.query<Row>(
      `INSERT INTO connectors (name, mode, transport, enabled, config_json)
       VALUES ($1, $2, $3, $4, $5::jsonb)
       ON CONFLICT (name) DO UPDATE SET
         mode        = EXCLUDED.mode,
         transport   = EXCLUDED.transport,
         enabled     = EXCLUDED.enabled,
         config_json = EXCLUDED.config_json,
         updated_at  = NOW()
       RETURNING id, name, mode, transport, enabled, config_json, health_status, health_error, last_health_at, created_at`,
      [input.name, input.mode, input.transport, input.enabled, JSON.stringify(input.configJson)]
    );
    return map(rows.rows[0]);
  }

  async update(
    id: string,
    patch: Partial<Pick<ConnectorEntity, 'name' | 'enabled' | 'configJson' | 'mode' | 'transport'>>
  ): Promise<ConnectorEntity | null> {
    const current = await this.getById(id);
    if (!current) return null;

    const rows = await this.db.query<Row>(
       `UPDATE connectors
       SET name = $2,
           mode = $3,
           transport = $4,
           enabled = $5,
           config_json = $6::jsonb,
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, name, mode, transport, enabled, config_json, health_status, health_error, last_health_at, created_at`,
      [
        id,
        patch.name ?? current.name,
        patch.mode ?? current.mode,
        patch.transport ?? current.transport,
        patch.enabled ?? current.enabled,
        JSON.stringify(patch.configJson ?? current.configJson)
      ]
    );

    return rows.rows[0] ? map(rows.rows[0]) : null;
  }

  async list(): Promise<ConnectorEntity[]> {
    const rows = await this.db.query<Row>(
      `SELECT id, name, mode, transport, enabled, config_json, health_status, health_error, last_health_at, created_at
       FROM connectors ORDER BY created_at DESC`
    );
    return rows.rows.map(map);
  }

  async getById(id: string): Promise<ConnectorEntity | null> {
    const rows = await this.db.query<Row>(
      `SELECT id, name, mode, transport, enabled, config_json, health_status, health_error, last_health_at, created_at
       FROM connectors WHERE id = $1`,
      [id]
    );
    return rows.rows[0] ? map(rows.rows[0]) : null;
  }

  async getByName(name: string): Promise<ConnectorEntity | null> {
    const rows = await this.db.query<Row>(
      `SELECT id, name, mode, transport, enabled, config_json, health_status, health_error, last_health_at, created_at
       FROM connectors WHERE name = $1`,
      [name]
    );
    return rows.rows[0] ? map(rows.rows[0]) : null;
  }

  async setHealth(id: string, healthStatus: ConnectorEntity['healthStatus'], healthError: string | null): Promise<void> {
    await this.db.query(
      `UPDATE connectors SET health_status = $2, health_error = $3, last_health_at = NOW(), updated_at = NOW() WHERE id = $1`,
      [id, healthStatus, healthError]
    );
  }

  async remove(id: string): Promise<boolean> {
    const result = await this.db.query<{ id: string }>('DELETE FROM connectors WHERE id = $1 RETURNING id', [id]);
    return result.rows.length > 0;
  }
}
