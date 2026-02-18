import type { DatabaseClient } from '../client.js';

export interface ClientPolicy {
  id: string;
  clientId: string;
  connectorIds: string[];
  allowedTools: string[];
  deniedTools: string[];
  updatedAt: string;
}

interface Row {
  id: string;
  client_id: string;
  connector_ids: string[];
  allowed_tools: string[];
  denied_tools: string[];
  updated_at: string;
}

const map = (row: Row): ClientPolicy => ({
  id: row.id,
  clientId: row.client_id,
  connectorIds: row.connector_ids ?? [],
  allowedTools: row.allowed_tools ?? [],
  deniedTools: row.denied_tools ?? [],
  updatedAt: row.updated_at
});

export class ClientPoliciesRepository {
  constructor(private readonly db: DatabaseClient) {}

  async ensure(clientId: string): Promise<ClientPolicy> {
    const existing = await this.getByClientId(clientId);
    if (existing) return existing;

    const rows = await this.db.query<Row>(
      `INSERT INTO client_policies (client_id, connector_ids, allowed_tools, denied_tools)
       VALUES ($1, '{}'::uuid[], '{}'::text[], '{}'::text[])
       RETURNING id, client_id, connector_ids, allowed_tools, denied_tools, updated_at`,
      [clientId]
    );

    return map(rows.rows[0]);
  }

  async getByClientId(clientId: string): Promise<ClientPolicy | null> {
    const rows = await this.db.query<Row>(
      `SELECT id, client_id, connector_ids, allowed_tools, denied_tools, updated_at
       FROM client_policies WHERE client_id = $1`,
      [clientId]
    );
    return rows.rows[0] ? map(rows.rows[0]) : null;
  }

  async setForClient(clientId: string, input: { connectorIds: string[]; allowedTools: string[]; deniedTools: string[] }): Promise<ClientPolicy> {
    await this.ensure(clientId);
    const rows = await this.db.query<Row>(
      `UPDATE client_policies
       SET connector_ids = $2::uuid[], allowed_tools = $3::text[], denied_tools = $4::text[], updated_at = NOW()
       WHERE client_id = $1
       RETURNING id, client_id, connector_ids, allowed_tools, denied_tools, updated_at`,
      [clientId, input.connectorIds, input.allowedTools, input.deniedTools]
    );

    return map(rows.rows[0]);
  }

  async countUsingConnector(connectorId: string): Promise<number> {
    const rows = await this.db.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM client_policies WHERE $1::uuid = ANY(connector_ids)`,
      [connectorId]
    );
    return Number(rows.rows[0]?.count ?? '0');
  }

  async listClientNamesUsingConnector(connectorId: string): Promise<string[]> {
    const rows = await this.db.query<{ name: string }>(
      `SELECT c.name
       FROM client_policies cp
       JOIN clients c ON c.id = cp.client_id
       WHERE $1::uuid = ANY(cp.connector_ids)
       ORDER BY c.name ASC`,
      [connectorId]
    );
    return rows.rows.map((r) => r.name);
  }
}
