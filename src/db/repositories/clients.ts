import type { DatabaseClient } from '../client.js';

export interface Client {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  createdAt: string;
}

interface Row {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  created_at: string;
}

const map = (row: Row): Client => ({
  id: row.id,
  name: row.name,
  description: row.description ?? undefined,
  enabled: row.enabled,
  createdAt: row.created_at
});

export class ClientsRepository {
  constructor(private readonly db: DatabaseClient) {}

  async create(input: { name: string; description?: string }): Promise<Client> {
    const rows = await this.db.query<Row>(
      `INSERT INTO clients (name, description, enabled)
       VALUES ($1, $2, true)
       RETURNING id, name, description, enabled, created_at`,
      [input.name, input.description ?? null]
    );
    return map(rows.rows[0]);
  }

  async list(): Promise<Client[]> {
    const rows = await this.db.query<Row>('SELECT id, name, description, enabled, created_at FROM clients ORDER BY created_at DESC');
    return rows.rows.map(map);
  }

  async get(id: string): Promise<Client | null> {
    const rows = await this.db.query<Row>('SELECT id, name, description, enabled, created_at FROM clients WHERE id = $1', [id]);
    return rows.rows[0] ? map(rows.rows[0]) : null;
  }

  async update(id: string, patch: Partial<Pick<Client, 'name' | 'description' | 'enabled'>>): Promise<Client | null> {
    const current = await this.get(id);
    if (!current) return null;

    const rows = await this.db.query<Row>(
      `UPDATE clients
       SET name = $2, description = $3, enabled = $4, updated_at = NOW()
       WHERE id = $1
       RETURNING id, name, description, enabled, created_at`,
      [id, patch.name ?? current.name, patch.description ?? current.description ?? null, patch.enabled ?? current.enabled]
    );

    return rows.rows[0] ? map(rows.rows[0]) : null;
  }

  async remove(id: string): Promise<boolean> {
    const result = await this.db.query<{ id: string }>('DELETE FROM clients WHERE id = $1 RETURNING id', [id]);
    return result.rows.length > 0;
  }
}
