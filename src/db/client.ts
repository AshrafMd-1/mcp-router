import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Pool, type QueryResultRow } from 'pg';

const CURRENT_MIGRATION = '20260218_rewrite_v1';

export interface DatabaseClient {
  query<T extends QueryResultRow = QueryResultRow>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  close(): Promise<void>;
}

export class PgDatabaseClient implements DatabaseClient {
  private readonly pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString });
  }

  async query<T extends QueryResultRow = QueryResultRow>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    const result = await this.pool.query<T>(sql, params);
    return { rows: result.rows };
  }

  async migrate(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const applied = await this.pool.query<{ id: string }>('SELECT id FROM schema_migrations WHERE id = $1', [CURRENT_MIGRATION]);
    if (applied.rows.length > 0) return;

    const sqlPath = resolve(process.cwd(), 'src/db/migrations/001_initial.sql');
    const sql = await readFile(sqlPath, 'utf-8');

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [CURRENT_MIGRATION]);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

export function createDatabaseClient(databaseUrl: string): PgDatabaseClient {
  return new PgDatabaseClient(databaseUrl);
}
