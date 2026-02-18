import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { DatabaseClient } from '../db/client.js';

export interface StoredToken {
  id: string;
  clientId: string;
  tokenHash: string;
  tokenPrefix: string;
  createdAt: string;
  revokedAt: string | null;
  lastUsedAt: string | null;
}

export interface TokenRecord extends StoredToken {
  plainToken?: string;
}

interface Row {
  id: string;
  client_id: string;
  token_hash: string;
  token_prefix: string;
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}

const map = (row: Row): StoredToken => ({
  id: row.id,
  clientId: row.client_id,
  tokenHash: row.token_hash,
  tokenPrefix: row.token_prefix,
  createdAt: row.created_at,
  revokedAt: row.revoked_at,
  lastUsedAt: row.last_used_at
});

export class TokenService {
  constructor(private readonly db: DatabaseClient) {}

  async issue(clientId: string): Promise<TokenRecord> {
    const token = `mgw_live_${randomBytes(24).toString('hex')}`;
    const tokenHash = this.hash(token);
    const tokenPrefix = token.slice(0, 12);

    const rows = await this.db.query<Row>(
      `INSERT INTO client_tokens (client_id, token_hash, token_prefix)
       VALUES ($1, $2, $3)
       RETURNING id, client_id, token_hash, token_prefix, created_at, revoked_at, last_used_at`,
      [clientId, tokenHash, tokenPrefix]
    );

    return { ...map(rows.rows[0]), plainToken: token };
  }

  async validate(rawToken: string): Promise<StoredToken | null> {
    const hash = this.hash(rawToken);
    const rows = await this.db.query<Row>(
      `SELECT id, client_id, token_hash, token_prefix, created_at, revoked_at, last_used_at
       FROM client_tokens
       WHERE revoked_at IS NULL`
    );

    for (const row of rows.rows) {
      const a = Buffer.from(row.token_hash, 'hex');
      const b = Buffer.from(hash, 'hex');
      if (a.length === b.length && timingSafeEqual(a, b)) {
        await this.db.query('UPDATE client_tokens SET last_used_at = NOW() WHERE id = $1', [row.id]);
        return { ...map(row), lastUsedAt: new Date().toISOString() };
      }
    }

    return null;
  }

  async revoke(tokenId: string): Promise<boolean> {
    const result = await this.db.query<{ id: string }>(
      `UPDATE client_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL RETURNING id`,
      [tokenId]
    );
    return result.rows.length > 0;
  }

  async listByClient(clientId: string): Promise<StoredToken[]> {
    const rows = await this.db.query<Row>(
      `SELECT id, client_id, token_hash, token_prefix, created_at, revoked_at, last_used_at
       FROM client_tokens WHERE client_id = $1 ORDER BY created_at DESC`,
      [clientId]
    );
    return rows.rows.map(map);
  }

  async get(tokenId: string): Promise<StoredToken | null> {
    const rows = await this.db.query<Row>(
      `SELECT id, client_id, token_hash, token_prefix, created_at, revoked_at, last_used_at
       FROM client_tokens WHERE id = $1`,
      [tokenId]
    );
    return rows.rows[0] ? map(rows.rows[0]) : null;
  }

  private hash(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }
}
