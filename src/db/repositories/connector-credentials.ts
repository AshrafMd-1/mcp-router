import type { DatabaseClient } from '../client.js';
import type { createEncryptionContext } from '../../security/crypto.js';

interface Row {
  connector_id: string;
  auth_kind: 'oauth_tokens' | 'api_header' | 'none';
  encrypted_secret: Buffer;
  expires_at: string | null;
}

export class ConnectorCredentialsRepository {
  constructor(
    private readonly db: DatabaseClient,
    private readonly crypto: ReturnType<typeof createEncryptionContext>
  ) {}

  async upsert(connectorId: string, authKind: Row['auth_kind'], payload: Record<string, unknown>, expiresAt: string | null = null): Promise<void> {
    const encrypted = this.crypto.encrypt(payload);
    await this.db.query(
      `INSERT INTO connector_credentials (connector_id, auth_kind, encrypted_secret, expires_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (connector_id, auth_kind)
       DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret, expires_at = EXCLUDED.expires_at, updated_at = NOW()`,
      [connectorId, authKind, encrypted, expiresAt]
    );
  }

  async get(connectorId: string, authKind: Row['auth_kind']): Promise<{ payload: Record<string, unknown>; expiresAt: string | null } | null> {
    const rows = await this.db.query<Row>(
      `SELECT connector_id, auth_kind, encrypted_secret, expires_at
       FROM connector_credentials WHERE connector_id = $1 AND auth_kind = $2`,
      [connectorId, authKind]
    );
    if (!rows.rows[0]) return null;
    const payload = this.crypto.decrypt(rows.rows[0].encrypted_secret);
    return { payload, expiresAt: rows.rows[0].expires_at };
  }

  async removeByConnector(connectorId: string): Promise<void> {
    await this.db.query('DELETE FROM connector_credentials WHERE connector_id = $1', [connectorId]);
  }
}
