import { randomBytes } from 'node:crypto';
import type { DatabaseClient } from '../client.js';

interface Row {
  session_id: string;
  expires_at: string;
}

export class AdminSessionsRepository {
  constructor(private readonly db: DatabaseClient) {}

  async create(ttlHours: number): Promise<string> {
    const sessionId = randomBytes(32).toString('base64url');
    await this.db.query(
      `INSERT INTO admin_sessions (session_id, last_seen_at, expires_at)
       VALUES ($1, NOW(), NOW() + ($2 || ' hours')::interval)`,
      [sessionId, String(ttlHours)]
    );
    return sessionId;
  }

  async validateAndTouch(sessionId: string, ttlHours: number): Promise<boolean> {
    const rows = await this.db.query<Row>(
      `SELECT session_id, expires_at FROM admin_sessions WHERE session_id = $1 AND expires_at > NOW()`,
      [sessionId]
    );
    if (!rows.rows[0]) return false;

    await this.db.query(
      `UPDATE admin_sessions
       SET last_seen_at = NOW(), expires_at = NOW() + ($2 || ' hours')::interval
       WHERE session_id = $1`,
      [sessionId, String(ttlHours)]
    );

    return true;
  }

  async delete(sessionId: string): Promise<void> {
    await this.db.query('DELETE FROM admin_sessions WHERE session_id = $1', [sessionId]);
  }
}
