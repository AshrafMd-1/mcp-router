import type { DatabaseClient } from '../client.js';
import type { ToolDefinition } from '../../mcp/protocol.js';

interface Row {
  tool_name: string;
  tool_title: string | null;
  tool_description: string | null;
  input_schema: Record<string, unknown>;
  is_read_only: boolean;
  cached_at: string;
}

export interface CachedTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  isReadOnly: boolean;
  cachedAt: string;
}

const map = (row: Row): CachedTool => ({
  name: row.tool_name,
  title: row.tool_title ?? undefined,
  description: row.tool_description ?? undefined,
  inputSchema: row.input_schema,
  isReadOnly: row.is_read_only,
  cachedAt: row.cached_at
});

export class ToolCacheRepository {
  constructor(private readonly db: DatabaseClient) {}

  async replaceForConnector(connectorId: string, tools: ToolDefinition[]): Promise<void> {
    await this.db.query('DELETE FROM connector_tool_cache WHERE connector_id = $1', [connectorId]);
    for (const tool of tools) {
      await this.db.query(
        `INSERT INTO connector_tool_cache (connector_id, tool_name, tool_title, tool_description, input_schema, is_read_only)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
        [connectorId, tool.name, tool.title ?? null, tool.description ?? null, JSON.stringify(tool.inputSchema), Boolean(tool.isReadOnly)]
      );
    }
  }

  async listByConnector(connectorId: string): Promise<CachedTool[]> {
    const rows = await this.db.query<Row>(
      `SELECT tool_name, tool_title, tool_description, input_schema, is_read_only, cached_at
       FROM connector_tool_cache WHERE connector_id = $1 ORDER BY tool_name ASC`,
      [connectorId]
    );
    return rows.rows.map(map);
  }
}
