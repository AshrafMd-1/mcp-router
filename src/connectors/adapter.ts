import type { ToolDefinition, ToolResult } from '../mcp/protocol.js';

export interface ConnectorCapabilities {
  tools: ToolDefinition[];
  resources: Array<{ name: string; uri: string }>;
  prompts: Array<{ name: string }>;
  serverInfo: { name: string; version?: string };
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheck: number;
  latencyMs: number | null;
  error: string | null;
}

export interface ConnectorAdapter {
  readonly id: string;
  readonly name: string;
  readonly type: 'http' | 'stdio';
  initialize(): Promise<ConnectorCapabilities>;
  refreshCapabilities(): Promise<ConnectorCapabilities>;
  callTool(name: string, args: unknown, options?: { timeout?: number }): Promise<ToolResult>;
  readResource(uri: string, options?: { timeout?: number }): Promise<unknown>;
  getPrompt(name: string, args?: Record<string, unknown>): Promise<unknown>;
  checkHealth(): Promise<HealthStatus>;
  shutdown(): Promise<void>;
}
