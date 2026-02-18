import type { ConnectorAdapter, ConnectorCapabilities, HealthStatus } from './adapter.js';
import type { JsonRpcResponse, ToolDefinition, ToolResult } from '../mcp/protocol.js';

interface HttpAdapterConfig {
  id: string;
  name: string;
  url: string;
  authToken?: string;
  authScheme?: string;
}

export class HttpConnectorAdapter implements ConnectorAdapter {
  readonly id: string;
  readonly name: string;
  readonly type = 'http' as const;

  private readonly config: HttpAdapterConfig;
  private sessionId: string | null = null;
  private capabilities: ConnectorCapabilities = {
    tools: [],
    resources: [],
    prompts: [],
    serverInfo: { name: 'unknown' }
  };

  constructor(config: HttpAdapterConfig) {
    this.id = config.id;
    this.name = config.name;
    this.config = config;
  }

  async initialize(): Promise<ConnectorCapabilities> {
    await this.sendRequest('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: { tools: {}, resources: {}, prompts: {} },
      clientInfo: { name: 'mcp-gateway', version: '0.1.0' }
    });
    await this.sendNotification('notifications/initialized');
    return this.refreshCapabilities();
  }

  async refreshCapabilities(): Promise<ConnectorCapabilities> {
    const tools = await this.sendRequest('tools/list', {});
    const resources = await this.sendOptionalRequest('resources/list', {}, { resources: [] });
    const prompts = await this.sendOptionalRequest('prompts/list', {}, { prompts: [] });

    this.capabilities = {
      tools: ((tools as { tools?: ToolDefinition[] }).tools ?? []).map((tool) => ({ ...tool })),
      resources: (resources as { resources?: Array<{ name: string; uri: string }> }).resources ?? [],
      prompts: (prompts as { prompts?: Array<{ name: string }> }).prompts ?? [],
      serverInfo: { name: this.name }
    };

    return this.capabilities;
  }

  async callTool(name: string, args: unknown, options?: { timeout?: number }): Promise<ToolResult> {
    const result = await this.sendRequest('tools/call', { name, arguments: args ?? {} }, options?.timeout);
    return result as ToolResult;
  }

  async readResource(uri: string): Promise<unknown> {
    return this.sendRequest('resources/read', { uri });
  }

  async getPrompt(name: string, args?: Record<string, unknown>): Promise<unknown> {
    return this.sendRequest('prompts/get', { name, arguments: args ?? {} });
  }

  async checkHealth(): Promise<HealthStatus> {
    const started = Date.now();
    try {
      await this.sendOptionalRequest('ping', {}, { ok: true }, 5000);
      return { status: 'healthy', lastCheck: Date.now(), latencyMs: Date.now() - started, error: null };
    } catch (error) {
      return {
        status: 'unhealthy',
        lastCheck: Date.now(),
        latencyMs: Date.now() - started,
        error: error instanceof Error ? error.message : 'Health check failed'
      };
    }
  }

  async shutdown(): Promise<void> {
    this.sessionId = null;
  }

  private async sendNotification(method: string, params?: unknown): Promise<void> {
    await fetch(this.config.url, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({ jsonrpc: '2.0', method, params })
    });
  }

  private async sendRequest(method: string, params: unknown, timeout = 30000): Promise<unknown> {
    const id = Math.floor(Math.random() * 1000000);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(this.config.url, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: controller.signal
      });

      if (!response.ok) {
        const responseText = await response.text().catch(() => '');
        const detail = responseText ? ` - ${responseText.slice(0, 300)}` : '';
        throw new Error(`Downstream HTTP ${response.status}${detail}`);
      }

      const contentType = response.headers.get('content-type') ?? '';
      const payload = contentType.includes('text/event-stream')
        ? await this.consumeSseResponse(response, id)
        : ((await response.json()) as JsonRpcResponse<unknown>);
      if ('error' in payload) {
        throw new Error(payload.error.message);
      }

      const nextSession = response.headers.get('Mcp-Session-Id');
      if (nextSession) {
        this.sessionId = nextSession;
      }

      return payload.result;
    } finally {
      clearTimeout(timer);
    }
  }

  private async sendOptionalRequest(
    method: string,
    params: unknown,
    fallback: unknown,
    timeout = 30000
  ): Promise<unknown> {
    try {
      return await this.sendRequest(method, params, timeout);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const normalized = message.toLowerCase();
      if (
        normalized.includes('method not found') ||
        normalized.includes('not supported') ||
        normalized.includes('unsupported')
      ) {
        return fallback;
      }
      throw error;
    }
  }

  private async consumeSseResponse(response: Response, requestId: number): Promise<JsonRpcResponse<unknown>> {
    const body = await response.text();
    const events = body.split('\n\n');

    for (const rawEvent of events) {
      const lines = rawEvent
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);

      if (lines.length === 0) continue;

      const dataLines = lines
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trim())
        .filter(Boolean);

      if (dataLines.length === 0) continue;

      const dataPayload = dataLines.join('\n');
      let candidate: unknown;
      try {
        candidate = JSON.parse(dataPayload);
      } catch {
        continue;
      }

      if (!candidate || typeof candidate !== 'object') continue;

      const maybe = candidate as JsonRpcResponse<unknown> & { id?: string | number | null };
      if (maybe.id === requestId) {
        return maybe;
      }
    }

    throw new Error('SSE response did not include matching JSON-RPC result');
  }

  private headers(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2025-06-18',
      ...(this.sessionId ? { 'Mcp-Session-Id': this.sessionId } : {}),
      ...(this.config.authToken ? { Authorization: `${this.config.authScheme ?? 'Bearer'} ${this.config.authToken}` } : {})
    };
  }
}
