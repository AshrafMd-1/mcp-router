import type { ConnectorAdapter, ConnectorCapabilities, HealthStatus } from './adapter.js';
import type { JsonRpcResponse, ToolDefinition, ToolResult } from '../mcp/protocol.js';
import { LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS } from './protocol-constants.js';
import { extractWWWAuthenticateParams, type ConnectorAuthState } from './auth-provider.js';
import { McpError, ErrorCode } from '../mcp/error-mapper.js';

export interface HttpAdapterConfig {
  id: string;
  name: string;
  url: string;
  authToken?: string;
  authScheme?: string;
  customHeaders?: Record<string, string>;
}

export class HttpConnectorAdapter implements ConnectorAdapter {
  readonly id: string;
  readonly name: string;
  readonly type = 'http' as const;

  private readonly config: HttpAdapterConfig;
  private sessionId: string | null = null;
  private protocolVersion: string = LATEST_PROTOCOL_VERSION;
  private serverInfo: { name: string; version?: string } = { name: 'unknown' };
  private authState: ConnectorAuthState = { status: 'none' };
  private hasCompletedAuthFlow = false;

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

  /**
   * Set negotiated protocol version (called after initialize)
   */
  setProtocolVersion(version: string): void {
    this.protocolVersion = version;
  }

  /**
   * Initialize connection to upstream MCP server with retry logic
   *
   * Follows SDK pattern from typescript-sdk/packages/client/src/client.ts:419-471
   */
  async initialize(): Promise<ConnectorCapabilities> {
    const maxRetries = 3;
    const baseDelay = 1000;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        // Step 1: Send initialize request
        const initResult = await this.sendRequest('initialize', {
          protocolVersion: LATEST_PROTOCOL_VERSION,
          capabilities: {
            tools: {},
            resources: {},
            prompts: {},
          },
          clientInfo: {
            name: 'mcp-gateway',
            version: '1.0.0'
          }
        }) as {
          protocolVersion: string;
          capabilities: Record<string, unknown>;
          serverInfo: { name: string; version?: string };
        };

        // Step 2: Validate protocol version
        if (!initResult?.protocolVersion) {
          throw new Error('Server sent invalid initialize result: missing protocolVersion');
        }

        if (!SUPPORTED_PROTOCOL_VERSIONS.includes(initResult.protocolVersion as typeof SUPPORTED_PROTOCOL_VERSIONS[number])) {
          throw new Error(
            `Server's protocol version ${initResult.protocolVersion} is not supported. ` +
            `Supported: ${SUPPORTED_PROTOCOL_VERSIONS.join(', ')}`
          );
        }

        // Step 3: Set negotiated version for subsequent requests
        this.setProtocolVersion(initResult.protocolVersion);

        // Store server info
        this.serverInfo = initResult.serverInfo ?? { name: this.name };

        // Step 4: Send initialized notification
        await this.sendNotification('notifications/initialized');

        // Step 5: Fetch tools/resources/prompts
        return await this.refreshCapabilities();

      } catch (error) {
        const isLastAttempt = attempt === maxRetries - 1;

        // Don't retry auth errors
        if (error instanceof McpError && error.code === ErrorCode.Unauthorized) {
          throw error;
        }

        if (isLastAttempt) {
          throw error;
        }

        // Exponential backoff: 1s, 2s, 4s
        const delay = baseDelay * Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw new Error('Initialize failed after max retries');
  }

  async refreshCapabilities(): Promise<ConnectorCapabilities> {
    const tools = await this.sendRequest('tools/list', {});
    const resources = await this.sendOptionalRequest('resources/list', {}, { resources: [] });
    const prompts = await this.sendOptionalRequest('prompts/list', {}, { prompts: [] });

    this.capabilities = {
      tools: ((tools as { tools?: ToolDefinition[] }).tools ?? []).map((tool) => ({ ...tool })),
      resources: (resources as { resources?: Array<{ name: string; uri: string }> }).resources ?? [],
      prompts: (prompts as { prompts?: Array<{ name: string }> }).prompts ?? [],
      serverInfo: this.serverInfo
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
    this.hasCompletedAuthFlow = false;
    this.authState = { status: 'none' };
  }

  private async sendNotification(method: string, params?: unknown): Promise<void> {
    await fetch(this.config.url, {
      method: 'POST',
      headers: this._commonHeaders(),
      body: JSON.stringify({ jsonrpc: '2.0', method, params })
    });
  }

  /**
   * Send JSON-RPC request with proper 401 handling
   *
   * Follows SDK pattern from typescript-sdk/packages/client/src/streamableHttp.ts:493-523
   */
  private async sendRequest(method: string, params: unknown, timeout = 30000): Promise<unknown> {
    const id = Math.floor(Math.random() * 1000000);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(this.config.url, {
        method: 'POST',
        headers: this._commonHeaders(),
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: controller.signal
      });

      // Handle 401 Unauthorized - trigger OAuth flow
      if (response.status === 401) {
        // Prevent infinite auth loops
        if (this.hasCompletedAuthFlow) {
          throw new McpError(
            ErrorCode.Unauthorized,
            'Server returned 401 after successful authentication',
            { authRequired: true, connectorId: this.id }
          );
        }

        // Extract OAuth hints from WWW-Authenticate header
        const { resourceMetadataUrl, scope, error: authError } = extractWWWAuthenticateParams(response);

        this.authState = {
          status: 'pending',
          resourceMetadataUrl: resourceMetadataUrl?.toString(),
          scope,
          error: authError,
        };

        // Return structured error with auth_required flag
        throw new McpError(
          ErrorCode.Unauthorized,
          'Authentication required for upstream MCP server',
          {
            authRequired: true,
            connectorId: this.id,
            resourceMetadataUrl: resourceMetadataUrl?.toString(),
            scope,
          }
        );
      }

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new McpError(
          ErrorCode.Unavailable,
          `Upstream HTTP ${response.status}: ${text.slice(0, 300)}`
        );
      }

      // Reset auth loop detection on success
      this.hasCompletedAuthFlow = false;

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

  /**
   * Build common headers for all requests
   *
   * Follows SDK pattern from typescript-sdk/packages/client/src/streamableHttp.ts:186-208
   */
  private _commonHeaders(): HeadersInit {
    const headers: Record<string, string> = {};

    // Content negotiation
    headers['content-type'] = 'application/json';
    headers['accept'] = 'application/json, text/event-stream';

    // Protocol version (use negotiated, not hardcoded)
    headers['mcp-protocol-version'] = this.protocolVersion;

    // Session ID if established
    if (this.sessionId) {
      headers['mcp-session-id'] = this.sessionId;
    }

    // Auth token (API key or OAuth access token)
    if (this.config.authToken) {
      headers['authorization'] = `${this.config.authScheme ?? 'Bearer'} ${this.config.authToken}`;
    }

    // Custom headers from connector config (without overwriting core headers)
    if (this.config.customHeaders) {
      for (const [key, value] of Object.entries(this.config.customHeaders)) {
        const lowerKey = key.toLowerCase();
        // Don't overwrite authorization or protocol headers
        if (lowerKey !== 'authorization' && !lowerKey.startsWith('mcp-')) {
          headers[key] = value;
        }
      }
    }

    return headers;
  }
}
