import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import type { ConnectorAdapter, ConnectorCapabilities, HealthStatus } from './adapter.js';
import type { ToolDefinition, ToolResult } from '../mcp/protocol.js';

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

interface StdioAdapterConfig {
  id: string;
  name: string;
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

export class StdioConnectorAdapter implements ConnectorAdapter {
  readonly id: string;
  readonly name: string;
  readonly type = 'stdio' as const;

  private readonly config: StdioAdapterConfig;
  private process: ChildProcessWithoutNullStreams | null = null;
  private readBuffer = '';
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();

  constructor(config: StdioAdapterConfig) {
    this.id = config.id;
    this.name = config.name;
    this.config = config;
  }

  async initialize(): Promise<ConnectorCapabilities> {
    await this.spawnProcess();
    await this.sendRequest('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: { tools: {}, resources: {}, prompts: {} },
      clientInfo: { name: 'mcp-gateway', version: '0.1.0' }
    });
    await this.sendNotification('notifications/initialized');
    return this.refreshCapabilities();
  }

  async refreshCapabilities(): Promise<ConnectorCapabilities> {
    const tools = (await this.sendRequest('tools/list', {})) as { tools?: ToolDefinition[] };
    const resources = (await this.sendRequest('resources/list', {})) as { resources?: Array<{ name: string; uri: string }> };
    const prompts = (await this.sendRequest('prompts/list', {})) as { prompts?: Array<{ name: string }> };

    return {
      tools: tools.tools ?? [],
      resources: resources.resources ?? [],
      prompts: prompts.prompts ?? [],
      serverInfo: { name: this.name }
    };
  }

  async callTool(name: string, args: unknown): Promise<ToolResult> {
    return (await this.sendRequest('tools/call', { name, arguments: args ?? {} })) as ToolResult;
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
      await this.sendRequest('ping', {});
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
    if (!this.process) return;
    this.process.stdin.end();
    this.process.kill('SIGTERM');
    this.process = null;
  }

  private async spawnProcess(): Promise<void> {
    if (this.process) return;

    this.process = spawn(this.config.command, this.config.args ?? [], {
      cwd: this.config.cwd,
      env: { ...process.env, ...this.config.env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    this.process.stdout.on('data', (chunk: Buffer) => {
      this.readBuffer += chunk.toString('utf-8');
      this.consumeBuffer();
    });

    this.process.stderr.on('data', () => {
      // Connector stderr is intentionally ignored in MVP.
    });

    this.process.on('exit', () => {
      for (const [id, pending] of this.pending.entries()) {
        clearTimeout(pending.timeout);
        pending.reject(new Error(`Connector process exited before response ${id}`));
      }
      this.pending.clear();
      this.process = null;
    });
  }

  private consumeBuffer(): void {
    const lines = this.readBuffer.split('\n');
    this.readBuffer = lines.pop() ?? '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let message: unknown;
      try {
        message = JSON.parse(trimmed);
      } catch {
        continue;
      }

      if (!message || typeof message !== 'object' || !('id' in message)) continue;
      const maybeId = (message as { id?: unknown }).id;
      if (typeof maybeId !== 'number') continue;

      const pending = this.pending.get(maybeId);
      if (!pending) continue;

      clearTimeout(pending.timeout);
      this.pending.delete(maybeId);

      if ('error' in (message as Record<string, unknown>)) {
        const errorMessage = ((message as { error?: { message?: string } }).error?.message) ?? 'Connector error';
        pending.reject(new Error(errorMessage));
      } else {
        pending.resolve((message as { result?: unknown }).result);
      }
    }
  }

  private async sendNotification(method: string, params?: unknown): Promise<void> {
    if (!this.process) throw new Error('Connector process not running');
    this.process.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  private sendRequest(method: string, params: unknown): Promise<unknown> {
    if (!this.process) {
      return Promise.reject(new Error('Connector process not running'));
    }

    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Request ${method} timed out`));
      }, this.config.timeoutMs ?? 30000);

      this.pending.set(id, { resolve, reject, timeout });
      this.process?.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }
}
