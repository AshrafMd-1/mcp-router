import { randomUUID } from 'node:crypto';
import type { ConnectorAdapter, ConnectorCapabilities } from './adapter.js';
import { HttpConnectorAdapter } from './http-adapter.js';
import { StdioConnectorAdapter } from './stdio-adapter.js';
import type { ToolDefinition } from '../mcp/protocol.js';

export type ConnectorDefinition =
  | {
      id: string;
      name: string;
      type: 'http';
      config: {
        url: string;
        authToken?: string;
        authScheme?: string;
        oauth?: {
          authorizationUrl?: string;
          tokenUrl?: string;
          clientId?: string;
          clientSecret?: string;
          redirectUri?: string;
          scopes?: string[];
        };
      };
      enabled: boolean;
    }
  | {
      id: string;
      name: string;
      type: 'stdio';
      config: { command: string; args?: string[]; cwd?: string; env?: Record<string, string> };
      enabled: boolean;
    };

interface ConnectorState {
  definition: ConnectorDefinition;
  adapter: ConnectorAdapter;
  capabilities: ConnectorCapabilities;
}

export class ConnectorManager {
  private readonly states = new Map<string, ConnectorState>();

  async register(definition: Omit<ConnectorDefinition, 'id'> & { id?: string }): Promise<ConnectorDefinition> {
    const connector: ConnectorDefinition = { ...definition, id: definition.id ?? randomUUID() } as ConnectorDefinition;
    const adapter = this.makeAdapter(connector);
    const capabilities = await this.initializeConnector(connector, adapter);
    this.states.set(connector.name, { definition: connector, adapter, capabilities });
    return connector;
  }

  list(): ConnectorDefinition[] {
    return [...this.states.values()].map((state) => state.definition);
  }

  get(name: string): ConnectorState | null {
    return this.states.get(name) ?? null;
  }

  async updateHttpAuthToken(name: string, authToken: string, authScheme = 'Bearer'): Promise<ConnectorDefinition | null> {
    const state = this.states.get(name);
    if (!state) return null;
    if (state.definition.type !== 'http') return null;

    state.definition = {
      ...state.definition,
      config: {
        ...state.definition.config,
        authToken,
        authScheme
      }
    };

    await state.adapter.shutdown();
    const adapter = this.makeAdapter(state.definition);
    const capabilities = await adapter.initialize();
    state.adapter = adapter;
    state.capabilities = capabilities;

    this.states.set(name, state);
    return state.definition;
  }

  async remove(name: string): Promise<boolean> {
    const state = this.states.get(name);
    if (!state) return false;
    await state.adapter.shutdown();
    this.states.delete(name);
    return true;
  }

  async refresh(name: string): Promise<ConnectorCapabilities> {
    const state = this.states.get(name);
    if (!state) throw new Error(`Connector not found: ${name}`);
    const capabilities = await state.adapter.refreshCapabilities();
    state.capabilities = capabilities;
    return capabilities;
  }

  allTools(): ToolDefinition[] {
    const tools: ToolDefinition[] = [];
    for (const state of this.states.values()) {
      for (const tool of state.capabilities.tools) {
        tools.push({ ...tool, name: `${state.definition.name}.${tool.name}` });
      }
    }
    return tools;
  }

  private makeAdapter(definition: ConnectorDefinition): ConnectorAdapter {
    if (definition.type === 'http') {
      return new HttpConnectorAdapter({
        id: definition.id,
        name: definition.name,
        url: definition.config.url,
        authToken: definition.config.authToken,
        authScheme: definition.config.authScheme
      });
    }

    return new StdioConnectorAdapter({
      id: definition.id,
      name: definition.name,
      command: definition.config.command,
      args: definition.config.args,
      cwd: definition.config.cwd,
      env: definition.config.env
    });
  }

  private async initializeConnector(
    definition: ConnectorDefinition,
    adapter: ConnectorAdapter
  ): Promise<ConnectorCapabilities> {
    try {
      return await adapter.initialize();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const shouldDeferAuth =
        definition.type === 'http' &&
        !definition.config.authToken &&
        (message.includes('401') || message.toLowerCase().includes('unauthorized'));

      if (shouldDeferAuth) {
        return {
          tools: [],
          resources: [],
          prompts: [],
          serverInfo: { name: definition.name, version: 'auth-pending' }
        };
      }

      throw error;
    }
  }
}
