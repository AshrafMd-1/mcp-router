import { randomUUID } from 'node:crypto';
import type { ConnectorAdapter, ConnectorCapabilities } from './adapter.js';
import { HttpConnectorAdapter } from './http-adapter.js';
import { StdioConnectorAdapter } from './stdio-adapter.js';
import { tryDiscoverOAuth, type OAuthServerInfo } from './oauth-discovery.js';
import type { ToolDefinition } from '../mcp/protocol.js';
import type { ConnectorCredentialsRepository } from '../db/repositories/connector-credentials.js';
import type { ConnectorsRepository } from '../db/repositories/connectors.js';

export type ConnectorDefinition =
  | {
      id: string;
      name: string;
      type: 'http';
      config: {
        url: string;
        authToken?: string;
        authScheme?: string;
        customHeaders?: Record<string, string>;
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
  oauthDiscovery?: OAuthServerInfo;
}

export class ConnectorManager {
  private readonly states = new Map<string, ConnectorState>();
  private readonly services?: {
    connectorCredentials: ConnectorCredentialsRepository;
    connectorRepo: ConnectorsRepository;
  };

  constructor(services?: {
    connectorCredentials: ConnectorCredentialsRepository;
    connectorRepo: ConnectorsRepository;
  }) {
    this.services = services;
  }

  async register(definition: Omit<ConnectorDefinition, 'id'> & { id?: string }): Promise<ConnectorDefinition> {
    const connector: ConnectorDefinition = { ...definition, id: definition.id ?? randomUUID() } as ConnectorDefinition;
    const adapter = this.makeAdapter(connector);

    // Attempt OAuth discovery for HTTP connectors (non-blocking)
    let oauthDiscovery: OAuthServerInfo | undefined;
    if (connector.type === 'http') {
      oauthDiscovery = (await tryDiscoverOAuth(connector.config.url)) ?? undefined;
    }

    const capabilities = await this.initializeConnector(connector, adapter);
    this.states.set(connector.name, { definition: connector, adapter, capabilities, oauthDiscovery });
    return connector;
  }

  list(): ConnectorDefinition[] {
    return [...this.states.values()].map((state) => state.definition);
  }

  get(name: string): ConnectorState | null {
    return this.states.get(name) ?? null;
  }

  /**
   * Get OAuth discovery info for a connector
   */
  getOAuthDiscovery(name: string): OAuthServerInfo | null {
    const state = this.states.get(name);
    return state?.oauthDiscovery ?? null;
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

  /**
   * Update custom headers for an HTTP connector
   */
  async updateCustomHeaders(name: string, customHeaders: Record<string, string>): Promise<ConnectorDefinition | null> {
    const state = this.states.get(name);
    if (!state) return null;
    if (state.definition.type !== 'http') return null;

    state.definition = {
      ...state.definition,
      config: {
        ...state.definition.config,
        customHeaders
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

  /**
   * Re-run OAuth discovery for a connector (e.g., after receiving 401 with resource_metadata)
   */
  async refreshOAuthDiscovery(name: string, resourceMetadataUrl?: string): Promise<OAuthServerInfo | null> {
    const state = this.states.get(name);
    if (!state) return null;
    if (state.definition.type !== 'http') return null;

    const discovery = await tryDiscoverOAuth(state.definition.config.url);
    if (discovery) {
      state.oauthDiscovery = discovery;
    }
    return discovery;
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

  private _makeTokenRefresher(
    connectorId: string,
    connectorUrl: string,
    connectorName: string
  ): (id: string) => Promise<string | null> {
    const { services } = this;
    if (!services) return async () => null;

    return async (_id: string) => {
      // 1. Load stored OAuth tokens
      const cred = await services.connectorCredentials.get(connectorId, 'oauth_tokens');
      const payload = cred?.payload;
      const refreshToken = typeof payload?.refreshToken === 'string' ? payload.refreshToken : null;
      if (!refreshToken) return null;

      // 2. Get client credentials (config_json.oauth first, then stored payload)
      const state = this.states.get(connectorName);
      const oauthCfg = state?.definition.type === 'http' ? state.definition.config.oauth : undefined;
      const clientId = oauthCfg?.clientId ?? (typeof payload?.clientId === 'string' ? payload.clientId : undefined);
      const clientSecret = oauthCfg?.clientSecret ?? (typeof payload?.clientSecret === 'string' ? payload.clientSecret : undefined);
      if (!clientId) return null;

      // 3. Discover token endpoint via RFC 9728
      let tokenEndpoint: string;
      try {
        const discovery = await tryDiscoverOAuth(connectorUrl);
        const endpoint = discovery?.authorizationServerMetadata?.token_endpoint;
        if (!endpoint) return null;
        tokenEndpoint = endpoint;
      } catch {
        return null;
      }

      // 4. POST refresh_token grant
      try {
        const form = new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: clientId,
        });
        if (clientSecret) form.set('client_secret', clientSecret);

        const res = await fetch(tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form.toString(),
        });

        if (!res.ok) {
          await services.connectorRepo.setHealth(connectorId, 'auth_failed', 'Refresh token expired - re-authenticate via admin');
          return null;
        }

        const data = (await res.json()) as {
          access_token?: string;
          refresh_token?: string;
          expires_in?: number;
          token_type?: string;
        };
        if (!data.access_token) return null;

        // 5. Persist new tokens (rotate refresh_token if server issued a new one)
        const expiresAt = data.expires_in
          ? new Date(Date.now() + data.expires_in * 1000).toISOString()
          : cred?.expiresAt ?? null;

        await services.connectorCredentials.upsert(
          connectorId,
          'oauth_tokens',
          {
            accessToken: data.access_token,
            refreshToken: data.refresh_token ?? refreshToken,
            tokenType: data.token_type ?? 'Bearer',
            clientId,
            ...(clientSecret ? { clientSecret } : {}),
          },
          expiresAt
        );

        return data.access_token;
      } catch {
        await services.connectorRepo.setHealth(connectorId, 'auth_failed', 'Token refresh failed - re-authenticate via admin');
        return null;
      }
    };
  }

  private makeAdapter(definition: ConnectorDefinition): ConnectorAdapter {
    if (definition.type === 'http') {
      // Only wire tokenRefresher for OAuth connectors (oauth field present = oauth_url mode).
      // api_header / none connectors get undefined so the existing 401 path is unchanged.
      const tokenRefresher = definition.config.oauth !== undefined && this.services
        ? this._makeTokenRefresher(definition.id, definition.config.url, definition.name)
        : undefined;

      return new HttpConnectorAdapter({
        id: definition.id,
        name: definition.name,
        url: definition.config.url,
        authToken: definition.config.authToken,
        authScheme: definition.config.authScheme,
        customHeaders: definition.config.customHeaders,
        tokenRefresher,
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
