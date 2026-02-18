import type { AppConfig } from './config/schema.js';
import { ConnectorManager } from './connectors/manager.js';
import { TokenService } from './auth/tokens.js';
import { ClientsRepository } from './db/repositories/clients.js';
import { ConnectorsRepository } from './db/repositories/connectors.js';
import { SessionManager } from './mcp/session.js';
import { ClientPoliciesRepository } from './db/repositories/client-policies.js';
import { ToolCacheRepository } from './db/repositories/tool-cache.js';
import { ConnectorCredentialsRepository } from './db/repositories/connector-credentials.js';
import { AdminSessionsRepository } from './db/repositories/admin-sessions.js';

export interface Services {
  connectors: ConnectorManager;
  clients: ClientsRepository;
  connectorRepo: ConnectorsRepository;
  clientPolicies: ClientPoliciesRepository;
  connectorCredentials: ConnectorCredentialsRepository;
  toolCache: ToolCacheRepository;
  tokens: TokenService;
  adminSessions: AdminSessionsRepository;
  sessions: SessionManager;
}

export interface AppContext {
  config: AppConfig;
  services: Services;
}
