import { loadConfig } from './config/index.js';
import { ConnectorManager, type ConnectorDefinition } from './connectors/manager.js';
import { TokenService } from './auth/tokens.js';
import { ClientsRepository } from './db/repositories/clients.js';
import { ConnectorsRepository } from './db/repositories/connectors.js';
import { SessionManager } from './mcp/session.js';
import { buildServer } from './server/fastify.js';
import type { AppContext } from './app-context.js';
import { createDatabaseClient } from './db/client.js';
import { ClientPoliciesRepository } from './db/repositories/client-policies.js';
import { ToolCacheRepository } from './db/repositories/tool-cache.js';
import { ConnectorCredentialsRepository } from './db/repositories/connector-credentials.js';
import { AdminSessionsRepository } from './db/repositories/admin-sessions.js';
import { createEncryptionContext } from './security/crypto.js';

const DB_STARTUP_MAX_ATTEMPTS = 30;
const DB_STARTUP_RETRY_DELAY_MS = 1000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isTransientStartupDbError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const code = 'code' in error ? String(error.code) : '';
  return code === '57P03' || code === 'ECONNREFUSED' || code === 'ETIMEDOUT';
}

async function waitForDatabaseReady(db: ReturnType<typeof createDatabaseClient>): Promise<void> {
  for (let attempt = 1; attempt <= DB_STARTUP_MAX_ATTEMPTS; attempt += 1) {
    try {
      await db.query('SELECT 1');
      return;
    } catch (error) {
      if (!isTransientStartupDbError(error) || attempt === DB_STARTUP_MAX_ATTEMPTS) {
        throw error;
      }
      console.warn(
        `Database not ready yet (attempt ${attempt}/${DB_STARTUP_MAX_ATTEMPTS}), retrying in ${DB_STARTUP_RETRY_DELAY_MS}ms`
      );
      await sleep(DB_STARTUP_RETRY_DELAY_MS);
    }
  }
}

function toRuntimeConnector(
  entity: Awaited<ReturnType<ConnectorsRepository['list']>>[number],
  authToken?: string,
  authScheme = 'Bearer'
): ConnectorDefinition | null {
  if (entity.transport === 'http') {
    const url = entity.configJson.url;
    if (typeof url !== 'string') return null;
    return {
      id: entity.id,
      name: entity.name,
      type: 'http',
      enabled: entity.enabled,
      config: { url, ...(authToken ? { authToken } : {}), ...(authToken ? { authScheme } : {}) }
    };
  }

  const command = entity.configJson.command;
  if (typeof command !== 'string') return null;
  const args = Array.isArray(entity.configJson.args) ? entity.configJson.args.map(String) : undefined;
  const cwd = typeof entity.configJson.cwd === 'string' ? entity.configJson.cwd : undefined;
  const env = entity.configJson.env && typeof entity.configJson.env === 'object'
    ? Object.fromEntries(Object.entries(entity.configJson.env as Record<string, unknown>).map(([k, v]) => [k, String(v)]))
    : undefined;

  return {
    id: entity.id,
    name: entity.name,
    type: 'stdio',
    enabled: entity.enabled,
    config: { command, args, cwd, env }
  };
}

function normalizeAuthScheme(tokenType?: string): string {
  if (!tokenType) return 'Bearer';
  return tokenType.toLowerCase() === 'bearer' ? 'Bearer' : tokenType;
}

async function main() {
  const config = loadConfig();
  const encryption = createEncryptionContext(config.ENCRYPTION_KEY);
  const db = createDatabaseClient(config.DATABASE_URL);
  await waitForDatabaseReady(db);
  if (config.AUTO_MIGRATE) {
    await db.migrate();
  }

  const services: AppContext['services'] = {
    connectors: new ConnectorManager(),
    clients: new ClientsRepository(db),
    connectorRepo: new ConnectorsRepository(db),
    clientPolicies: new ClientPoliciesRepository(db),
    connectorCredentials: new ConnectorCredentialsRepository(db, encryption),
    toolCache: new ToolCacheRepository(db),
    tokens: new TokenService(db),
    adminSessions: new AdminSessionsRepository(db),
    sessions: new SessionManager()
  };

  const persistedConnectors = await services.connectorRepo.list();
  for (const connector of persistedConnectors) {
    try {
      const cred = await services.connectorCredentials.get(connector.id, 'oauth_tokens');
      const authToken = typeof cred?.payload.accessToken === 'string' ? cred.payload.accessToken : undefined;
      const authScheme = normalizeAuthScheme(typeof cred?.payload.tokenType === 'string' ? cred.payload.tokenType : 'Bearer');
      const runtimeConnector = toRuntimeConnector(connector, authToken, authScheme);
      if (!runtimeConnector) continue;

      await services.connectors.register(runtimeConnector);
      const runtime = services.connectors.get(runtimeConnector.name);
      if (runtime) {
        await services.toolCache.replaceForConnector(connector.id, runtime.capabilities.tools);
      }
    } catch (error) {
      console.error(`Failed to initialize persisted connector: ${connector.name}`, error);
    }
  }

  const ctx: AppContext = { config, services };
  const app = await buildServer(ctx);

  const address = await app.listen({ host: config.HOST, port: config.PORT });
  console.log(`MCP gateway listening at ${address}`);

  const shutdown = async () => {
    console.log('Shutting down gateway');
    await app.close();
    for (const connector of services.connectors.list()) {
      await services.connectors.remove(connector.name);
    }
    await db.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
