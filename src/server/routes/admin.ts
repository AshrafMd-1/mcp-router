import { createHash, randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { AppContext } from '../../app-context.js';
import { buildSessionCookie, clearSessionCookie } from '../middleware/auth.js';
import type { ConnectorDefinition } from '../../connectors/manager.js';

const loginSchema = z.object({ password: z.string().min(1) });

const connectorCreateSchema = z.object({
  name: z.string().min(1),
  mode: z.enum(['oauth_url', 'json_config']),
  transport: z.enum(['http', 'stdio']),
  enabled: z.boolean().default(true),
  configJson: z.record(z.unknown())
});

const connectorUpdateSchema = z.object({
  name: z.string().min(1).optional(),
  mode: z.enum(['oauth_url', 'json_config']).optional(),
  transport: z.enum(['http', 'stdio']).optional(),
  enabled: z.boolean().optional(),
  configJson: z.record(z.unknown()).optional()
});

const clientCreateSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional()
});

const clientUpdateSchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  enabled: z.boolean().optional()
});

const policyUpdateSchema = z.object({
  connectorIds: z.array(z.string()),
  allowedTools: z.array(z.string()),
  deniedTools: z.array(z.string()).optional().default([])
});

function sanitizeConfig(configJson: Record<string, unknown>) {
  const cloned: Record<string, unknown> = { ...configJson };
  for (const key of Object.keys(cloned)) {
    const lower = key.toLowerCase();
    if (lower.includes('token') || lower.includes('secret') || lower.includes('password')) {
      cloned[key] = '***redacted***';
    }
  }
  return cloned;
}

function toRuntimeConnector(
  name: string,
  id: string,
  transport: 'http' | 'stdio',
  configJson: Record<string, unknown>,
  authToken?: string,
  authScheme = 'Bearer'
): ConnectorDefinition {
  if (transport === 'http') {
    const url = typeof configJson.url === 'string' ? configJson.url : '';

    // SDK-aligned: Extract custom headers from configJson.headers
    const customHeaders = configJson.headers && typeof configJson.headers === 'object'
      ? configJson.headers as Record<string, string>
      : undefined;

    return {
      id,
      name,
      type: 'http',
      enabled: true,
      config: {
        url,
        ...(authToken ? { authToken } : {}),
        ...(authToken ? { authScheme } : {}),
        ...(customHeaders ? { customHeaders } : {}),
        ...(configJson.oauth && typeof configJson.oauth === 'object' ? { oauth: configJson.oauth as any } : {})
      }
    };
  }

  const command = String(configJson.command ?? '');
  const args = Array.isArray(configJson.args) ? configJson.args.map(String) : undefined;
  const cwd = typeof configJson.cwd === 'string' ? configJson.cwd : undefined;
  const env = configJson.env && typeof configJson.env === 'object'
    ? Object.fromEntries(Object.entries(configJson.env as Record<string, unknown>).map(([k, v]) => [k, String(v)]))
    : undefined;

  return {
    id,
    name,
    type: 'stdio',
    enabled: true,
    config: { command, args, cwd, env }
  };
}

function parseBearerFromAuthHeader(authHeader?: string): string | undefined {
  if (!authHeader) return undefined;
  const [scheme, token] = authHeader.split(' ');
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') return undefined;
  return token;
}

function normalizeAuthScheme(tokenType?: string): string {
  if (!tokenType) return 'Bearer';
  return tokenType.toLowerCase() === 'bearer' ? 'Bearer' : tokenType;
}

export async function registerAdminRoutes(app: FastifyInstance, ctx: AppContext): Promise<void> {
  const base = '/admin';

  const oauthState = new Map<
    string,
    {
      connectorId: string;
      resource?: string;
      audience?: string;
      scope?: string;
      tokenEndpoint: string;
      clientId: string;
      clientSecret?: string;
      codeVerifier: string;
      redirectUri: string;
    }
  >();

  async function discoverOAuth(resourceUrl: string) {
    const target = new URL(resourceUrl);
    const path = target.pathname.replace(/\/$/, '');
    const candidates = [
      ...(path && path !== '/' ? [new URL(`/.well-known/oauth-protected-resource${path}`, target.origin).toString()] : []),
      new URL('/.well-known/oauth-protected-resource', target.origin).toString(),
      new URL('/.well-known/oauth-authorization-server', target.origin).toString(),
      new URL('/.well-known/openid-configuration', target.origin).toString()
    ];

    for (const url of candidates) {
      try {
        const res = await fetch(url);
        if (!res.ok) continue;
        const data = (await res.json()) as Record<string, unknown>;
        if (data.authorization_endpoint && data.token_endpoint) {
          return {
            authorizationEndpoint: String(data.authorization_endpoint),
            tokenEndpoint: String(data.token_endpoint),
            registrationEndpoint: data.registration_endpoint ? String(data.registration_endpoint) : undefined,
            resource: typeof data.resource === 'string' ? data.resource : undefined,
            scopesSupported: Array.isArray(data.scopes_supported)
              ? data.scopes_supported.map(String).filter(Boolean)
              : undefined
          };
        }
        if (Array.isArray(data.authorization_servers) && data.authorization_servers.length > 0) {
          const issuer = String(data.authorization_servers[0]);
          const metaRes = await fetch(new URL('/.well-known/oauth-authorization-server', issuer).toString());
          if (!metaRes.ok) continue;
          const meta = (await metaRes.json()) as Record<string, unknown>;
          if (meta.authorization_endpoint && meta.token_endpoint) {
            return {
              authorizationEndpoint: String(meta.authorization_endpoint),
              tokenEndpoint: String(meta.token_endpoint),
              registrationEndpoint: meta.registration_endpoint ? String(meta.registration_endpoint) : undefined,
              resource: typeof data.resource === 'string' ? data.resource : undefined,
              scopesSupported: Array.isArray(data.scopes_supported)
                ? data.scopes_supported.map(String).filter(Boolean)
                : undefined
            };
          }
        }
      } catch {
        continue;
      }
    }

    throw new Error('OAuth discovery failed for this MCP URL');
  }

  async function registerDynamicClient(registrationEndpoint: string, redirectUri: string) {
    const payload = {
      client_name: 'mcp-gateway',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none'
    };

    const res = await fetch(registrationEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      throw new Error(`Dynamic client registration failed (${res.status})`);
    }

    const json = (await res.json()) as { client_id?: string; client_secret?: string };
    if (!json.client_id) {
      throw new Error('Dynamic client registration returned no client_id');
    }

    return { clientId: json.client_id, clientSecret: json.client_secret };
  }

  app.post(`${base}/login`, async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    if (parsed.data.password !== ctx.config.ADMIN_TOKEN) {
      return reply.code(401).send({ error: 'Invalid credentials' });
    }

    const sessionId = await ctx.services.adminSessions.create(ctx.config.ADMIN_SESSION_HOURS);
    const secure = request.protocol === 'https';
    reply.header('Set-Cookie', buildSessionCookie(sessionId, secure));
    return { ok: true };
  });

  app.post(`${base}/logout`, async (request, reply) => {
    const raw = request.headers.cookie ?? '';
    const cookie = raw
      .split(';')
      .map((s) => s.trim())
      .find((s) => s.startsWith('mgw_admin_session='));

    const sessionId = cookie ? decodeURIComponent(cookie.slice('mgw_admin_session='.length)) : null;
    if (sessionId) await ctx.services.adminSessions.delete(sessionId);

    const secure = request.protocol === 'https';
    reply.header('Set-Cookie', clearSessionCookie(secure));
    return { ok: true };
  });

  app.get(`${base}/session`, async () => ({ authenticated: true, username: 'admin' }));

  app.get(`${base}/connectors`, async () => {
    const connectors = await ctx.services.connectorRepo.list();
    return {
      connectors: connectors.map((c) => ({
        ...c,
        configJson: sanitizeConfig(c.configJson)
      }))
    };
  });

  app.post(`${base}/connectors`, async (request, reply) => {
    const parsed = connectorCreateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const body = parsed.data;
    if (body.transport === 'http' && typeof body.configJson.url !== 'string') {
      return reply.code(400).send({ error: 'HTTP connector requires configJson.url' });
    }
    if (body.transport === 'stdio' && typeof body.configJson.command !== 'string') {
      return reply.code(400).send({ error: 'stdio connector requires configJson.command' });
    }

    const created = await ctx.services.connectorRepo.create({
      name: body.name,
      mode: body.mode,
      transport: body.transport,
      enabled: body.enabled,
      configJson: body.configJson
    });

    const authToken = parseBearerFromAuthHeader(typeof created.configJson.Authorization === 'string' ? created.configJson.Authorization : undefined)
      ?? (typeof created.configJson.authToken === 'string' ? created.configJson.authToken : undefined);

    const runtime = toRuntimeConnector(created.name, created.id, created.transport, created.configJson, authToken, normalizeAuthScheme('Bearer'));
    try {
      await ctx.services.connectors.register(runtime);
      const state = ctx.services.connectors.get(created.name);
      if (state) {
        await ctx.services.toolCache.replaceForConnector(created.id, state.capabilities.tools);
        const health = await state.adapter.checkHealth();
        await ctx.services.connectorRepo.setHealth(created.id, health.status, health.error);
      }
      if (authToken) {
        await ctx.services.connectorCredentials.upsert(created.id, 'api_header', { authToken }, null);
      }
    } catch (error) {
      await ctx.services.connectorRepo.setHealth(created.id, 'unhealthy', error instanceof Error ? error.message : 'Init failed');
    }

    return reply.code(201).send({ ...created, configJson: sanitizeConfig(created.configJson) });
  });

  app.put(`${base}/connectors/:id`, async (request, reply) => {
    const parsed = connectorUpdateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const id = (request.params as { id: string }).id;
    const updated = await ctx.services.connectorRepo.update(id, parsed.data);
    if (!updated) return reply.code(404).send({ error: 'Connector not found' });

    await ctx.services.connectors.remove(updated.name);
    const cred = await ctx.services.connectorCredentials.get(id, 'oauth_tokens');
    const authToken = typeof cred?.payload.accessToken === 'string' ? cred.payload.accessToken : undefined;
    const authScheme = normalizeAuthScheme(typeof cred?.payload.tokenType === 'string' ? cred.payload.tokenType : 'Bearer');
    const runtime = toRuntimeConnector(updated.name, updated.id, updated.transport, updated.configJson, authToken, authScheme);

    try {
      await ctx.services.connectors.register(runtime);
      const state = ctx.services.connectors.get(updated.name);
      if (state) {
        await ctx.services.toolCache.replaceForConnector(updated.id, state.capabilities.tools);
        const health = await state.adapter.checkHealth();
        await ctx.services.connectorRepo.setHealth(updated.id, health.status, health.error);
      }
    } catch (error) {
      await ctx.services.connectorRepo.setHealth(updated.id, 'unhealthy', error instanceof Error ? error.message : 'Init failed');
    }

    return { ...updated, configJson: sanitizeConfig(updated.configJson) };
  });

  app.delete(`${base}/connectors/:id`, async (request, reply) => {
    const id = (request.params as { id: string }).id;
    const connector = await ctx.services.connectorRepo.getById(id);
    if (!connector) return reply.code(404).send({ error: 'Connector not found' });

    const usageCount = await ctx.services.clientPolicies.countUsingConnector(id);
    if (usageCount > 0) {
      const clientNames = await ctx.services.clientPolicies.listClientNamesUsingConnector(id);
      return reply.code(409).send({
        error: `Connector is used by clients: ${clientNames.join(', ')}`
      });
    }

    await ctx.services.connectors.remove(connector.name);
    await ctx.services.connectorCredentials.removeByConnector(id);
    await ctx.services.connectorRepo.remove(id);
    return reply.code(204).send();
  });

  app.post(`${base}/connectors/:id/discover`, async (request, reply) => {
    const id = (request.params as { id: string }).id;
    const connector = await ctx.services.connectorRepo.getById(id);
    if (!connector) return reply.code(404).send({ error: 'Connector not found' });

    let state = ctx.services.connectors.get(connector.name);
    if (!state) {
      const oauthCred = await ctx.services.connectorCredentials.get(id, 'oauth_tokens');
      const apiCred = await ctx.services.connectorCredentials.get(id, 'api_header');
      const oauthToken = typeof oauthCred?.payload.accessToken === 'string' ? oauthCred.payload.accessToken : undefined;
      const oauthScheme = normalizeAuthScheme(typeof oauthCred?.payload.tokenType === 'string' ? oauthCred.payload.tokenType : 'Bearer');
      const apiToken = typeof apiCred?.payload.authToken === 'string' ? apiCred.payload.authToken : undefined;
      const runtime = toRuntimeConnector(
        connector.name,
        connector.id,
        connector.transport,
        connector.configJson,
        oauthToken ?? apiToken,
        oauthToken ? oauthScheme : 'Bearer'
      );
      try {
        await ctx.services.connectors.register(runtime);
      } catch (error) {
        return reply.code(400).send({ error: error instanceof Error ? error.message : 'Connector runtime not initialized' });
      }
      state = ctx.services.connectors.get(connector.name);
    }
    if (!state) return reply.code(404).send({ error: 'Connector runtime not initialized' });

    try {
      const capabilities = await ctx.services.connectors.refresh(connector.name);
      await ctx.services.toolCache.replaceForConnector(id, capabilities.tools);
      return { tools: capabilities.tools.length, resources: capabilities.resources.length, prompts: capabilities.prompts.length };
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : 'Discover failed' });
    }
  });

  app.get(`${base}/connectors/:id/health`, async (request, reply) => {
    const id = (request.params as { id: string }).id;
    const connector = await ctx.services.connectorRepo.getById(id);
    if (!connector) return reply.code(404).send({ error: 'Connector not found' });

    let state = ctx.services.connectors.get(connector.name);
    if (!state) {
      const oauthCred = await ctx.services.connectorCredentials.get(id, 'oauth_tokens');
      const apiCred = await ctx.services.connectorCredentials.get(id, 'api_header');
      const oauthToken = typeof oauthCred?.payload.accessToken === 'string' ? oauthCred.payload.accessToken : undefined;
      const oauthScheme = normalizeAuthScheme(typeof oauthCred?.payload.tokenType === 'string' ? oauthCred.payload.tokenType : 'Bearer');
      const apiToken = typeof apiCred?.payload.authToken === 'string' ? apiCred.payload.authToken : undefined;
      const runtime = toRuntimeConnector(
        connector.name,
        connector.id,
        connector.transport,
        connector.configJson,
        oauthToken ?? apiToken,
        oauthToken ? oauthScheme : 'Bearer'
      );
      try {
        await ctx.services.connectors.register(runtime);
      } catch (error) {
        return { status: 'unhealthy', error: error instanceof Error ? error.message : 'Connector runtime not initialized' };
      }
      state = ctx.services.connectors.get(connector.name);
    }
    if (!state) return { status: 'unhealthy', error: 'Connector runtime not initialized' };

    const health = await state.adapter.checkHealth();
    await ctx.services.connectorRepo.setHealth(id, health.status, health.error);
    return health;
  });

  app.post(`${base}/connectors/:id/oauth/start`, async (request, reply) => {
    const id = (request.params as { id: string }).id;
    const connector = await ctx.services.connectorRepo.getById(id);
    if (!connector) return reply.code(404).send({ error: 'Connector not found' });
    if (connector.mode !== 'oauth_url' || connector.transport !== 'http') {
      return reply.code(400).send({ error: 'OAuth start is only supported for oauth_url HTTP connectors' });
    }

    const resource = typeof connector.configJson.url === 'string' ? connector.configJson.url : '';
    if (!resource) return reply.code(400).send({ error: 'Connector URL missing' });

    let metadata: {
      authorizationEndpoint: string;
      tokenEndpoint: string;
      registrationEndpoint?: string;
      resource?: string;
      scopesSupported?: string[];
    };
    try {
      metadata = await discoverOAuth(resource);
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : 'OAuth discovery failed' });
    }

    const host = request.headers.host ?? request.hostname;
    const redirectUri = `${request.protocol}://${host}/admin/oauth/callback`;

    let clientId: string | undefined;
    let clientSecret: string | undefined;

    const oauthCfg = connector.configJson.oauth && typeof connector.configJson.oauth === 'object'
      ? (connector.configJson.oauth as Record<string, unknown>)
      : undefined;
    const configuredResource = typeof oauthCfg?.resource === 'string' ? oauthCfg.resource : undefined;
    const configuredAudience = typeof oauthCfg?.audience === 'string' ? oauthCfg.audience : undefined;
    const configuredScope = typeof oauthCfg?.scope === 'string' ? oauthCfg.scope : undefined;
    // Keep runtime OAuth requests minimal by default.
    // Send resource only when explicitly configured for the connector.
    const effectiveResource = configuredResource;
    // Audience is provider/client specific and often requires per-client whitelisting.
    // Only send it when explicitly configured for this connector.
    const effectiveAudience = configuredAudience;

    if (oauthCfg?.clientId && typeof oauthCfg.clientId === 'string') {
      clientId = oauthCfg.clientId;
      clientSecret = typeof oauthCfg.clientSecret === 'string' ? oauthCfg.clientSecret : undefined;
    } else if (metadata.registrationEndpoint) {
      try {
        const reg = await registerDynamicClient(metadata.registrationEndpoint, redirectUri);
        clientId = reg.clientId;
        clientSecret = reg.clientSecret;
      } catch (error) {
        return reply.code(400).send({ error: error instanceof Error ? error.message : 'Dynamic registration failed' });
      }
    } else {
      return reply.code(400).send({ error: 'OAuth provider does not support dynamic registration for URL-only flow' });
    }

    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const state = randomBytes(16).toString('hex');

    oauthState.set(state, {
      connectorId: connector.id,
      resource: effectiveResource,
      audience: effectiveAudience,
      scope: configuredScope,
      tokenEndpoint: metadata.tokenEndpoint,
      clientId,
      clientSecret,
      codeVerifier,
      redirectUri
    });

    const authUrl = new URL(metadata.authorizationEndpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    if (effectiveResource) authUrl.searchParams.set('resource', effectiveResource);
    if (effectiveAudience) authUrl.searchParams.set('audience', effectiveAudience);
    if (configuredScope) authUrl.searchParams.set('scope', configuredScope);
    authUrl.searchParams.set('state', state);

    return { url: authUrl.toString(), state };
  });

  app.get(`${base}/oauth/callback`, async (request, reply) => {
    const query = request.query as { code?: string; state?: string; error?: string };
    if (query.error) return reply.code(400).type('text/html').send(`<h3>OAuth failed: ${query.error}</h3>`);
    if (!query.code || !query.state) return reply.code(400).type('text/html').send('<h3>Missing code or state</h3>');

    const flow = oauthState.get(query.state);
    if (!flow) return reply.code(400).type('text/html').send('<h3>Invalid state</h3>');
    oauthState.delete(query.state);

    const form = new URLSearchParams();
    form.set('grant_type', 'authorization_code');
    form.set('code', query.code);
    form.set('redirect_uri', flow.redirectUri);
    form.set('client_id', flow.clientId);
    form.set('code_verifier', flow.codeVerifier);
    if (flow.resource) form.set('resource', flow.resource);
    if (flow.audience) form.set('audience', flow.audience);
    if (flow.scope) form.set('scope', flow.scope);
    if (flow.clientSecret) form.set('client_secret', flow.clientSecret);

    const tokenRes = await fetch(flow.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString()
    });

    if (!tokenRes.ok) {
      const detail = await tokenRes.text();
      return reply.code(400).type('text/html').send(`<h3>OAuth token exchange failed</h3><pre>${detail}</pre>`);
    }

    const tokenPayload = (await tokenRes.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
      token_type?: string;
    };

    if (!tokenPayload.access_token) {
      return reply.code(400).type('text/html').send('<h3>OAuth token response missing access_token</h3>');
    }

    const expiresAt = tokenPayload.expires_in
      ? new Date(Date.now() + tokenPayload.expires_in * 1000).toISOString()
      : null;

    await ctx.services.connectorCredentials.upsert(
      flow.connectorId,
      'oauth_tokens',
      {
        accessToken: tokenPayload.access_token,
        refreshToken: tokenPayload.refresh_token,
        tokenType: normalizeAuthScheme(tokenPayload.token_type)
      },
      expiresAt
    );

    const connector = await ctx.services.connectorRepo.getById(flow.connectorId);
    if (connector) {
      try {
        await ctx.services.connectors.remove(connector.name);
        const runtime = toRuntimeConnector(
          connector.name,
          connector.id,
          connector.transport,
          connector.configJson,
          tokenPayload.access_token,
          normalizeAuthScheme(tokenPayload.token_type)
        );
        await ctx.services.connectors.register(runtime);
        const state = ctx.services.connectors.get(connector.name);
        if (state) {
          await ctx.services.toolCache.replaceForConnector(connector.id, state.capabilities.tools);
          const health = await state.adapter.checkHealth();
          await ctx.services.connectorRepo.setHealth(connector.id, health.status, health.error);
        }
      } catch (error) {
        const detail = error instanceof Error ? error.message : 'Connector re-initialization failed';
        await ctx.services.connectorRepo.setHealth(connector.id, 'unhealthy', detail);
        return reply.type('text/html').send(`<html><body><h2>OAuth token saved.</h2><p>Connector validation failed: ${detail}</p><script>if(window.opener&&window.opener!==window){window.opener.postMessage({type:'oauth-complete',ok:false,connectorId:'${connector.id}'},window.location.origin);}window.close();</script></body></html>`);
      }
    }

    return reply.type('text/html').send(`<html><body><h2>OAuth connected successfully.</h2><script>if(window.opener&&window.opener!==window){window.opener.postMessage({type:'oauth-complete',ok:true,connectorId:'${flow.connectorId}'},window.location.origin);}window.close();</script></body></html>`);
  });

  app.get(`${base}/clients`, async () => ({ clients: await ctx.services.clients.list() }));

  app.post(`${base}/clients`, async (request, reply) => {
    const parsed = clientCreateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const client = await ctx.services.clients.create(parsed.data as { name: string; description?: string });
    await ctx.services.clientPolicies.ensure(client.id);
    return reply.code(201).send(client);
  });

  app.put(`${base}/clients/:id`, async (request, reply) => {
    const parsed = clientUpdateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const client = await ctx.services.clients.update((request.params as { id: string }).id, parsed.data);
    if (!client) return reply.code(404).send({ error: 'Client not found' });
    return client;
  });

  app.delete(`${base}/clients/:id`, async (request, reply) => {
    const ok = await ctx.services.clients.remove((request.params as { id: string }).id);
    if (!ok) return reply.code(404).send({ error: 'Client not found' });
    return reply.code(204).send();
  });

  app.get(`${base}/clients/:id/policy`, async (request, reply) => {
    const clientId = (request.params as { id: string }).id;
    const client = await ctx.services.clients.get(clientId);
    if (!client) return reply.code(404).send({ error: 'Client not found' });

    const policy = await ctx.services.clientPolicies.ensure(clientId);
    return { policy };
  });

  app.put(`${base}/clients/:id/policy`, async (request, reply) => {
    const clientId = (request.params as { id: string }).id;
    const parsed = policyUpdateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const client = await ctx.services.clients.get(clientId);
    if (!client) return reply.code(404).send({ error: 'Client not found' });

    const connectors = await ctx.services.connectorRepo.list();
    const validConnectorIds = new Set(connectors.map((c) => c.id));
    for (const cid of parsed.data.connectorIds) {
      if (!validConnectorIds.has(cid)) {
        return reply.code(400).send({ error: `Unknown connector id: ${cid}` });
      }
    }

    const policy = await ctx.services.clientPolicies.setForClient(clientId, {
      connectorIds: parsed.data.connectorIds,
      allowedTools: parsed.data.allowedTools,
      deniedTools: parsed.data.deniedTools
    });
    return { policy };
  });

  app.get(`${base}/clients/:id/tokens`, async (request, reply) => {
    const clientId = (request.params as { id: string }).id;
    const client = await ctx.services.clients.get(clientId);
    if (!client) return reply.code(404).send({ error: 'Client not found' });
    const tokens = await ctx.services.tokens.listByClient(clientId);
    return {
      tokens: tokens.map((token) => ({
        id: token.id,
        tokenPrefix: token.tokenPrefix,
        createdAt: token.createdAt,
        revokedAt: token.revokedAt,
        lastUsedAt: token.lastUsedAt
      }))
    };
  });

  app.post(`${base}/clients/:id/tokens`, async (request, reply) => {
    const clientId = (request.params as { id: string }).id;
    const client = await ctx.services.clients.get(clientId);
    if (!client) return reply.code(404).send({ error: 'Client not found' });

    const token = await ctx.services.tokens.issue(clientId);
    return reply.code(201).send({
      id: token.id,
      token: token.plainToken,
      clientId: token.clientId,
      createdAt: token.createdAt,
      tokenPrefix: token.tokenPrefix
    });
  });

  app.delete(`${base}/clients/:id/tokens/:tokenId`, async (request, reply) => {
    const params = request.params as { id: string; tokenId: string };
    const client = await ctx.services.clients.get(params.id);
    if (!client) return reply.code(404).send({ error: 'Client not found' });
    const token = await ctx.services.tokens.get(params.tokenId);
    if (!token || token.clientId !== params.id) return reply.code(404).send({ error: 'Token not found' });
    const ok = await ctx.services.tokens.revoke(params.tokenId);
    if (!ok) return reply.code(404).send({ error: 'Token not found' });
    return reply.code(204).send();
  });

  app.delete(`${base}/tokens/:id`, async (request, reply) => {
    const tokenId = (request.params as { id: string }).id;
    const ok = await ctx.services.tokens.revoke(tokenId);
    if (!ok) return reply.code(404).send({ error: 'Token not found' });
    return reply.code(204).send();
  });

  app.post(`${base}/tokens/:id/rotate`, async (request, reply) => {
    const tokenId = (request.params as { id: string }).id;
    const existing = await ctx.services.tokens.get(tokenId);
    if (!existing) return reply.code(404).send({ error: 'Token not found' });

    await ctx.services.tokens.revoke(tokenId);
    const token = await ctx.services.tokens.issue(existing.clientId);
    return reply.code(201).send({
      id: token.id,
      token: token.plainToken,
      clientId: token.clientId,
      createdAt: token.createdAt,
      tokenPrefix: token.tokenPrefix
    });
  });

  app.get(`${base}/tool-catalog`, async (request, reply) => {
    const connectorId = (request.query as { connectorId?: string }).connectorId;
    if (!connectorId) return reply.code(400).send({ error: 'connectorId is required' });

    const connector = await ctx.services.connectorRepo.getById(connectorId);
    if (!connector) return reply.code(404).send({ error: 'Connector not found' });

    const runtime = ctx.services.connectors.get(connector.name);
    const cached = await ctx.services.toolCache.listByConnector(connectorId);

    if (!runtime) {
      return {
        stale: true,
        tools: cached.map((t) => ({
          name: `${connector.name}.${t.name}`,
          title: t.title,
          description: t.description,
          inputSchema: t.inputSchema,
          isReadOnly: t.isReadOnly,
          cachedAt: t.cachedAt
        }))
      };
    }

    return {
      stale: false,
      tools: runtime.capabilities.tools.map((t) => ({ ...t, name: `${connector.name}.${t.name}` }))
    };
  });
}
