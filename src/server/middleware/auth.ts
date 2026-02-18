import fp from 'fastify-plugin';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AppContext } from '../../app-context.js';

const ADMIN_SESSION_COOKIE = 'mgw_admin_session';

declare module 'fastify' {
  interface FastifyRequest {
    auth?: {
      tokenId: string;
      tokenPrefix: string;
      clientId: string;
    };
  }
}

function getBearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header) return null;
  const [scheme, token] = header.split(' ');
  if (!scheme || !token) return null;
  if (scheme.toLowerCase() !== 'bearer') return null;
  return token;
}

function parseCookies(request: FastifyRequest): Record<string, string> {
  const raw = request.headers.cookie;
  if (!raw) return {};

  const out: Record<string, string> = {};
  for (const chunk of raw.split(';')) {
    const [key, ...rest] = chunk.trim().split('=');
    if (!key) continue;
    out[key] = decodeURIComponent(rest.join('='));
  }
  return out;
}

export function buildSessionCookie(sessionId: string, secure: boolean): string {
  const attrs = [
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(sessionId)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax'
  ];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

export function clearSessionCookie(secure: boolean): string {
  const attrs = [
    `${ADMIN_SESSION_COOKIE}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0'
  ];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

export const authPlugin = fp<{ ctx: AppContext }>(async (fastify, opts) => {
  fastify.decorateRequest('auth', undefined);

  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    if (request.url.startsWith('/health')) return;
    if (request.url.startsWith('/.well-known/')) return;

    if (request.url.startsWith('/admin')) {
      const publicPaths = ['/admin', '/admin/', '/admin/app.js', '/admin/login', '/admin/oauth/callback'];
      if (publicPaths.some((path) => request.url === path || request.url.startsWith(`${path}?`))) {
        return;
      }

      if (request.url === '/admin/session' || request.url === '/admin/logout' || request.url.startsWith('/admin/connectors') || request.url.startsWith('/admin/clients') || request.url.startsWith('/admin/tokens') || request.url.startsWith('/admin/tool-catalog')) {
        const cookies = parseCookies(request);
        const sessionId = cookies[ADMIN_SESSION_COOKIE];
        if (!sessionId) {
          await reply.code(401).send({ error: 'Unauthorized' });
          return;
        }

        const valid = await opts.ctx.services.adminSessions.validateAndTouch(sessionId, opts.ctx.config.ADMIN_SESSION_HOURS);
        if (!valid) {
          await reply.code(401).send({ error: 'Unauthorized' });
          return;
        }
      }

      return;
    }

    if (!request.url.startsWith('/mcp')) return;

    const token = getBearerToken(request);
    if (!token) {
      await reply.code(401).send({ error: 'Missing bearer token' });
      return;
    }

    const validated = await opts.ctx.services.tokens.validate(token);
    if (!validated) {
      await reply.code(401).send({ error: 'Invalid token' });
      return;
    }

    const client = await opts.ctx.services.clients.get(validated.clientId);
    if (!client || !client.enabled) {
      await reply.code(401).send({ error: 'Client disabled' });
      return;
    }

    request.auth = {
      tokenId: validated.id,
      tokenPrefix: validated.tokenPrefix,
      clientId: client.id
    };
  });
});
