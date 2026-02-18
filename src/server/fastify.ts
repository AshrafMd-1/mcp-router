import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { resolve } from 'node:path';
import { authPlugin } from './middleware/auth.js';
import { registerMcpRoutes } from './routes/mcp.js';
import { registerAdminRoutes } from './routes/admin.js';
import type { AppContext } from '../app-context.js';

export async function buildServer(ctx: AppContext) {
  const app = Fastify({
    logger: false
  });

  await app.register(fastifyStatic, {
    root: resolve(process.cwd(), 'src/admin/ui'),
    prefix: '/admin/'
  });

  app.get('/health', async () => ({ status: 'ok', uptime: process.uptime() }));

  await app.register(authPlugin, { ctx });
  await registerMcpRoutes(app, ctx);
  await registerAdminRoutes(app, ctx);

  return app;
}
