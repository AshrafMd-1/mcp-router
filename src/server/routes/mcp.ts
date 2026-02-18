import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { MGatewayRouter } from '../../mcp/router.js';
import type { AppContext } from '../../app-context.js';
import type { JsonRpcRequest } from '../../mcp/protocol.js';

const jsonRpcSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string(), z.number(), z.null()]).optional(),
  method: z.string(),
  params: z.unknown().optional()
});

export async function registerMcpRoutes(app: FastifyInstance, ctx: AppContext): Promise<void> {
  const router = new MGatewayRouter(ctx);

  app.post('/mcp', async (request, reply) => {
    if (!request.auth) {
      return reply.code(200).send({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32001, message: 'UNAUTHORIZED' }
      });
    }

    const parsed = jsonRpcSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(200).send({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'INVALID_JSON_RPC_PAYLOAD' }
      });
    }

    const response = await router.handle(parsed.data as JsonRpcRequest, request.auth);
    return reply.code(200).send(response);
  });

  app.get('/mcp', async (request, reply) => {
    if (!request.auth) {
      return reply.code(401).send({ error: 'Unauthorized' });
    }

    reply.raw.setHeader('Content-Type', 'text/event-stream');
    reply.raw.setHeader('Cache-Control', 'no-cache');
    reply.raw.setHeader('Connection', 'keep-alive');

    const interval = setInterval(() => {
      reply.raw.write(`event: heartbeat\ndata: ${JSON.stringify({ t: Date.now() })}\n\n`);
    }, 15000);

    request.raw.on('close', () => {
      clearInterval(interval);
    });

    reply.raw.write(`event: ready\ndata: ${JSON.stringify({ session: request.headers['mcp-session-id'] ?? null })}\n\n`);
  });
}
