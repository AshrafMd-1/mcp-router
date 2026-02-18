import type { AppContext } from '../app-context.js';
import type { JsonRpcRequest, JsonRpcResponse, ToolCallParams } from './protocol.js';
import { isToolAllowed } from './policy-evaluator.js';
import { mapDownstreamError } from './error-mapper.js';
import type { ToolDefinition } from './protocol.js';

export class MGatewayRouter {
  constructor(private readonly ctx: AppContext) {}

  async handle(request: JsonRpcRequest, auth: NonNullable<import('fastify').FastifyRequest['auth']>): Promise<JsonRpcResponse> {
    const policy = await this.ctx.services.clientPolicies.getByClientId(auth.clientId);
    if (!policy) {
      return this.error(request.id ?? null, -32020, 'POLICY_NOT_FOUND');
    }

    try {
      switch (request.method) {
        case 'initialize': {
          const session = this.ctx.services.sessions.create(auth.clientId);
          return this.success(request.id ?? null, {
            protocolVersion: '2025-06-18',
            capabilities: { tools: {}, resources: {}, prompts: {} },
            serverInfo: { name: 'mcp-gateway', version: '1.0.0' },
            sessionId: session.id
          });
        }

        case 'tools/list': {
          const tools: Array<ReturnType<typeof this.toExternalToolDef>> = [];
          for (const connector of this.ctx.services.connectors.list()) {
            if (!policy.connectorIds.includes(connector.id)) continue;
            const state = this.ctx.services.connectors.get(connector.name);
            if (!state) continue;
            for (const tool of state.capabilities.tools) {
              const internalName = `${connector.name}.${tool.name}`;
              if (!isToolAllowed(policy, internalName, connector.id).allowed) continue;
              tools.push(this.toExternalToolDef(connector.name, tool));
            }
          }
          return this.success(request.id ?? null, { tools });
        }

        case 'tools/call': {
          const params = request.params as ToolCallParams;
          if (!params?.name) {
            return this.error(request.id ?? null, -32602, 'INVALID_PARAMS');
          }
          const resolved = this.resolveExternalToolName(params.name, policy);
          if (!resolved) return this.error(request.id ?? null, -32020, 'INVALID_TOOL_NAME');
          if (resolved.ambiguous) return this.error(request.id ?? null, -32020, 'AMBIGUOUS_TOOL_NAME');
          const { connectorState, innerTool, internalName, tool } = resolved;
          const allowed = isToolAllowed(policy, internalName, connectorState.definition.id);
          if (!allowed.allowed) return this.error(request.id ?? null, -32020, allowed.reason ?? 'POLICY_DENIED');
          const validation = this.validateArgs(tool.inputSchema, params.arguments ?? {});
          if (!validation.valid) return this.error(request.id ?? null, -32602, `INVALID_PARAMS: ${validation.reason}`);

          try {
            const result = await connectorState.adapter.callTool(innerTool, params.arguments ?? {});
            return this.success(request.id ?? null, result);
          } catch (error) {
            const mapped = mapDownstreamError(error);
            return this.error(request.id ?? null, mapped.code, mapped.message);
          }
        }

        case 'resources/list': {
          const resources = this.ctx.services.connectors
            .list()
            .filter((connector) => policy.connectorIds.includes(connector.id))
            .flatMap((connector) => {
              const state = this.ctx.services.connectors.get(connector.name);
              if (!state) return [];
              return state.capabilities.resources.map((resource) => ({ ...resource, uri: `${connector.name}:${resource.uri}` }));
            });
          return this.success(request.id ?? null, { resources });
        }

        case 'resources/read': {
          const params = (request.params ?? {}) as { uri?: string };
          if (!params.uri) return this.error(request.id ?? null, -32602, 'INVALID_PARAMS');
          const [connectorName, rawUri] = this.parseColon(params.uri);
          if (!connectorName || !rawUri) return this.error(request.id ?? null, -32602, 'INVALID_URI');

          const connectorState = this.ctx.services.connectors.get(connectorName);
          if (!connectorState) return this.error(request.id ?? null, -32020, 'UNKNOWN_CONNECTOR');
          if (!policy.connectorIds.includes(connectorState.definition.id)) {
            return this.error(request.id ?? null, -32020, 'POLICY_DENIED');
          }

          try {
            const result = await connectorState.adapter.readResource(rawUri);
            return this.success(request.id ?? null, result);
          } catch (error) {
            const mapped = mapDownstreamError(error);
            return this.error(request.id ?? null, mapped.code, mapped.message);
          }
        }

        case 'prompts/list': {
          const prompts = this.ctx.services.connectors
            .list()
            .filter((connector) => policy.connectorIds.includes(connector.id))
            .flatMap((connector) => {
              const state = this.ctx.services.connectors.get(connector.name);
              if (!state) return [];
              return state.capabilities.prompts.map((prompt) => ({ ...prompt, name: `${connector.name}.${prompt.name}` }));
            });
          return this.success(request.id ?? null, { prompts });
        }

        case 'prompts/get': {
          const params = (request.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
          if (!params.name) return this.error(request.id ?? null, -32602, 'INVALID_PARAMS');
          const [connectorName, promptName] = this.parseNamespaced(params.name);
          if (!connectorName || !promptName) return this.error(request.id ?? null, -32602, 'INVALID_PROMPT_NAME');

          const connectorState = this.ctx.services.connectors.get(connectorName);
          if (!connectorState) return this.error(request.id ?? null, -32020, 'UNKNOWN_CONNECTOR');
          if (!policy.connectorIds.includes(connectorState.definition.id)) {
            return this.error(request.id ?? null, -32020, 'POLICY_DENIED');
          }

          try {
            const result = await connectorState.adapter.getPrompt(promptName, params.arguments ?? {});
            return this.success(request.id ?? null, result);
          } catch (error) {
            const mapped = mapDownstreamError(error);
            return this.error(request.id ?? null, mapped.code, mapped.message);
          }
        }

        default:
          return this.error(request.id ?? null, -32601, 'METHOD_NOT_SUPPORTED');
      }
    } catch {
      return this.error(request.id ?? null, -32000, 'GATEWAY_ERROR');
    }
  }

  private parseNamespaced(name: string): [string | null, string | null] {
    const parts = name.split('.');
    if (parts.length < 2) return [null, null];
    return [parts[0] ?? null, parts.slice(1).join('.') || null];
  }

  private sanitizeToolPart(value: string): string {
    const out = value.replace(/[^a-zA-Z0-9_-]/g, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '');
    return out || 'x';
  }

  private toExternalToolName(connectorName: string, toolName: string): string {
    return `${this.sanitizeToolPart(connectorName)}__${this.sanitizeToolPart(toolName)}`;
  }

  private toExternalToolDef(connectorName: string, tool: { name: string; title?: string; description?: string; inputSchema?: unknown; isReadOnly?: boolean }) {
    return {
      ...tool,
      name: this.toExternalToolName(connectorName, tool.name)
    };
  }

  private resolveExternalToolName(
    externalName: string,
    policy: Awaited<ReturnType<AppContext['services']['clientPolicies']['getByClientId']>>
  ): {
    connectorState: NonNullable<ReturnType<AppContext['services']['connectors']['get']>>;
    innerTool: string;
    internalName: string;
    tool: ToolDefinition;
    ambiguous?: boolean;
  } | null {
    const matches: Array<{
      connectorState: NonNullable<ReturnType<AppContext['services']['connectors']['get']>>;
      innerTool: string;
      internalName: string;
      tool: ToolDefinition;
    }> = [];

    for (const connector of this.ctx.services.connectors.list()) {
      if (!policy?.connectorIds.includes(connector.id)) continue;
      const state = this.ctx.services.connectors.get(connector.name);
      if (!state) continue;
      for (const tool of state.capabilities.tools) {
        const candidate = this.toExternalToolName(connector.name, tool.name);
        if (candidate !== externalName) continue;
        matches.push({
          connectorState: state,
          innerTool: tool.name,
          internalName: `${connector.name}.${tool.name}`,
          tool
        });
      }
    }

    if (matches.length === 0) return null;
    if (matches.length > 1) return { ...matches[0], ambiguous: true };
    return matches[0];
  }

  private validateArgs(schema: unknown, args: Record<string, unknown>): { valid: boolean; reason?: string } {
    if (!schema || typeof schema !== 'object') return { valid: true };
    const s = schema as Record<string, unknown>;
    const expectedType = s.type;
    if (expectedType && expectedType !== 'object') return { valid: true };
    if (args === null || Array.isArray(args) || typeof args !== 'object') {
      return { valid: false, reason: 'arguments must be an object' };
    }

    const props = s.properties && typeof s.properties === 'object'
      ? (s.properties as Record<string, Record<string, unknown>>)
      : {};
    const required = Array.isArray(s.required) ? s.required.filter((x): x is string => typeof x === 'string') : [];

    for (const key of required) {
      if (!(key in args)) return { valid: false, reason: `missing required field: ${key}` };
    }

    if (s.additionalProperties === false) {
      for (const key of Object.keys(args)) {
        if (!(key in props)) return { valid: false, reason: `unknown field: ${key}` };
      }
    }

    for (const [key, value] of Object.entries(args)) {
      const propSchema = props[key];
      if (!propSchema || typeof propSchema !== 'object') continue;
      const t = propSchema.type;
      if (!t || typeof t !== 'string') continue;
      if (t === 'string' && typeof value !== 'string') return { valid: false, reason: `${key} must be string` };
      if (t === 'number' && typeof value !== 'number') return { valid: false, reason: `${key} must be number` };
      if (t === 'integer' && (!Number.isInteger(value) || typeof value !== 'number')) return { valid: false, reason: `${key} must be integer` };
      if (t === 'boolean' && typeof value !== 'boolean') return { valid: false, reason: `${key} must be boolean` };
      if (t === 'array' && !Array.isArray(value)) return { valid: false, reason: `${key} must be array` };
      if (t === 'object' && (typeof value !== 'object' || value === null || Array.isArray(value))) {
        return { valid: false, reason: `${key} must be object` };
      }
    }

    return { valid: true };
  }

  private parseColon(uri: string): [string | null, string | null] {
    const idx = uri.indexOf(':');
    if (idx <= 0) return [null, null];
    return [uri.slice(0, idx), uri.slice(idx + 1)];
  }

  private success(id: string | number | null, result: unknown): JsonRpcResponse {
    return { jsonrpc: '2.0', id, result };
  }

  private error(id: string | number | null, code: number, message: string): JsonRpcResponse {
    return { jsonrpc: '2.0', id, error: { code, message } };
  }
}
