// MCP error codes (matching JSON-RPC 2.0 and MCP spec)
export enum ErrorCode {
  // Standard JSON-RPC errors
  ParseError = -32700,
  InvalidRequest = -32600,
  MethodNotFound = -32601,
  InvalidParams = -32602,
  InternalError = -32603,

  // MCP-specific errors
  Unauthorized = -32010,
  CapabilityMismatch = -32011,
  Timeout = -32012,
  Unavailable = -32013,
  AuthRequired = -32014,
}

export interface MappedMcpError {
  code: number;
  message: string;
  data?: {
    authRequired?: boolean;
    connectorId?: string;
    resourceMetadataUrl?: string;
    scope?: string;
  };
}

/**
 * Custom MCP Error class with structured data
 */
export class McpError extends Error {
  readonly code: ErrorCode;
  readonly data?: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = 'McpError';
    this.code = code;
    this.data = data;
  }

  toMappedError(): MappedMcpError {
    return {
      code: this.code,
      message: this.message,
      data: this.data as MappedMcpError['data']
    };
  }
}

export function mapDownstreamError(error: unknown): MappedMcpError {
  // Handle McpError instances directly
  if (error instanceof McpError) {
    return error.toMappedError();
  }

  const message = error instanceof Error ? error.message : String(error);
  const lower = message.toLowerCase();

  // Check for auth_required flag in error data
  if (error instanceof Error && 'data' in error) {
    const data = (error as Error & { data?: Record<string, unknown> }).data;
    if (data?.authRequired) {
      return {
        code: ErrorCode.AuthRequired,
        message: 'UPSTREAM_AUTH_REQUIRED',
        data: {
          authRequired: true,
          connectorId: data.connectorId as string | undefined,
          resourceMetadataUrl: data.resourceMetadataUrl as string | undefined,
          scope: data.scope as string | undefined
        }
      };
    }
  }

  if (lower.includes('401') || lower.includes('403') || lower.includes('unauthorized')) {
    return { code: ErrorCode.Unauthorized, message: 'UPSTREAM_UNAUTHORIZED' };
  }
  if (lower.includes('404') || lower.includes('method not found')) {
    return { code: ErrorCode.CapabilityMismatch, message: 'UPSTREAM_CAPABILITY_MISMATCH' };
  }
  if (lower.includes('timed out') || lower.includes('abort')) {
    return { code: ErrorCode.Timeout, message: 'UPSTREAM_TIMEOUT' };
  }
  if (lower.includes('500') || lower.includes('502') || lower.includes('503') || lower.includes('504') || lower.includes('downstream http')) {
    return { code: ErrorCode.Unavailable, message: 'UPSTREAM_UNAVAILABLE' };
  }

  return { code: ErrorCode.InternalError, message: 'UPSTREAM_ERROR' };
}
