export interface JsonRpcRequest<T = unknown> {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: T;
}

export interface JsonRpcSuccess<T = unknown> {
  jsonrpc: '2.0';
  id: string | number | null;
  result: T;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcErrorResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  error: JsonRpcError;
}

export type JsonRpcResponse<T = unknown> = JsonRpcSuccess<T> | JsonRpcErrorResponse;

export interface ToolDefinition {
  name: string;
  title?: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  isReadOnly?: boolean;
}

export interface ToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: unknown;
  isError?: boolean;
}
