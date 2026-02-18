export interface MappedMcpError {
  code: number;
  message: string;
}

export function mapDownstreamError(error: unknown): MappedMcpError {
  const message = error instanceof Error ? error.message : String(error);
  const lower = message.toLowerCase();

  if (lower.includes('401') || lower.includes('403') || lower.includes('unauthorized')) {
    return { code: -32010, message: 'UPSTREAM_UNAUTHORIZED' };
  }
  if (lower.includes('404') || lower.includes('method not found')) {
    return { code: -32011, message: 'UPSTREAM_CAPABILITY_MISMATCH' };
  }
  if (lower.includes('timed out') || lower.includes('abort')) {
    return { code: -32012, message: 'UPSTREAM_TIMEOUT' };
  }
  if (lower.includes('500') || lower.includes('502') || lower.includes('503') || lower.includes('504') || lower.includes('downstream http')) {
    return { code: -32013, message: 'UPSTREAM_UNAVAILABLE' };
  }

  return { code: -32000, message: 'UPSTREAM_ERROR' };
}
