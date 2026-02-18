import { describe, expect, it } from 'vitest';
import { mapDownstreamError } from '../src/mcp/error-mapper.js';

describe('mapDownstreamError', () => {
  it('maps unauthorized', () => {
    expect(mapDownstreamError(new Error('Downstream HTTP 401')).code).toBe(-32010);
  });

  it('maps method mismatch', () => {
    expect(mapDownstreamError(new Error('Method not found')).code).toBe(-32011);
  });

  it('maps timeout', () => {
    expect(mapDownstreamError(new Error('Request timed out')).code).toBe(-32012);
  });

  it('maps unavailable', () => {
    expect(mapDownstreamError(new Error('Downstream HTTP 503')).code).toBe(-32013);
  });
});
