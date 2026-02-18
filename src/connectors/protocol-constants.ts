// Protocol version constants matching the official MCP TypeScript SDK
// Reference: typescript-sdk/packages/core/src/types.ts:3-5

export const LATEST_PROTOCOL_VERSION = '2025-11-25';

export const SUPPORTED_PROTOCOL_VERSIONS = [
  '2025-11-25',
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
  '2024-10-07'
] as const;
