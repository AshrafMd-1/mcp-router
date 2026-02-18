// WWW-Authenticate header parsing and connector auth state management
// Reference: typescript-sdk/packages/client/src/auth.ts:647-677

import type { OAuthTokens } from './oauth-types.js';

export interface ConnectorAuthState {
  status: 'none' | 'pending' | 'authorized' | 'failed';
  authorizationUrl?: string;
  resourceMetadataUrl?: string;
  scope?: string;
  tokens?: OAuthTokens;
  error?: string;
}

/**
 * Extract OAuth parameters from WWW-Authenticate header (RFC 6750)
 *
 * Example header:
 * Bearer realm="example", resource_metadata="https://example.com/.well-known/oauth-protected-resource", scope="read write"
 */
export function extractWWWAuthenticateParams(response: Response): {
  resourceMetadataUrl?: URL;
  scope?: string;
  error?: string;
} {
  const header = response.headers.get('www-authenticate');
  if (!header) return {};

  // Check if it's a Bearer challenge
  const parts = header.split(' ');
  const type = parts[0];
  if (type?.toLowerCase() !== 'bearer') return {};

  const extractField = (fieldName: string): string | undefined => {
    // Match both quoted and unquoted values
    const pattern = new RegExp(`${fieldName}=(?:"([^"]+)"|([^\\s,]+))`);
    const match = header.match(pattern);
    return match?.[1] || match?.[2];
  };

  const resourceMetadataStr = extractField('resource_metadata');
  let resourceMetadataUrl: URL | undefined;
  if (resourceMetadataStr) {
    try {
      resourceMetadataUrl = new URL(resourceMetadataStr);
    } catch {
      // Ignore invalid URL
    }
  }

  return {
    resourceMetadataUrl,
    scope: extractField('scope'),
    error: extractField('error'),
  };
}
