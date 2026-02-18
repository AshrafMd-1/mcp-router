// RFC 9728 OAuth discovery functions
// Reference: typescript-sdk/packages/client/src/auth.ts:741-761, 972-1020

import { LATEST_PROTOCOL_VERSION } from './protocol-constants.js';

const DISCOVERY_TIMEOUT = 10000; // 10 seconds

export interface OAuthProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  scopes_supported?: string[];
}

export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported: string[];
  code_challenge_methods_supported?: string[];
}

export interface OAuthServerInfo {
  authorizationServerUrl: string;
  authorizationServerMetadata?: AuthorizationServerMetadata;
  resourceMetadata?: OAuthProtectedResourceMetadata;
}

/**
 * Fetch with timeout helper
 */
async function fetchWithTimeout(
  url: URL | string,
  options: RequestInit,
  timeout: number
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Discover OAuth Protected Resource Metadata (RFC 9728)
 *
 * Tries path-aware discovery first, then falls back to root path.
 * https://datatracker.ietf.org/doc/html/rfc9728
 */
export async function discoverOAuthProtectedResourceMetadata(
  serverUrl: string | URL,
  options?: { resourceMetadataUrl?: string | URL }
): Promise<OAuthProtectedResourceMetadata> {
  const url = new URL(serverUrl);

  // If explicit resource_metadata URL provided (from WWW-Authenticate), use it
  const metadataUrl = options?.resourceMetadataUrl
    ? new URL(options.resourceMetadataUrl)
    : new URL(`/.well-known/oauth-protected-resource${url.pathname}`, url.origin);

  const response = await fetchWithTimeout(
    metadataUrl,
    {
      headers: { 'MCP-Protocol-Version': LATEST_PROTOCOL_VERSION }
    },
    DISCOVERY_TIMEOUT
  );

  if (response.ok) {
    return await response.json() as OAuthProtectedResourceMetadata;
  }

  // If path-aware discovery failed, try fallback to root
  if (!options?.resourceMetadataUrl) {
    const fallbackUrl = new URL('/.well-known/oauth-protected-resource', url.origin);
    const fallbackRes = await fetchWithTimeout(
      fallbackUrl,
      {
        headers: { 'MCP-Protocol-Version': LATEST_PROTOCOL_VERSION }
      },
      DISCOVERY_TIMEOUT
    );

    if (fallbackRes.ok) {
      return await fallbackRes.json() as OAuthProtectedResourceMetadata;
    }
  }

  throw new Error('Resource server does not implement OAuth 2.0 Protected Resource Metadata (RFC 9728)');
}

/**
 * Discover Authorization Server Metadata
 *
 * Tries OAuth metadata endpoint first (RFC 8414), then falls back to OIDC.
 */
export async function discoverAuthorizationServerMetadata(
  authorizationServerUrl: string | URL
): Promise<AuthorizationServerMetadata | undefined> {
  const url = new URL(authorizationServerUrl);

  // Try OAuth metadata first (RFC 8414), then OIDC
  const urlsToTry = [
    new URL('/.well-known/oauth-authorization-server', url.origin),
    new URL('/.well-known/openid-configuration', url.origin),
  ];

  for (const metadataUrl of urlsToTry) {
    try {
      const response = await fetchWithTimeout(
        metadataUrl,
        {
          headers: { 'MCP-Protocol-Version': LATEST_PROTOCOL_VERSION }
        },
        DISCOVERY_TIMEOUT
      );

      if (response.ok) {
        return await response.json() as AuthorizationServerMetadata;
      }
    } catch {
      // Continue to next URL
      continue;
    }
  }

  return undefined;
}

/**
 * Complete OAuth server discovery flow
 *
 * 1. Discover protected resource metadata to find authorization server(s)
 * 2. Discover authorization server metadata for endpoints
 */
export async function discoverOAuthServerInfo(
  serverUrl: string | URL,
  options?: { resourceMetadataUrl?: URL }
): Promise<OAuthServerInfo> {
  let resourceMetadata: OAuthProtectedResourceMetadata | undefined;
  let authorizationServerUrl: string | undefined;

  // Step 1: Try to discover protected resource metadata
  try {
    resourceMetadata = await discoverOAuthProtectedResourceMetadata(
      serverUrl,
      { resourceMetadataUrl: options?.resourceMetadataUrl }
    );

    // Use first authorization server from metadata
    if (resourceMetadata.authorization_servers?.length) {
      authorizationServerUrl = resourceMetadata.authorization_servers[0];
    }
  } catch {
    // RFC 9728 not supported by this server
  }

  // Fallback: use server URL origin as authorization server
  if (!authorizationServerUrl) {
    authorizationServerUrl = new URL('/', serverUrl).toString();
  }

  // Step 2: Discover authorization server metadata
  const authorizationServerMetadata = await discoverAuthorizationServerMetadata(
    authorizationServerUrl
  );

  return {
    authorizationServerUrl,
    authorizationServerMetadata,
    resourceMetadata,
  };
}

/**
 * Attempt OAuth discovery for a server URL, returning null if not supported
 */
export async function tryDiscoverOAuth(
  serverUrl: string | URL
): Promise<OAuthServerInfo | null> {
  try {
    return await discoverOAuthServerInfo(serverUrl);
  } catch {
    return null;
  }
}
