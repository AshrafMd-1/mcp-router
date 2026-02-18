// OAuth type definitions for MCP authentication
// Reference: typescript-sdk/packages/client/src/auth.ts

export interface OAuthTokens {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}
