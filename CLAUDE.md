# MCP Router — Project Context

## What This Is

A self-hosted gateway for Model Context Protocol (MCP) servers. AI agents connect with a single client token, the gateway enforces tool-level access policies, and it handles upstream OAuth 2.0 token exchange and refresh so clients never manage credentials directly. Ships with an admin UI and supports both remote (HTTP) and local (STDIO) MCP servers.

## Tech Stack

- **Runtime**: Node.js 22+, TypeScript 5.7, ESM modules
- **Server**: Fastify 5.x
- **Database**: PostgreSQL (via `pg` driver, no ORM)
- **Validation**: Zod
- **Testing**: Vitest
- **Build**: `tsc` → `dist/`
- **Dev**: `tsx watch` for hot reload
- **Containerization**: Docker Compose (postgres + gateway)

## Commands

```bash
npm run dev          # Development with hot reload
npm run build        # TypeScript compilation
npm start            # Run production build (dist/main.js)
npm test             # Vitest run
npm run test:watch   # Vitest watch mode
docker compose up --build  # Full stack with Postgres
```

## Environment Variables

Required in `.env` (see `.env.example`):
- `DATABASE_URL` — Postgres connection string
- `ADMIN_TOKEN` — Admin UI login password (min 12 chars)
- `ENCRYPTION_KEY` — 32-byte key (64-char hex) for AES-256-GCM credential encryption
- `PORT` (default 3000), `HOST` (default 0.0.0.0)
- `AUTO_MIGRATE` (default true), `ADMIN_SESSION_HOURS` (default 24)

## Architecture Overview

```
AI Agent → POST /mcp (Bearer token) → Gateway → Upstream MCP Server
                                         │
                           ┌─────────────┼─────────────┐
                           │             │             │
                      Auth Layer    Policy Engine   Connector Manager
                    (tokens.ts)   (policy-evaluator)  (manager.ts)
                           │             │             │
                      SHA256 hash    Glob matching   OAuth refresh
                      timing-safe    allow/deny      AES-256-GCM
                      comparison     filtering       token storage
```

The gateway is both an MCP server (frontend to agents) and an MCP client (backend to upstream servers).

## Request Lifecycle

1. Request hits `POST /mcp` (`src/server/routes/mcp.ts`)
2. Auth middleware (`src/server/middleware/auth.ts`) validates Bearer token via `TokenService.validate()` — SHA256 hash + timing-safe comparison
3. MCP Router (`src/mcp/router.ts`) dispatches by JSON-RPC method:
   - `tools/list` → fan out to all allowed connectors, filter by policy, return merged list
   - `tools/call` → policy check, then proxy to correct connector
4. ConnectorManager (`src/connectors/manager.ts`) routes to adapter:
   - HTTP: `HttpConnectorAdapter` sends request with OAuth token attached
   - STDIO: `StdioConnectorAdapter` writes to spawned process stdin
5. On 401 from upstream: transparent token refresh via `_doTokenRefresh()` with concurrency lock (one refresh, all waiters share result), then retry once
6. Response flows back through the chain to agent

## Database Schema (7 tables)

- **`connectors`** — upstream MCP server registry (name, transport, config_json, health)
- **`connector_credentials`** — encrypted OAuth tokens per connector (AES-256-GCM, unique IV per row)
- **`connector_tool_cache`** — cached tool metadata for admin UI policy editor
- **`clients`** — registered AI agents
- **`client_tokens`** — SHA256 hashed bearer tokens (plaintext never stored)
- **`client_policies`** — per-client access rules (connector_ids, allowed_tools globs, denied_tools)
- **`admin_sessions`** — admin UI session tracking

## Key Source Files

| File | Purpose |
|------|---------|
| `src/main.ts` | Entry point, startup, connector loading |
| `src/auth/tokens.ts` | Token issue/validate/revoke with SHA256 + timingSafeEqual |
| `src/security/crypto.ts` | AES-256-GCM encrypt/decrypt for stored credentials |
| `src/connectors/manager.ts` | Connector registry, adapter creation, token refresh wiring |
| `src/connectors/http-adapter.ts` | HTTP transport with 401 retry, refresh lock, SSE support |
| `src/connectors/stdio-adapter.ts` | STDIO transport (spawn process, JSON-RPC over stdin/stdout) |
| `src/connectors/oauth-discovery.ts` | RFC 9728 .well-known discovery (resource + auth server metadata) |
| `src/mcp/router.ts` | JSON-RPC dispatch, policy enforcement on every request |
| `src/mcp/policy-evaluator.ts` | `isToolAllowed()` — glob matching against allow/deny lists |
| `src/server/routes/admin.ts` | Admin API: CRUD for connectors/clients, OAuth flow, dynamic client registration |
| `src/server/routes/mcp.ts` | MCP endpoint: JSON-RPC + SSE |
| `src/admin/ui/app.js` | Admin dashboard (vanilla JS, ~900 lines) |
| `src/db/migrations/001_initial.sql` | Full database schema |

## Security Design

- **Client tokens**: `mgw_live_` + 24 random bytes. Plaintext shown once, only SHA256 hash stored. Validated with `crypto.timingSafeEqual()` to prevent timing attacks.
- **Upstream credentials**: Encrypted at rest with AES-256-GCM (unique 12-byte IV per row, auth tag for tamper detection). Key from `ENCRYPTION_KEY` env var.
- **Agent isolation**: Agents never see upstream OAuth tokens. Compromised agent = revoke one gateway token, upstream unaffected.
- **Policy enforcement**: Tool filtering on both `tools/list` (hide tools) and `tools/call` (reject unauthorized calls).
- **Admin auth**: Password-based (`ADMIN_TOKEN`) with HttpOnly session cookies.

## OAuth Flow

1. **Discovery**: Gateway hits `.well-known/oauth-protected-resource` on MCP server URL → finds auth server → hits `.well-known/oauth-authorization-server` → gets all OAuth endpoints
2. **Dynamic client registration**: POSTs to `registration_endpoint` as public client (`token_endpoint_auth_method: 'none'`). Works with open providers (Linear), fails with restrictive ones (Figma — requires pre-registered credentials)
3. **Authorization**: PKCE flow via admin UI popup → user approves → gateway exchanges code for access + refresh tokens → encrypts and stores
4. **Automatic refresh**: On 401, `_makeTokenRefresher()` uses stored refresh token to get new access token. Concurrency lock ensures only one refresh fires even with multiple simultaneous 401s.

## Connector Auth Modes

- **`oauth_url`**: Full OAuth with discovery + dynamic registration + PKCE + auto-refresh
- **`json_config` with API key**: Static token in Authorization header or custom headers
- **`json_config` with none**: No auth (open MCP servers)

## Admin UI

Vanilla JS served from `src/admin/ui/` at `/admin/`. Features:
- Connector CRUD with OAuth popup flow
- Client management with token issue/revoke/rotate
- Policy editor: select connectors, click tools to allow/deny (glob patterns)
- Tool discovery: fetches `tools/list` from upstream and caches results
- Health monitoring per connector

## Known Design Decisions

- Opaque hashed tokens instead of JWTs for client auth — gateway is both issuer and validator, so JWT self-containment adds no value. Opaque tokens are simpler and instantly revocable.
- PostgreSQL only, no Redis — access patterns (occasional policy reads, occasional token validation) don't justify a second infrastructure dependency. Redis makes sense at scale for rate limiting and shared caching.
- Tool names are namespaced as `{connectorName}.{toolName}` to avoid collisions across upstream servers.
- `deniedTools` is stored in DB but not yet enforced in `policy-evaluator.ts` (noted in AGENTS.md).

## Coding Conventions

- ESM imports with `.js` extensions (TypeScript compiled to ESM)
- Repository pattern for all database access (`src/db/repositories/`)
- No ORM — raw SQL with parameterized queries via `pg`
- Zod for all input validation (config, API request bodies)
- Fastify plugins for middleware (auth)
- Error handling via custom `McpError` class with typed error codes
