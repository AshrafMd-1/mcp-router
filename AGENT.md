# MCP Gateway Agent Guide

This document captures the current implementation exactly as it exists in this repo, including architecture, file ownership, runtime flow, UI behavior, persistence model, and known edge-cases.

## 1. Product Scope (Current)

Two personas only:

- Admin (web UI): configures connectors and clients from `/admin/`
- MCP client (Claude/Cursor/etc.): calls `/mcp` using a client token

No public admin API auth tokens are used in normal flow anymore. Admin access is session-cookie based from UI login.

## 2. High-Level Architecture

- Process entry: `src/main.ts`
- HTTP server: Fastify in `src/server/fastify.ts`
- Admin UI static app: `src/admin/ui/index.html` + `src/admin/ui/app.js`
- Admin routes: `src/server/routes/admin.ts`
- MCP routes: `src/server/routes/mcp.ts`
- Runtime connector engine: `src/connectors/*`
- MCP request router/policy gate: `src/mcp/router.ts`
- PostgreSQL persistence repositories: `src/db/repositories/*`
- Secret encryption for connector credentials: `src/security/crypto.ts`

## 3. Request Flows

### 3.1 Admin UI Flow

1. Open `/admin/`
2. Login with password only (password == `ADMIN_TOKEN`)
3. Server creates session in `admin_sessions`, sets `mgw_admin_session` cookie
4. UI manages:
- Connectors
- Clients
- Client policy (allowed tools)
- Client tokens

### 3.2 MCP Client Flow

1. MCP client sends `Authorization: Bearer mgw_live_...` to `/mcp`
2. `auth` middleware validates token hash against `client_tokens`
3. `MGatewayRouter` checks client policy from `client_policies`
4. Gateway exposes only allowed connectors/tools
5. Tool calls are forwarded to connector adapters (`http`/`stdio`)
6. Errors are normalized into MCP JSON-RPC error payloads

## 4. Auth Model

### 4.1 Admin auth

- Middleware: `src/server/middleware/auth.ts`
- Cookie name: `mgw_admin_session`
- Session storage: table `admin_sessions`
- Admin username is fixed as `admin` (UI shows password-only login)

### 4.2 MCP auth

- Bearer token only
- Token format issued by gateway: `mgw_live_<hex>`
- Stored hashed (`sha256`) in `client_tokens.token_hash`
- Plain token is shown once at creation

## 5. Connector Model

Stored connector shape (`connectors`):

- `mode`: `oauth_url` or `json_config`
- `transport`: `http` or `stdio`
- `config_json`: connector config

Runtime connector shape (in `ConnectorManager`):

- HTTP: URL + optional auth token/scheme
- STDIO: command + args + cwd + env

### 5.1 HTTP connector behavior

- Adapter file: `src/connectors/http-adapter.ts`
- Uses MCP JSON-RPC over HTTP POST
- Supports response as JSON and SSE-like payload parsing
- Health check tries `ping` via optional request
- Optional methods (`resources/list`, `prompts/list`, `ping`) gracefully fallback when upstream says unsupported

### 5.2 OAuth URL mode

- Admin route: `POST /admin/connectors/:id/oauth/start`
- URL-only setup discovers metadata from target `.well-known/*`
- Supports dynamic client registration if provider exposes it
- Uses PKCE + state
- Callback: `GET /admin/oauth/callback`
- Access token stored in `connector_credentials` under `oauth_tokens`
- Connector is reinitialized after callback; tool cache and health updated

Important: if provider token has wrong audience/resource, callback can save token but connector validation can fail with downstream 401.

### 5.3 API token mode

- UI sends HTTP `json_config` with `configJson.Authorization = "Bearer ..."`
- On save, connector can be discovered immediately (`/discover`)
- API header token is stored in `connector_credentials` as `api_header`

## 6. Policy Model

Current policy semantics (allowlist-first):

- `connector_ids`: which connectors client can access
- `allowed_tools`: exact tool names allowed (`connector.tool` internal form)
- `denied_tools`: currently persisted but forced empty from admin route

Runtime decision path:

- `src/mcp/policy-evaluator.ts`
- `src/mcp/router.ts`

## 7. MCP Contract Hardening (Implemented)

- `/mcp` POST always returns JSON-RPC payload (result/error)
- Unauthorized POST response is JSON-RPC error (`-32001`)
- Invalid JSON-RPC request returns `-32600`
- Tool call arguments are validated against tool `inputSchema` before forwarding
- Tool names exposed to clients are sanitized to MCP-safe pattern:
  - external: `connector__tool`
  - internal mapping back to `connector.tool`

## 8. Persistence and Encryption

### 8.1 DB

Migration file: `src/db/migrations/001_initial.sql`

Core tables:

- `connectors`
- `connector_credentials`
- `connector_tool_cache`
- `clients`
- `client_policies`
- `client_tokens`
- `admin_sessions`
- `schema_migrations`

### 8.2 Secret encryption

- File: `src/security/crypto.ts`
- Algorithm: AES-256-GCM
- Envelope format includes `v`, `alg`, `iv`, `tag`, `ct`
- `ENCRYPTION_KEY` required (32-byte base64 or 64-char hex)
- `ConnectorCredentialsRepository` encrypts on write / decrypts on read

## 9. UI Structure (Current)

### 9.1 App shell

- Sidebar nav: Clients / Connectors
- Main cards list
- Modal-driven CRUD flows

### 9.2 Client modal

- Same modal for create + edit
- Tabs:
  - Details
  - Access
  - Tokens
- Access tab:
  - connector chips
  - tool chips (selected = allowed)
  - selected tools grouped by connector
  - live policy JSON preview
- Tokens tab:
  - issue token
  - list/revoke tokens
  - after issuing token, shows ready-to-copy MCP `mcpServers` snippet
- Save closes modal and persists details + policy

### 9.3 Connector modal

- Fields:
  - name
  - transport (`http`/`stdio`)
  - auth mode (`oauth`/`api_token`) for HTTP
- Config JSON preview panel
- Buttons:
  - Save
  - Authorize & Save (OAuth)
- OAuth completion popup posts `oauth-complete` message back to opener and closes

## 10. Env and Runtime Requirements

Defined in `src/config/schema.ts`:

- `ADMIN_TOKEN` (required, min 12)
- `DATABASE_URL` (required)
- `ENCRYPTION_KEY` (required, min 32 chars; validated in crypto parser)
- Optional defaults:
  - `NODE_ENV` default `development`
  - `HOST` default `0.0.0.0`
  - `PORT` default `3000`
  - `ADMIN_SESSION_HOURS` default `24`
  - `AUTO_MIGRATE` default `true`

Config load: `src/config/index.ts` via dotenv (quiet mode).

## 11. Startup/Shutdown Sequence

In `src/main.ts`:

1. Load env
2. Build encryption context
3. Create DB client
4. Wait for DB readiness (retry up to 30 times)
5. Run migration when `AUTO_MIGRATE=true`
6. Build repositories/services
7. Rehydrate persisted connectors from DB + saved credentials
8. Register runtime connectors and cache discovered tools
9. Start Fastify
10. On SIGINT/SIGTERM: close server, shutdown adapters, close DB

## 12. File-by-File Ownership Map

### Core app and config

- `src/main.ts`: bootstrap, DB readiness, migration, persisted connector rehydrate, process lifecycle
- `src/app-context.ts`: dependency container typing
- `src/config/schema.ts`: strict env schema
- `src/config/index.ts`: dotenv + schema parse

### Server and middleware

- `src/server/fastify.ts`: app creation, static admin serving, route registration
- `src/server/middleware/auth.ts`: admin session auth + MCP token auth
- `src/server/routes/admin.ts`: all admin web APIs and OAuth flows
- `src/server/routes/mcp.ts`: MCP HTTP/SSE endpoints, JSON-RPC guardrails

### MCP layer

- `src/mcp/router.ts`: JSON-RPC method dispatch, policy checks, tool name mapping, argument validation
- `src/mcp/policy-evaluator.ts`: allow/deny logic
- `src/mcp/error-mapper.ts`: downstream-to-MCP error normalization
- `src/mcp/protocol.ts`: request/response/tool types
- `src/mcp/session.ts`: in-memory MCP session tracking

### Connector runtime

- `src/connectors/manager.ts`: register/remove/refresh connectors, startup behavior
- `src/connectors/adapter.ts`: adapter interface
- `src/connectors/http-adapter.ts`: HTTP transport implementation
- `src/connectors/stdio-adapter.ts`: stdio transport implementation

### DB and repositories

- `src/db/client.ts`: PG pool and migration runner
- `src/db/migrations/001_initial.sql`: schema reset + create
- `src/db/repositories/connectors.ts`: connector CRUD + health status
- `src/db/repositories/connector-credentials.ts`: encrypted auth credential storage
- `src/db/repositories/tool-cache.ts`: connector tool cache
- `src/db/repositories/clients.ts`: client CRUD
- `src/db/repositories/client-policies.ts`: policy CRUD and connector usage checks
- `src/db/repositories/admin-sessions.ts`: admin session lifecycle
- `src/auth/tokens.ts`: issue/validate/revoke/list client tokens

### Admin frontend

- `src/admin/ui/index.html`: layout + styles + shell
- `src/admin/ui/app.js`: full client-side state machine and API integration

### Tests

- `tests/error-mapper.test.ts`: downstream error mapping tests
- `tests/policy-evaluator.test.ts`: policy behavior tests

### Build/runtime infra

- `Dockerfile`: gateway container build
- `docker-compose.yml`: postgres + gateway stack, env-driven secrets
- `.env.example`: required env template
- `package.json`: scripts and dependencies

## 13. Known Failure Modes and What They Mean

### 13.1 `Connector runtime not initialized`

Usually means connector was stored but runtime manager does not currently hold a live adapter. Current code attempts lazy register in discover/health routes, but init can still fail when auth/config is invalid.

### 13.2 `Downstream HTTP 401` after OAuth callback

Token got saved but upstream rejects it. Common causes:

- wrong audience/resource for provider
- token issued for different resource server
- provider requires scopes not requested

Observed variant:

- `invalid_token`
- `Token audience does not match resource server`

### 13.3 Tool list empty after successful `/mcp` initialize

Means client token/policy is valid but no allowed tools are currently discoverable for policy-selected connectors.

### 13.4 `FST_ERR_CTP_EMPTY_JSON_BODY`

Route expected JSON body because `Content-Type: application/json` was set but body was empty. Use `{}` for empty JSON in POST calls.

## 14. Operational Notes

- Keep `ADMIN_TOKEN`, `DATABASE_URL`, and `ENCRYPTION_KEY` in env only.
- Do not log sensitive token payloads.
- Connector config shown in API/UI is sanitized (token/secret/password keys redacted).
- Connector credentials are encrypted in DB; only decrypted in process.

## 15. What Was Explicitly Cleaned

- Removed old policy-engine/preset/rate-limiter modules not used in current MVP path.
- Removed audit/logging repository modules not used by current flow.
- Disabled verbose Fastify logger (`logger: false`), replaced with minimal startup/error logs.
- Moved docker-compose secrets to env references.

## 16. Current MVP Reality

The gateway is now centered on:

1. Admin website management
2. MCP gateway for clients
3. Postgres persistence across restarts

Everything else is intentionally trimmed for this phase.
