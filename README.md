# MCP Gateway [alpha]

A self-hosted gateway that multiplexes multiple upstream MCP servers into a single endpoint. AI clients (Claude, Cursor, etc.) connect once and get access to whichever tools the admin has granted them.

```
AI Client (Claude/Cursor)
        │  Bearer token
        ▼
  ┌─────────────┐       allowlist policy
  │ MCP Gateway │──────────────────────────────┐
  └─────────────┘                              │
     │         │          │                    │
     ▼         ▼          ▼                    ▼
   Linear   Granola    local CLI          tool catalog
   (OAuth)  (OAuth)    (STDIO)            (per client)
```

## Features

### Connector types
| Type | Auth | Example |
|------|------|---------|
| HTTP - OAuth URL | OAuth 2.0 + PKCE, auto-discovery (RFC 9728), dynamic client registration | Figma, GitHub, Atlan |
| HTTP - JSON config | API key / custom headers | Any HTTP MCP server |
| STDIO | env vars / none | Local CLI tools, `npx` servers |

### Per-client access control
- Create named clients, assign a subset of connectors, then allowlist specific tools (glob patterns supported: `github.*`, `figma.get_*`)
- Issue multiple bearer tokens per client; revoke or rotate individually
- Tool names are exposed as `connector__tool` so there are no collisions across connectors

### OAuth support
- Auto-discovers authorization server via `/.well-known/oauth-protected-resource` → `/.well-known/oauth-authorization-server` chain (RFC 9728)
- Dynamic client registration when the provider supports it; falls back to manually configured `clientId`/`clientSecret`
- PKCE (`S256`) on every authorization request
- Transparent token refresh on `401` - single concurrent refresh per connector (lock prevents duplicate grant requests)
- `auth_failed` guard: once a refresh token is known expired, all further calls are rejected immediately with a structured error pointing to `/admin/connectors/:id/oauth/start`

### Storage & security
- PostgreSQL with auto-migration on startup (`AUTO_MIGRATE=true`)
- Connector credentials (OAuth tokens, API keys) encrypted at rest with AES-GCM (`ENCRYPTION_KEY`)
- Admin sessions stored server-side; short-lived by default (`ADMIN_SESSION_HOURS`)
- `sanitizeConfig` strips `token`, `secret`, and `password` fields before returning connector config to the browser

### Admin UI
- Vanilla JS single-page app at `/admin/`
- Connectors view: create / edit / delete, OAuth flow, health check, tool discovery
- Clients view: create / edit / delete, access policy (connector selection + tool allowlist), token management (issue / revoke / rotate)

### MCP protocol
- Protocol version `2025-06-18`
- Proxies `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`
- All downstream errors normalized to typed MCP error codes (`UPSTREAM_UNAUTHORIZED`, `UPSTREAM_TIMEOUT`, `UPSTREAM_UNAVAILABLE`, etc.)
- SSE and plain JSON response bodies both handled

## Tech stack

- Node.js 22 + TypeScript (ESM)
- Fastify 5
- PostgreSQL 16
- Vitest

## Environment

Copy `.env.example` to `.env` and fill in:

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `ADMIN_TOKEN` | yes | - | Password for the admin UI |
| `DATABASE_URL` | yes | - | `postgres://user:pass@host:5432/db` |
| `ENCRYPTION_KEY` | yes | - | 64-char hex or 32-byte base64 (AES-GCM key) |
| `HOST` | no | `0.0.0.0` | Bind address |
| `PORT` | no | `3000` | Listen port |
| `AUTO_MIGRATE` | no | `true` | Run DB migrations on startup |
| `ADMIN_SESSION_HOURS` | no | `24` | Admin session lifetime |

Generate a key:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Quick start with Docker

```bash
cp .env.example .env
# Edit .env - set ADMIN_TOKEN and ENCRYPTION_KEY at minimum
docker compose up --build
```

Endpoints:

| Path | Purpose |
|------|---------|
| `http://localhost:3000/admin/` | Admin UI |
| `http://localhost:3000/mcp` | MCP endpoint (for clients) |
| `http://localhost:3000/health` | Health check |

## Run locally

```bash
npm install
npm run dev        # tsx watch - auto-restarts on change
```

Build and start:
```bash
npm run build
npm start
```

## MCP client setup

After issuing a token in the admin UI, add this to your client config:

```json
{
  "mcpServers": {
    "gateway": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://127.0.0.1:3000/mcp",
        "--header",
        "Authorization: Bearer <CLIENT_TOKEN>"
      ]
    }
  }
}
```

## Admin walkthrough

1. Open `/admin/` and log in with `ADMIN_TOKEN`
2. **Connectors** → Create connector
   - *OAuth URL*: paste the MCP server URL; click "Connect OAuth" to go through browser OAuth
   - *JSON config (HTTP)*: paste URL + API key or headers
   - *JSON config (STDIO)*: paste `{"command": "npx", "args": ["-y", "some-mcp-server"]}`
3. Click **Discover Tools** to populate the tool catalog
4. **Clients** → Create client
5. Open the client → **Access** tab → select connectors and check the tools to allow
6. **Tokens** tab → Issue token (shown once - copy it)
7. Paste the token into your AI client config

## API reference

### Admin endpoints (session cookie required)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/admin/login` | Login, sets `mgw_admin_session` cookie |
| `POST` | `/admin/logout` | Invalidate session |
| `GET` | `/admin/connectors` | List connectors |
| `POST` | `/admin/connectors` | Create connector |
| `PUT` | `/admin/connectors/:id` | Update connector |
| `DELETE` | `/admin/connectors/:id` | Delete connector (blocked if in use) |
| `POST` | `/admin/connectors/:id/discover` | Refresh tool catalog |
| `GET` | `/admin/connectors/:id/health` | Live health check |
| `POST` | `/admin/connectors/:id/oauth/start` | Begin OAuth flow |
| `GET` | `/admin/oauth/callback` | OAuth redirect callback |
| `GET` | `/admin/tool-catalog?connectorId=` | List tools for connector |
| `GET` | `/admin/clients` | List clients |
| `POST` | `/admin/clients` | Create client |
| `PUT` | `/admin/clients/:id` | Update client |
| `DELETE` | `/admin/clients/:id` | Delete client |
| `GET` | `/admin/clients/:id/policy` | Get access policy |
| `PUT` | `/admin/clients/:id/policy` | Update access policy |
| `GET` | `/admin/clients/:id/tokens` | List tokens |
| `POST` | `/admin/clients/:id/tokens` | Issue new token |
| `DELETE` | `/admin/clients/:id/tokens/:tokenId` | Revoke token |
| `POST` | `/admin/tokens/:id/rotate` | Rotate token |

### MCP endpoint

`POST /mcp` - Bearer token auth. Accepts JSON-RPC 2.0.

Supported methods: `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`

## Testing

```bash
npm test
```

Unit tests cover policy evaluation and error mapping.

## Known issues & planned work

### Critical

- **OAuth stability (Figma, GitHub, Atlan)** - Authentication failures still observed for these providers. Investigation ongoing; likely scope or audience parameter mismatches.
- **Issue Token before initial save** - Issuing a token immediately after creating a client (before the first save completes) can fail. Needs a guard in the UI to wait for the client record to be confirmed.

### High

- **Unified tool filtering** - The DB schema stores both `allowedTools` and `deniedTools`, but the policy evaluator only enforces allowlists. Goal: a single list where every tool is either *Allowed* or *Hidden*, removing the denylist concept entirely.
- **Raw config textarea for OAuth connectors** - Advanced overrides (`resource`, `audience`, `scope`, `clientId`) are only accessible for JSON config connectors. OAuth URL connectors need the same raw config panel.
- **Tools list for all connector types** - The tools list view is not shown for all connector types in the admin UI.

### UI / UX

- **Access tags active state** - The current "everything green" chip styling makes it hard to tell which tab is active. Needs better visual contrast.
- **Tool description tooltips** - Tool tags should show the full description on hover.
- **Global loading states** - API requests lack consistent loading indicators; users can interact with stale data during fetches.
- **API key not displayed on reopen** - When a connector is saved with an API key, reopening it shows an empty field because credentials are redacted before being sent to the browser. The UI should indicate a key is stored and allow replacing it.
- **Enhanced error messages** - Error display across the UI needs more actionable copy to help with troubleshooting.
