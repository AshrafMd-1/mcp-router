# MCP Gateway - Agent Instructions

## Project Overview

**MCP Gateway** is a multi-tenant proxy/router for Model Context Protocol (MCP) servers. It allows organizations to:
- Centrally manage connections to multiple MCP servers (connectors)
- Issue client tokens with fine-grained access policies
- Enforce tool-level allowlists per client
- Support both HTTP and stdio transport protocols
- Handle OAuth authentication for upstream MCP servers

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Code    │────▶│   MCP Gateway   │────▶│  MCP Servers    │
│  (Client)       │     │   (This Repo)   │     │  (Connectors)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │ Bearer Token          │ Policy Engine         │ HTTP/stdio
        │                       │ Tool Allowlist        │
        └───────────────────────┴───────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js 22+ |
| Server | Fastify 5.x |
| Database | PostgreSQL (via `pg`) |
| Validation | Zod |
| Build | TypeScript 5.7 |
| Test | Vitest |

## Directory Structure

```
src/
├── main.ts                    # Entry point
├── app-context.ts             # Dependency injection container
├── config/
│   ├── index.ts               # Config loader
│   └── schema.ts              # Zod config schema
├── connectors/
│   ├── adapter.ts             # ConnectorAdapter interface
│   ├── http-adapter.ts        # HTTP transport (Streamable HTTP)
│   ├── stdio-adapter.ts       # stdio transport
│   ├── manager.ts             # ConnectorManager runtime registry
│   ├── oauth-discovery.ts     # OAuth 2.0 discovery
│   ├── oauth-types.ts         # OAuth type definitions
│   ├── auth-provider.ts       # Auth state extraction
│   └── protocol-constants.ts  # MCP protocol versions
├── mcp/
│   ├── protocol.ts            # JSON-RPC types
│   ├── router.ts              # Request routing logic
│   ├── session.ts             # Session management
│   ├── policy-evaluator.ts    # Tool allowlist enforcement
│   └── error-mapper.ts        # MCP error codes
├── db/
│   ├── client.ts              # PostgreSQL connection
│   └── repositories/
│       ├── clients.ts         # Client CRUD
│       ├── connectors.ts      # Connector CRUD
│       ├── client-policies.ts # Access policies
│       ├── connector-credentials.ts # OAuth tokens
│       ├── tool-cache.ts      # Tool catalog cache
│       └── admin-sessions.ts  # Admin UI sessions
├── auth/
│   └── tokens.ts              # Client token issuing/validation
├── security/
│   └── crypto.ts              # Hashing utilities
├── server/
│   ├── fastify.ts             # Server setup
│   ├── middleware/
│   │   └── auth.ts            # Cookie/Bearer auth
│   └── routes/
│       ├── admin.ts           # Admin API endpoints
│       └── mcp.ts             # MCP protocol endpoint
└── admin/
    └── ui/
        ├── index.html         # Admin dashboard
        └── app.js             # Frontend JavaScript
```

## Key Concepts

### Connectors
Backend MCP servers registered with the gateway. Two types:
- **HTTP**: Uses Streamable HTTP transport (SDK-aligned)
- **stdio**: Spawns local process with JSON-RPC over stdin/stdout

### Clients
API consumers identified by bearer tokens. Each client has:
- Name and description
- Enabled/disabled status
- Access policy (connectorIds + allowedTools)

### Policies
Per-client access control:
- `connectorIds`: Which connectors are accessible
- `allowedTools`: Glob patterns for allowed tool names (e.g., `connector.*`)
- `deniedTools`: Explicit tool blocklist (optional)

### Tool Naming
Tools are namespaced: `{connectorName}.{toolName}`
Example: `github.create_issue`, `slack.send_message`

## API Reference

### Admin Routes (`/admin/*`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/admin/login` | Authenticate with ADMIN_TOKEN |
| POST | `/admin/logout` | Clear session |
| GET | `/admin/session` | Check auth status |
| GET | `/admin/connectors` | List all connectors |
| POST | `/admin/connectors` | Create connector |
| PUT | `/admin/connectors/:id` | Update connector |
| DELETE | `/admin/connectors/:id` | Delete connector |
| POST | `/admin/connectors/:id/discover` | Refresh tools |
| GET | `/admin/connectors/:id/health` | Check health |
| POST | `/admin/connectors/:id/oauth/start` | Begin OAuth flow |
| GET | `/admin/oauth/callback` | OAuth callback |
| GET | `/admin/clients` | List all clients |
| POST | `/admin/clients` | Create client |
| PUT | `/admin/clients/:id` | Update client (name, description, enabled) |
| DELETE | `/admin/clients/:id` | Delete client |
| GET | `/admin/clients/:id/policy` | Get access policy |
| PUT | `/admin/clients/:id/policy` | Update access policy |
| GET | `/admin/clients/:id/tokens` | List tokens |
| POST | `/admin/clients/:id/tokens` | Issue new token |
| DELETE | `/admin/clients/:id/tokens/:tokenId` | Revoke token |
| POST | `/admin/tokens/:id/rotate` | Rotate token (revoke + issue new) |
| GET | `/admin/tool-catalog?connectorId=` | List tools for connector |

### MCP Routes (`/mcp`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/mcp` | JSON-RPC endpoint (tools/call, etc.) |

## Configuration

Environment variables (`.env`):

```bash
DATABASE_URL=postgresql://user:pass@localhost:5432/mcp_gateway
ADMIN_TOKEN=your-admin-password
ADMIN_SESSION_HOURS=24
PORT=3000
HOST=0.0.0.0
```

## Recent Changes (API Contract Audit)

### Backend Fixes

1. **customHeaders pass-through** (`admin.ts:65-79`)
   - `toRuntimeConnector()` now extracts `configJson.headers` as `customHeaders`
   - Passed to `HttpConnectorAdapter` which merges into request headers
   - SDK-aligned: matches TypeScript SDK's `_commonHeaders()` pattern

2. **deniedTools schema usage** (`admin.ts:633`)
   - Changed from hardcoded `deniedTools: []` to `parsed.data.deniedTools`
   - Schema at line 40 accepts optional `deniedTools` array

### Frontend Fixes

3. **Toggle client handler** (`app.js`)
   - Added handler for `data-act="toggle-client"` button
   - Calls `PUT /admin/clients/:id` with `{ enabled: !current }`

4. **Token rotate feature** (`app.js`)
   - Added "Rotate" button in token list
   - Calls `POST /admin/tokens/:id/rotate`
   - Displays new token value after rotation

5. **Custom headers format** (`app.js:699`)
   - Changed from `{ url, Authorization: "..." }`
   - To `{ url, headers: { Authorization: "..." } }`
   - Matches backend expectation for nested headers

6. **Denied tools UI** (`app.js`)
   - Added `deniedTools` Set for tracking
   - 3-state cycle: none → allow → deny → none (click to cycle)
   - Right-click to directly toggle deny
   - Visual indicators: green (allow), red (deny), neutral (none)
   - Sends `deniedTools` array in policy update

## Policy Enforcement Logic

```typescript
// src/mcp/policy-evaluator.ts
function isToolAllowed(policy, toolName, connectorId) {
  // 1. Check connector is selected
  if (!policy.connectorIds.includes(connectorId)) {
    return { allowed: false, reason: 'CONNECTOR_NOT_SELECTED' };
  }

  // 2. Check tool matches allowlist pattern
  for (const pattern of policy.allowedTools) {
    if (globMatch(toolName, pattern)) {
      return { allowed: true };
    }
  }

  return { allowed: false, reason: 'NOT_ALLOWED' };
}
```

**Note**: Current implementation uses allowlist-only approach. `deniedTools` is stored but not enforced in `policy-evaluator.ts`. To enable deny enforcement, update the evaluator to check deniedTools before allowedTools.

## HTTP Adapter Protocol Compliance

The `HttpConnectorAdapter` follows the MCP TypeScript SDK patterns:

1. **Initialize handshake** (`initialize` → `notifications/initialized`)
2. **Protocol version negotiation** (supports 2024-11-05, 2025-01-15)
3. **Session management** via `Mcp-Session-Id` header
4. **401 handling** with OAuth discovery hints from `WWW-Authenticate`
5. **Custom headers** merged without overwriting auth/protocol headers

## Development

```bash
# Install dependencies
npm install

# Run with hot reload
npm run dev

# Build for production
npm run build

# Run production build
npm start

# Run tests
npm test
```

## Testing Checklist

After making changes, verify:

- [ ] `npm run build` passes with 0 errors
- [ ] Admin UI loads at http://localhost:3000/admin
- [ ] Can create/update/delete connectors
- [ ] Can create/update/delete clients
- [ ] Can toggle client enabled status
- [ ] Can issue/revoke/rotate tokens
- [ ] Can configure tool allowlist with glob patterns
- [ ] Can configure denied tools
- [ ] OAuth flow completes for oauth_url connectors
- [ ] MCP tools/call works with valid client token

## Security Considerations

- Admin authentication via `ADMIN_TOKEN` + session cookies
- Client authentication via Bearer tokens (hashed in DB)
- Tool-level access control per client
- OAuth tokens stored encrypted in `connector_credentials`
- Custom headers don't override `Authorization` or `mcp-*` headers
