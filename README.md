# MCP Gateway

MCP gateway with two personas:

- Admin (web): configures connectors and clients from `/admin/`
- MCP clients (Claude/Cursor/etc.): connect to `/mcp` using issued client tokens

## What It Does

- Admin login via password (`ADMIN_TOKEN`) with session cookie
- Connector management:
  - HTTP OAuth (URL-only + browser OAuth callback)
  - HTTP API token
  - STDIO JSON config
- Client management:
  - create/edit clients
  - assign connector/tool allowlist policy
  - issue/revoke multiple client tokens
- MCP proxying with policy enforcement
- Postgres-backed persistence across restarts
- Encrypted connector credential storage

## Tech Stack

- Node.js + TypeScript
- Fastify
- PostgreSQL
- Vitest

## Environment

Create `.env` from `.env.example`.

Required values:

- `ADMIN_TOKEN`
- `DATABASE_URL`
- `ENCRYPTION_KEY` (32-byte base64 or 64-char hex)

Common optional values:

- `HOST` (default `0.0.0.0`)
- `PORT` (default `3000`)
- `AUTO_MIGRATE` (default `true`)

## Run with Docker

```bash
docker compose up --build
```

Endpoints:

- Admin UI: `http://127.0.0.1:3000/admin/`
- MCP endpoint: `http://127.0.0.1:3000/mcp`
- Health: `http://127.0.0.1:3000/health`

## Run Locally

```bash
npm install
npm run dev
```

Build/start:

```bash
npm run build
npm start
```

## Admin Usage

1. Open `/admin/` and login with password = `ADMIN_TOKEN`
2. Create connector(s)
3. Refresh/discover tools for connector
4. Create client
5. Select allowed tools in client Access tab
6. Save client policy
7. Issue token in Tokens tab (token shown once)

## MCP Client Config Example

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

## Testing

```bash
npm test
```

Includes function/unit tests only.

## Notes

- `/mcp` POST responses are always JSON-RPC formatted.
- Tool names are exported in client-safe format (`connector__tool`) and mapped internally.
- Downstream upstream errors are normalized to MCP error codes/messages.
