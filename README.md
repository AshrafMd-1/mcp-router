# MCP Gateway MVP

MCP gateway with two personas:
- Admin (web only): manage connectors + clients from `/admin/`
- MCP clients (Claude/Cursor/etc.): call `/mcp` with client token

## Run

```bash
docker compose up --build
```

Gateway: `http://127.0.0.1:3000`
Admin UI: `http://127.0.0.1:3000/admin/`

## Admin login

- Username is fixed internally: `admin`
- UI asks only for password
- Password is `ADMIN_TOKEN` env (default `change-me-admin-token`)

## Admin workflow

1. Create connectors:
- `oauth_url` + `http`: only `configJson.url` required, then click **Start OAuth**
- `json_config`: full JSON config for `http` or `stdio`

2. Create clients

3. Configure client policy in client modal:
- select connectors
- click tool tags (unselected -> allow -> deny -> unselected)

4. Issue token (shown once)

5. Use token with MCP clients against `POST /mcp`

## Persistence

All required state is in PostgreSQL:
- connectors
- connector credentials (OAuth/API)
- tool cache
- clients
- client policies
- client tokens
- admin sessions

No audit log persistence in MVP.

## Tests

Function/unit tests only:

```bash
npm test
```
