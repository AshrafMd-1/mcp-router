# Unified MCP Gateway Architecture

## Context

This document defines the architecture for a **Unified MCP Gateway** that exposes a single HTTP MCP endpoint and routes requests to multiple downstream MCP servers (HTTP/SSE or stdio subprocess). The gateway enforces application-level security and policy control via Bearer tokens, while TLS/reverse proxy/IP allowlisting are handled externally.

**Key requirements:**
- Single human user, multiple logical clients/devices
- Per-token visibility and permission control
- Default DENY policy with explicit deny overrides allow
- Tool namespace format: `<connector>.<tool>`
- Downstream secrets stored only in gateway

---

## 1. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MCP GATEWAY                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌─────────────────────────────────────────────────┐    │
│  │   Clients    │    │              HTTP Server (Fastify)               │    │
│  │              │    │                                                   │    │
│  │ ┌──────────┐ │    │  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │    │
│  │ │  Claude  │─┼────┼─▶│ POST /mcp   │  │ GET /mcp    │  │ Admin UI │ │    │
│  │ │  Token A │ │    │  │ (JSON-RPC)  │  │ (SSE stream)│  │ /admin/* │ │    │
│  │ └──────────┘ │    │  └──────┬──────┘  └──────┬──────┘  └────┬─────┘ │    │
│  │              │    │         │                │               │       │    │
│  │ ┌──────────┐ │    │         ▼                ▼               ▼       │    │
│  │ │ OpenClaw │─┼────┼─────────────────────────────────────────────────│    │
│  │ │  Token B │ │    │                                                   │    │
│  │ └──────────┘ │    │  ┌─────────────────────────────────────────────┐ │    │
│  │              │    │  │           Authentication Layer              │ │    │
│  │ ┌──────────┐ │    │  │  • Bearer token validation                  │ │    │
│  │ │  Codex   │─┼────┼─▶│  • Token → Client lookup                    │ │    │
│  │ │  Token C │ │    │  │  • Rate limit check                         │ │    │
│  │ └──────────┘ │    │  └──────────────────┬──────────────────────────┘ │    │
│  └──────────────┘    │                     │                             │    │
│                      │                     ▼                             │    │
│                      │  ┌─────────────────────────────────────────────┐ │    │
│                      │  │            Policy Engine                    │ │    │
│                      │  │  • Parse tool namespace (connector.tool)    │ │    │
│                      │  │  • Check connector visibility               │ │    │
│                      │  │  • Evaluate allow/deny rules (glob match)   │ │    │
│                      │  │  • Check read-only constraint               │ │    │
│                      │  │  • Apply result constraints                 │ │    │
│                      │  └──────────────────┬──────────────────────────┘ │    │
│                      │                     │                             │    │
│                      │                     ▼                             │    │
│                      │  ┌─────────────────────────────────────────────┐ │    │
│                      │  │           Request Router                    │ │    │
│                      │  │  • Route to connector by namespace          │ │    │
│                      │  │  • Aggregate tools/list from connectors     │ │    │
│                      │  │  • Transform tool names (add/strip prefix)  │ │    │
│                      │  └──────────────────┬──────────────────────────┘ │    │
│                      │                     │                             │    │
│                      └─────────────────────┼─────────────────────────────┘    │
│                                            │                                  │
│  ┌─────────────────────────────────────────┴─────────────────────────────┐   │
│  │                      Connector Manager                                 │   │
│  │                                                                        │   │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐     │   │
│  │  │  HTTP Adapter    │  │  HTTP Adapter    │  │  stdio Adapter   │     │   │
│  │  │  (Linear)        │  │  (Glean)         │  │  (filesystem)    │     │   │
│  │  │                  │  │                  │  │                  │     │   │
│  │  │ • OAuth tokens   │  │ • API key auth   │  │ • Subprocess     │     │   │
│  │  │ • SSE streaming  │  │ • JSON response  │  │ • stdin/stdout   │     │   │
│  │  │ • Tool cache     │  │ • Tool cache     │  │ • Process super  │     │   │
│  │  │ • Health check   │  │ • Health check   │  │ • Restart policy │     │   │
│  │  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘     │   │
│  │           │                     │                     │                │   │
│  └───────────┼─────────────────────┼─────────────────────┼────────────────┘   │
│              │                     │                     │                    │
│              ▼                     ▼                     ▼                    │
│  ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────────┐       │
│  │ Linear MCP Server │ │ Glean MCP Server  │ │ Local MCP Subprocess  │       │
│  │ (https://...)     │ │ (https://...)     │ │ (node server.js)      │       │
│  └───────────────────┘ └───────────────────┘ └───────────────────────┘       │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                         PostgreSQL                                       │ │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌────────────┐ ┌───────────────┐  │ │
│  │  │ clients │ │ tokens  │ │connectors│ │ policies   │ │ audit_logs    │  │ │
│  │  │         │ │ (hashed)│ │          │ │            │ │               │  │ │
│  │  └─────────┘ └─────────┘ └──────────┘ └────────────┘ └───────────────┘  │ │
│  │  ┌──────────────┐ ┌────────────────┐ ┌─────────────────┐                │ │
│  │  │ tool_cache   │ │ policy_presets │ │ connector_auth  │                │ │
│  │  └──────────────┘ └────────────────┘ └─────────────────┘                │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. API Design

### 2.1 MCP Endpoint (Client-Facing)

#### POST /mcp
Main MCP endpoint accepting JSON-RPC 2.0 requests.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2025-06-18
Mcp-Session-Id: <session-id>  (after initialization)
```

**Request Body (JSON-RPC 2.0):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "linear.create_issue",
    "arguments": { "title": "Bug fix", "team": "ENG" }
  }
}
```

**Response:**
- `Content-Type: application/json` for single responses
- `Content-Type: text/event-stream` for streaming (SSE)

**Supported Methods:**
| Method | Description | Gateway Behavior |
|--------|-------------|------------------|
| `initialize` | Start session | Create gateway session, return aggregated capabilities |
| `tools/list` | List tools | Return filtered tools based on token policy |
| `tools/call` | Execute tool | Route to connector, apply constraints |
| `resources/list` | List resources | Aggregate from visible connectors |
| `resources/read` | Read resource | Route to connector |
| `prompts/list` | List prompts | Aggregate from visible connectors |
| `prompts/get` | Get prompt | Route to connector |

#### GET /mcp
SSE stream for server-initiated messages.

**Headers:**
```
Authorization: Bearer <token>
Accept: text/event-stream
MCP-Protocol-Version: 2025-06-18
Mcp-Session-Id: <session-id>
Last-Event-ID: <event-id>  (for resumption)
```

---

### 2.2 Admin API

Base path: `/admin/api/v1`

#### Authentication
```
Authorization: Bearer <admin-token>
```

#### Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/connectors` | List all connectors |
| POST | `/connectors` | Create connector |
| GET | `/connectors/:id` | Get connector details |
| PUT | `/connectors/:id` | Update connector |
| DELETE | `/connectors/:id` | Delete connector |
| POST | `/connectors/:id/discover` | Refresh tool cache |
| GET | `/connectors/:id/health` | Get health status |

**Create Connector (HTTP):**
```json
{
  "name": "linear",
  "type": "http",
  "config": {
    "url": "https://linear-mcp.example.com/mcp",
    "auth": {
      "type": "oauth",
      "clientId": "...",
      "clientSecret": "...",
      "tokenEndpoint": "https://api.linear.app/oauth/token",
      "scopes": ["read", "write"]
    }
  }
}
```

**Create Connector (stdio):**
```json
{
  "name": "filesystem",
  "type": "stdio",
  "config": {
    "command": "node",
    "args": ["/opt/mcp-servers/filesystem/index.js"],
    "env": { "ROOT_DIR": "/data" },
    "restart": { "enabled": true, "maxAttempts": 3 }
  }
}
```

#### Clients & Tokens

| Method | Path | Description |
|--------|------|-------------|
| GET | `/clients` | List all clients |
| POST | `/clients` | Create client |
| GET | `/clients/:id` | Get client details |
| PUT | `/clients/:id` | Update client |
| DELETE | `/clients/:id` | Delete client |
| POST | `/clients/:id/tokens` | Issue new token |
| GET | `/clients/:id/tokens` | List tokens |
| DELETE | `/tokens/:id` | Revoke token |
| POST | `/tokens/:id/rotate` | Rotate token |

**Create Client:**
```json
{
  "name": "Claude Desktop",
  "description": "Claude Code on MacBook Pro",
  "policyId": "policy-uuid"
}
```

**Issue Token Response:**
```json
{
  "id": "token-uuid",
  "token": "mgw_live_xxxxxxxxxxxx",  // Only shown once
  "clientId": "client-uuid",
  "createdAt": "2026-02-18T10:00:00Z",
  "expiresAt": null
}
```

#### Policies

| Method | Path | Description |
|--------|------|-------------|
| GET | `/policies` | List all policies |
| POST | `/policies` | Create policy |
| GET | `/policies/:id` | Get policy details |
| PUT | `/policies/:id` | Update policy |
| DELETE | `/policies/:id` | Delete policy |
| GET | `/presets` | List curated presets |
| POST | `/policies/:id/test` | Test policy against tool |

**Create Policy:**
```json
{
  "name": "Linear Write Access",
  "rules": {
    "connectors": ["linear"],
    "allow": ["linear.*"],
    "deny": ["linear.delete_*"],
    "readOnly": false,
    "constraints": {
      "rateLimit": { "requests": 100, "windowMs": 60000 },
      "maxResults": 50
    }
  }
}
```

#### Audit Logs

| Method | Path | Description |
|--------|------|-------------|
| GET | `/audit-logs` | Query audit logs |
| GET | `/audit-logs/:id` | Get log entry |

**Query Parameters:**
- `clientId` - Filter by client
- `connector` - Filter by connector
- `method` - Filter by MCP method
- `status` - Filter by success/error
- `from` / `to` - Date range
- `limit` / `offset` - Pagination

---

## 3. Database Schema

```sql
-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Connectors
CREATE TABLE connectors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('http', 'stdio')),
    config JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Connector authentication secrets (encrypted)
CREATE TABLE connector_auth (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id UUID REFERENCES connectors(id) ON DELETE CASCADE,
    auth_type VARCHAR(20) NOT NULL,  -- 'oauth', 'bearer', 'api_key'
    encrypted_credentials BYTEA NOT NULL,  -- AES-256-GCM encrypted
    token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Cached tools per connector
CREATE TABLE tool_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id UUID REFERENCES connectors(id) ON DELETE CASCADE,
    tool_name VARCHAR(200) NOT NULL,
    title VARCHAR(200),
    description TEXT,
    input_schema JSONB NOT NULL,
    is_read_only BOOLEAN DEFAULT false,  -- Curated classification
    cached_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(connector_id, tool_name)
);

-- Policy presets (curated read-only sets per connector)
CREATE TABLE policy_presets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    connector_id UUID REFERENCES connectors(id) ON DELETE CASCADE,
    rules JSONB NOT NULL,  -- { allow: [], deny: [], readOnly: true }
    is_system BOOLEAN DEFAULT false,  -- System-managed vs user-created
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Policies
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    rules JSONB NOT NULL,
    -- {
    --   connectors: ["linear", "glean"],
    --   allow: ["linear.*", "glean.search"],
    --   deny: ["linear.delete_*"],
    --   readOnly: false,
    --   constraints: { rateLimit: {...}, maxResults: 50 }
    -- }
    preset_ids UUID[],  -- References to policy_presets
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Clients (logical client/device)
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    policy_id UUID REFERENCES policies(id),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tokens (hashed, never stored in plain text after issuance)
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 hash
    token_prefix VARCHAR(12) NOT NULL,  -- First 12 chars for identification
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Rate limit tracking
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER DEFAULT 0,
    UNIQUE(client_id, window_start)
);

-- Audit logs (partitioned by month for performance)
CREATE TABLE audit_logs (
    id UUID DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    client_id UUID,
    token_prefix VARCHAR(12),
    connector_name VARCHAR(100),
    method VARCHAR(50),  -- tools/call, tools/list, etc.
    tool_name VARCHAR(200),
    request_summary JSONB,  -- Sanitized request data
    response_status VARCHAR(20),  -- success, denied, error
    error_message TEXT,
    duration_ms INTEGER,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions (example for Feb 2026)
CREATE TABLE audit_logs_2026_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

-- Indexes
CREATE INDEX idx_connectors_enabled ON connectors(enabled);
CREATE INDEX idx_tool_cache_connector ON tool_cache(connector_id);
CREATE INDEX idx_tokens_hash ON tokens(token_hash);
CREATE INDEX idx_tokens_client ON tokens(client_id);
CREATE INDEX idx_clients_policy ON clients(policy_id);
CREATE INDEX idx_audit_client ON audit_logs(client_id, timestamp);
CREATE INDEX idx_audit_connector ON audit_logs(connector_name, timestamp);
CREATE INDEX idx_rate_limits_window ON rate_limits(client_id, window_start);
```

---

## 4. Policy Evaluation Logic

### 4.1 Policy Data Structure

```typescript
interface Policy {
  id: string;
  name: string;
  rules: PolicyRules;
  presetIds?: string[];  // Inherited preset rules
}

interface PolicyRules {
  // Visible connectors (empty = none visible)
  connectors: string[];

  // Allow patterns (glob syntax)
  allow: string[];  // e.g., ["linear.*", "glean.search_*"]

  // Deny patterns (explicit deny overrides allow)
  deny: string[];   // e.g., ["linear.delete_*", "*.admin_*"]

  // Read-only mode (only allows tools marked as read-only)
  readOnly: boolean;

  // Request constraints
  constraints?: {
    rateLimit?: { requests: number; windowMs: number };
    maxResults?: number;
    timeout?: number;
  };
}
```

### 4.2 Evaluation Algorithm

```typescript
class PolicyEngine {
  /**
   * Evaluate if a tool call is permitted
   * Returns: { allowed: boolean, reason?: string, constraints?: Constraints }
   */
  evaluate(
    policy: Policy,
    toolName: string,  // e.g., "linear.create_issue"
    toolMetadata: ToolMetadata
  ): PolicyDecision {

    // Step 1: Parse namespace
    const [connector, tool] = this.parseToolName(toolName);
    if (!connector || !tool) {
      return { allowed: false, reason: 'INVALID_TOOL_NAME' };
    }

    // Step 2: Check connector visibility
    if (!policy.rules.connectors.includes(connector)) {
      return { allowed: false, reason: 'CONNECTOR_NOT_VISIBLE' };
    }

    // Step 3: Check explicit DENY first (deny overrides allow)
    for (const pattern of policy.rules.deny) {
      if (this.globMatch(toolName, pattern)) {
        return { allowed: false, reason: 'EXPLICIT_DENY', pattern };
      }
    }

    // Step 4: Check read-only constraint
    if (policy.rules.readOnly && !toolMetadata.isReadOnly) {
      return { allowed: false, reason: 'READ_ONLY_VIOLATION' };
    }

    // Step 5: Check ALLOW (default is DENY)
    let allowed = false;
    let matchedPattern: string | undefined;

    for (const pattern of policy.rules.allow) {
      if (this.globMatch(toolName, pattern)) {
        allowed = true;
        matchedPattern = pattern;
        break;
      }
    }

    if (!allowed) {
      return { allowed: false, reason: 'NO_ALLOW_MATCH' };
    }

    // Step 6: Return allowed with constraints
    return {
      allowed: true,
      matchedPattern,
      constraints: policy.rules.constraints
    };
  }

  /**
   * Filter tools/list response based on policy
   */
  filterTools(policy: Policy, tools: Tool[]): Tool[] {
    return tools.filter(tool => {
      const decision = this.evaluate(policy, tool.name, tool);
      return decision.allowed;
    });
  }

  /**
   * Glob pattern matching
   * Supports: * (any chars), ? (single char)
   */
  private globMatch(text: string, pattern: string): boolean {
    const regex = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape regex chars
      .replace(/\*/g, '.*')                    // * → .*
      .replace(/\?/g, '.');                    // ? → .

    return new RegExp(`^${regex}$`).test(text);
  }

  private parseToolName(name: string): [string, string] | [null, null] {
    const parts = name.split('.');
    if (parts.length < 2) return [null, null];
    return [parts[0], parts.slice(1).join('.')];
  }
}
```

### 4.3 Read-Only Classification

Each connector maintains a curated list of read-only tools:

```typescript
// Built-in read-only presets per connector type
const READ_ONLY_PRESETS: Record<string, string[]> = {
  'linear': [
    'linear.get_*',
    'linear.list_*',
    'linear.search_*',
  ],
  'glean': [
    'glean.search',
    'glean.chat',
    'glean.read_document',
    'glean.meeting_lookup',
  ],
  'atlassian': [
    'atlassian.get*',
    'atlassian.search*',
  ],
};

// Tool metadata includes isReadOnly flag from cache
interface ToolMetadata {
  name: string;
  isReadOnly: boolean;  // Curated in tool_cache table
}
```

---

## 5. Connector Adapter Design

### 5.1 Unified Interface

```typescript
interface ConnectorAdapter {
  readonly id: string;
  readonly name: string;
  readonly type: 'http' | 'stdio';
  readonly health: HealthStatus;
  readonly capabilities: ConnectorCapabilities | null;

  initialize(): Promise<ConnectorCapabilities>;
  callTool(name: string, args: unknown, options?: CallOptions): Promise<ToolResult>;
  readResource(uri: string, options?: CallOptions): Promise<ResourceContent>;
  refreshCapabilities(): Promise<ConnectorCapabilities>;
  checkHealth(): Promise<HealthStatus>;
  shutdown(): Promise<void>;
}

interface ConnectorCapabilities {
  tools: ToolDefinition[];
  resources: ResourceDefinition[];
  serverInfo: ServerInfo;
}

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheck: number;
  latencyMs: number | null;
  error: string | null;
}
```

### 5.2 HTTP Adapter (Streamable HTTP)

```typescript
class HttpConnectorAdapter implements ConnectorAdapter {
  private sessionId: string | null = null;
  private pendingRequests: Map<number, PendingRequest> = new Map();
  private toolCache: Map<string, ToolDefinition> = new Map();
  private authProvider: AuthProvider;

  constructor(config: HttpConnectorConfig) {
    this.authProvider = this.createAuthProvider(config.auth);
  }

  async initialize(): Promise<ConnectorCapabilities> {
    // 1. Get auth token
    const token = await this.authProvider.getToken();

    // 2. Send initialize request
    const response = await this.sendRequest('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: { tools: {} },
      clientInfo: { name: 'mcp-gateway', version: '1.0.0' }
    }, { headers: { Authorization: `Bearer ${token}` } });

    // 3. Store session ID
    this.sessionId = response.headers.get('Mcp-Session-Id');

    // 4. Send initialized notification
    await this.sendNotification('notifications/initialized');

    // 5. Discover tools
    return this.refreshCapabilities();
  }

  async callTool(name: string, args: unknown, options?: CallOptions): Promise<ToolResult> {
    const response = await this.sendRequest('tools/call', {
      name,
      arguments: args
    }, {
      timeout: options?.timeout ?? 30000,
      signal: options?.signal
    });

    return response.result;
  }

  private async sendRequest(
    method: string,
    params: unknown,
    options: RequestOptions = {}
  ): Promise<JSONRPCResponse> {
    const id = this.nextRequestId++;
    const token = await this.authProvider.getToken();

    const response = await fetch(this.config.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Authorization': `Bearer ${token}`,
        'MCP-Protocol-Version': '2025-06-18',
        ...(this.sessionId && { 'Mcp-Session-Id': this.sessionId }),
        ...options.headers
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id,
        method,
        params
      }),
      signal: options.signal ?? AbortSignal.timeout(options.timeout ?? 30000)
    });

    if (!response.ok) {
      if (response.status === 401) {
        await this.authProvider.refreshToken();
        return this.sendRequest(method, params, options);  // Retry
      }
      throw new ConnectorError(`HTTP ${response.status}`, response.status);
    }

    const contentType = response.headers.get('Content-Type') ?? '';

    if (contentType.includes('text/event-stream')) {
      return this.consumeSSEResponse(response, id);
    }

    return response.json();
  }

  private async consumeSSEResponse(response: Response, requestId: number): Promise<JSONRPCResponse> {
    // Parse SSE stream and find response matching requestId
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const events = this.parseSSEEvents(buffer);

      for (const event of events.complete) {
        const message = JSON.parse(event.data);
        if (message.id === requestId) {
          return message;
        }
      }

      buffer = events.remaining;
    }

    throw new ConnectorError('SSE stream closed without response');
  }
}
```

### 5.3 stdio Adapter

```typescript
class StdioConnectorAdapter implements ConnectorAdapter {
  private process: ChildProcess | null = null;
  private pendingRequests: Map<number, PendingRequest> = new Map();
  private readBuffer = '';
  private restartAttempts = 0;

  async initialize(): Promise<ConnectorCapabilities> {
    await this.spawnProcess();

    // MCP initialization handshake
    const initResult = await this.sendRequest('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: { tools: {} },
      clientInfo: { name: 'mcp-gateway', version: '1.0.0' }
    });

    await this.sendNotification('notifications/initialized');

    return this.refreshCapabilities();
  }

  private async spawnProcess(): Promise<void> {
    const { command, args, cwd, env } = this.config;

    this.process = spawn(command, args ?? [], {
      cwd,
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Read stdout (newline-delimited JSON)
    this.process.stdout!.on('data', (chunk: Buffer) => {
      this.readBuffer += chunk.toString('utf-8');
      this.processReadBuffer();
    });

    // Log stderr
    this.process.stderr!.on('data', (chunk: Buffer) => {
      this.logger.debug(`[${this.name}] stderr: ${chunk.toString()}`);
    });

    // Handle crashes
    this.process.on('exit', (code, signal) => {
      this.handleProcessExit(code, signal);
    });
  }

  private processReadBuffer(): void {
    const lines = this.readBuffer.split('\n');
    this.readBuffer = lines.pop() ?? '';

    for (const line of lines) {
      if (!line.trim()) continue;

      try {
        const message = JSON.parse(line);
        this.handleMessage(message);
      } catch (err) {
        this.logger.error(`Invalid JSON from subprocess: ${line}`);
      }
    }
  }

  async callTool(name: string, args: unknown): Promise<ToolResult> {
    return this.sendRequest('tools/call', { name, arguments: args });
  }

  private async sendRequest(method: string, params: unknown): Promise<any> {
    const id = this.nextRequestId++;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new TimeoutError(`Request ${method} timed out`));
      }, this.config.timeout ?? 30000);

      this.pendingRequests.set(id, { resolve, reject, timeout });

      const message = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
      this.process!.stdin!.write(message);
    });
  }

  async shutdown(): Promise<void> {
    if (!this.process) return;

    // Graceful shutdown sequence
    // 1. Close stdin
    this.process.stdin!.end();

    // 2. Wait for graceful exit (2s)
    const exited = await this.waitForExit(2000);
    if (exited) return;

    // 3. SIGTERM
    this.process.kill('SIGTERM');
    const terminated = await this.waitForExit(2000);
    if (terminated) return;

    // 4. SIGKILL
    this.process.kill('SIGKILL');
  }

  private async handleProcessExit(code: number | null, signal: string | null): Promise<void> {
    if (code === 0) return;  // Clean exit

    // Auto-restart if configured
    if (this.config.restart?.enabled && this.restartAttempts < this.config.restart.maxAttempts) {
      this.restartAttempts++;
      await this.sleep(this.config.restart.delay * this.restartAttempts);
      await this.spawnProcess();
      await this.initialize();
    }
  }
}
```

---

## 6. Deployment Structure

### 6.1 Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  gateway:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgres://mcpgw:${DB_PASSWORD}@postgres:5432/mcpgw
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - ADMIN_TOKEN=${ADMIN_TOKEN}
      - LOG_LEVEL=info
    volumes:
      - ./mcp-servers:/opt/mcp-servers:ro  # For stdio servers
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=mcpgw
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=mcpgw
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U mcpgw"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

### 6.2 Dockerfile

```dockerfile
# Dockerfile
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner

WORKDIR /app
RUN apk add --no-cache curl

# Copy built app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Non-root user
RUN addgroup -g 1001 -S mcpgw && \
    adduser -S mcpgw -u 1001 -G mcpgw
USER mcpgw

EXPOSE 3000
CMD ["node", "dist/main.js"]
```

### 6.3 Directory Structure

```
mcp-gateway/
├── src/
│   ├── main.ts                    # Entry point
│   ├── config/
│   │   ├── index.ts               # Configuration loader
│   │   └── schema.ts              # Config validation (zod)
│   ├── server/
│   │   ├── fastify.ts             # Fastify server setup
│   │   ├── routes/
│   │   │   ├── mcp.ts             # POST/GET /mcp
│   │   │   └── admin.ts           # /admin/api/v1/*
│   │   └── middleware/
│   │       ├── auth.ts            # Token validation
│   │       └── logging.ts         # Request logging
│   ├── mcp/
│   │   ├── protocol.ts            # JSON-RPC types
│   │   ├── session.ts             # Session management
│   │   └── router.ts              # Request routing
│   ├── connectors/
│   │   ├── manager.ts             # Connector lifecycle
│   │   ├── adapter.ts             # Base interface
│   │   ├── http-adapter.ts        # HTTP/SSE adapter
│   │   └── stdio-adapter.ts       # stdio adapter
│   ├── policy/
│   │   ├── engine.ts              # Policy evaluation
│   │   ├── presets.ts             # Read-only presets
│   │   └── rate-limiter.ts        # Rate limiting
│   ├── auth/
│   │   ├── tokens.ts              # Token generation/validation
│   │   ├── oauth-provider.ts      # OAuth client
│   │   └── encryption.ts          # Credential encryption
│   ├── db/
│   │   ├── client.ts              # PostgreSQL client
│   │   ├── repositories/
│   │   │   ├── connectors.ts
│   │   │   ├── clients.ts
│   │   │   ├── policies.ts
│   │   │   └── audit.ts
│   │   └── migrations/
│   │       └── 001_initial.sql
│   ├── admin/
│   │   ├── ui/                    # Static admin UI (Vite + React)
│   │   └── api/                   # Admin API handlers
│   └── logging/
│       ├── logger.ts              # Structured logging
│       └── audit.ts               # Audit log service
├── admin-ui/                      # Admin UI source (separate build)
├── tests/
├── docker-compose.yml
├── Dockerfile
└── package.json
```

---

## 7. Build Plan (MVP → Hardened)

### Phase 1: Foundation (Week 1)
**Goal:** Basic MCP proxy with single HTTP connector

- [ ] Project setup (TypeScript, ESLint, Vitest)
- [ ] PostgreSQL client and migrations
- [ ] Configuration loading (env vars, validation)
- [ ] Fastify server with `/health` endpoint
- [ ] JSON-RPC parser and types
- [ ] Basic HTTP connector adapter (no auth)
- [ ] POST /mcp endpoint (pass-through to single connector)
- [ ] Structured JSON logging to stdout

**Verification:** Can proxy `tools/list` and `tools/call` to a single downstream MCP server

### Phase 2: Multi-Connector & Routing (Week 2)
**Goal:** Support multiple connectors with namespaced tools

- [ ] Connector manager (lifecycle, health checks)
- [ ] Tool namespace transformation (`<connector>.<tool>`)
- [ ] Request router (parse namespace, route to connector)
- [ ] Aggregated `tools/list` response
- [ ] Tool cache in database
- [ ] stdio connector adapter (subprocess management)
- [ ] Process supervision (restart on crash)

**Verification:** Can route requests to Linear HTTP + filesystem stdio connectors

### Phase 3: Authentication & Tokens (Week 3)
**Goal:** Token-based client authentication

- [ ] Token generation (cryptographically secure)
- [ ] Token hashing (SHA-256, never store plain)
- [ ] Token validation middleware
- [ ] Clients and tokens database tables
- [ ] Admin API: create/list/revoke tokens
- [ ] Token prefix for identification in logs
- [ ] Last-used tracking

**Verification:** Requests without valid token are rejected with 401

### Phase 4: Policy Engine (Week 4)
**Goal:** Per-token access control

- [ ] Policy data model and storage
- [ ] Glob pattern matching
- [ ] Policy evaluation algorithm
- [ ] Connector visibility filtering
- [ ] Allow/deny rule processing
- [ ] Read-only constraint
- [ ] Filtered `tools/list` based on policy
- [ ] Policy presets (curated read-only sets)

**Verification:** Different tokens see different tools, deny rules work

### Phase 5: Constraints & Rate Limiting (Week 5)
**Goal:** Request constraints and audit logging

- [ ] Rate limiter (sliding window in Postgres)
- [ ] Max results constraint
- [ ] Request timeout enforcement
- [ ] Audit log table (partitioned)
- [ ] Audit log insertion on every request
- [ ] Admin API: query audit logs
- [ ] Sanitization of sensitive data in logs

**Verification:** Rate limits enforced, audit trail complete

### Phase 6: Downstream Auth (Week 6)
**Goal:** OAuth and API key auth for connectors

- [ ] Credential encryption (AES-256-GCM)
- [ ] OAuth client credentials flow
- [ ] OAuth token refresh
- [ ] Bearer token injection
- [ ] API key header injection
- [ ] Auth error handling (401 → refresh)
- [ ] Encrypted storage in connector_auth table

**Verification:** Can authenticate to Linear (OAuth) and Glean (API key)

### Phase 7: SSE Streaming (Week 7)
**Goal:** Full SSE support for both client and connector sides

- [ ] GET /mcp SSE endpoint for server-initiated messages
- [ ] Session management (Mcp-Session-Id)
- [ ] SSE response parsing from connectors
- [ ] SSE response generation to clients
- [ ] Resumability (Last-Event-ID)
- [ ] Progress notifications passthrough

**Verification:** Streaming tool responses work end-to-end

### Phase 8: Admin UI (Week 8)
**Goal:** Web UI for management

- [ ] React + Vite admin UI scaffold
- [ ] Connector management UI
- [ ] Client and token management UI
- [ ] Policy editor with validation
- [ ] Audit log viewer with filters
- [ ] Health dashboard
- [ ] Static file serving from Fastify

**Verification:** Can manage entire gateway from browser

### Phase 9: Hardening (Week 9)
**Goal:** Production readiness

- [ ] Input validation on all endpoints (zod)
- [ ] Error handling standardization
- [ ] Graceful shutdown (drain connections)
- [ ] Connection pooling tuning
- [ ] Request ID tracing
- [ ] Health endpoint with dependency checks
- [ ] Docker multi-stage build optimization
- [ ] Security headers (Helmet)

### Phase 10: Testing & Documentation (Week 10)
**Goal:** Test coverage and docs

- [ ] Unit tests for policy engine
- [ ] Integration tests for connectors
- [ ] E2E tests for MCP endpoint
- [ ] API documentation (OpenAPI)
- [ ] Deployment guide
- [ ] Operations runbook

---

## 8. Example Policies

### Claude Token: Linear Write Access
```json
{
  "name": "Claude - Linear Write",
  "rules": {
    "connectors": ["linear"],
    "allow": ["linear.*"],
    "deny": [
      "linear.delete_*",
      "linear.*_milestone",
      "linear.*_initiative"
    ],
    "readOnly": false,
    "constraints": {
      "rateLimit": { "requests": 200, "windowMs": 60000 }
    }
  }
}
```

### OpenClaw Token: Linear Read-Only
```json
{
  "name": "OpenClaw - Linear Read-Only",
  "rules": {
    "connectors": ["linear"],
    "allow": ["linear.*"],
    "deny": [],
    "readOnly": true,
    "constraints": {
      "rateLimit": { "requests": 100, "windowMs": 60000 },
      "maxResults": 50
    }
  }
}
```

### Codex Token: Glean Search + Linear Search Only
```json
{
  "name": "Codex - Search Only",
  "rules": {
    "connectors": ["glean", "linear"],
    "allow": [
      "glean.search",
      "glean.chat",
      "glean.read_document",
      "linear.list_*",
      "linear.get_*",
      "linear.search_*"
    ],
    "deny": [],
    "readOnly": true,
    "constraints": {
      "rateLimit": { "requests": 50, "windowMs": 60000 },
      "maxResults": 20
    }
  }
}
```

---

## 9. Risks and Mitigations

### 9.1 Schema Drift
**Risk:** Connector tool schemas change, cached data becomes stale.

**Mitigations:**
- TTL-based cache expiration (default 5 minutes)
- Background refresh before TTL
- `notifications/tools/list_changed` handling
- Manual refresh via Admin API
- Version tracking in tool_cache table

### 9.2 Streaming Complexity
**Risk:** SSE streaming adds complexity, potential for resource leaks.

**Mitigations:**
- Request timeout enforcement (hard kill)
- Connection limits per client
- Backpressure handling
- Explicit stream cleanup on disconnect
- Memory monitoring for long streams

### 9.3 Tool Name Collisions
**Risk:** Two connectors expose tools with same name.

**Mitigations:**
- Namespace prefix is mandatory (`connector.tool`)
- Reject connector registration if collision detected
- Unique constraint in tool_cache per connector

### 9.4 Authentication Token Leaks
**Risk:** Tokens exposed in logs, errors, or responses.

**Mitigations:**
- Tokens shown only once on creation
- Store only SHA-256 hash
- Prefix used for identification (first 12 chars)
- Sanitize all log output
- Never include tokens in error responses

### 9.5 Downstream Auth Failures
**Risk:** OAuth token expires mid-request, or refresh fails.

**Mitigations:**
- Proactive token refresh (60s before expiry)
- Retry with refresh on 401
- Circuit breaker pattern for repeated failures
- Clear error propagation to client
- Audit log of auth failures

### 9.6 subprocess Instability
**Risk:** stdio servers crash, hang, or produce invalid output.

**Mitigations:**
- Request timeout (kill subprocess if exceeded)
- Auto-restart with exponential backoff
- Max restart attempts limit
- Health check via ping
- Graceful shutdown sequence (stdin close → SIGTERM → SIGKILL)
- stderr logging for debugging

### 9.7 Denial of Service
**Risk:** Malicious client exhausts resources.

**Mitigations:**
- Per-token rate limiting
- Request size limits
- Connection limits
- Timeout enforcement
- Result set limits (maxResults)
- External rate limiting at reverse proxy

### 9.8 Audit Log Volume
**Risk:** Audit logs grow unbounded, impact performance.

**Mitigations:**
- Table partitioning by month
- Automatic partition creation
- Retention policy (drop old partitions)
- Async log insertion (non-blocking)
- Indexed query paths
- Summary tables for analytics

---

## 10. Critical Files for Implementation

| File | Purpose |
|------|---------|
| `src/policy/engine.ts` | Core policy evaluation logic |
| `src/connectors/http-adapter.ts` | HTTP/SSE connector |
| `src/connectors/stdio-adapter.ts` | stdio subprocess connector |
| `src/mcp/router.ts` | Request routing and namespace handling |
| `src/auth/tokens.ts` | Token generation and validation |
| `src/server/routes/mcp.ts` | Main MCP endpoint handlers |
| `src/db/migrations/001_initial.sql` | Database schema |

---

## 11. Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Runtime | Node.js 22 | LTS, native fetch, excellent MCP SDK support |
| Framework | Fastify | Fast, TypeScript-first, plugin ecosystem |
| Database | PostgreSQL 16 | JSONB, partitioning, proven reliability |
| ORM | Drizzle | Type-safe, lightweight, good migrations |
| Validation | Zod | TypeScript-native, composable |
| Admin UI | React + Vite | Fast dev, small bundle |
| Testing | Vitest | Fast, ESM-native |
| Logging | Pino | Fast structured JSON logging |
