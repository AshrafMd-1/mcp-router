DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS policy_presets CASCADE;
DROP TABLE IF EXISTS connector_auth CASCADE;
DROP TABLE IF EXISTS tool_cache CASCADE;
DROP TABLE IF EXISTS policies CASCADE;
DROP TABLE IF EXISTS tokens CASCADE;
DROP TABLE IF EXISTS admin_sessions CASCADE;
DROP TABLE IF EXISTS client_tokens CASCADE;
DROP TABLE IF EXISTS client_policies CASCADE;
DROP TABLE IF EXISTS connector_tool_cache CASCADE;
DROP TABLE IF EXISTS connector_credentials CASCADE;
DROP TABLE IF EXISTS clients CASCADE;
DROP TABLE IF EXISTS connectors CASCADE;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE connectors (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) UNIQUE NOT NULL,
  mode VARCHAR(20) NOT NULL CHECK (mode IN ('oauth_url', 'json_config')),
  transport VARCHAR(20) NOT NULL CHECK (transport IN ('http', 'stdio')),
  enabled BOOLEAN DEFAULT true,
  config_json JSONB NOT NULL,
  health_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
  health_error TEXT,
  last_health_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE connector_credentials (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  connector_id UUID REFERENCES connectors(id) ON DELETE CASCADE,
  auth_kind VARCHAR(20) NOT NULL CHECK (auth_kind IN ('oauth_tokens', 'api_header', 'none')),
  encrypted_secret BYTEA NOT NULL,
  expires_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (connector_id, auth_kind)
);

CREATE TABLE connector_tool_cache (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  connector_id UUID REFERENCES connectors(id) ON DELETE CASCADE,
  tool_name VARCHAR(200) NOT NULL,
  tool_title VARCHAR(200),
  tool_description TEXT,
  input_schema JSONB NOT NULL,
  is_read_only BOOLEAN DEFAULT false,
  cached_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(connector_id, tool_name)
);

CREATE TABLE clients (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) NOT NULL,
  description TEXT,
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE client_policies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id UUID UNIQUE REFERENCES clients(id) ON DELETE CASCADE,
  connector_ids UUID[] NOT NULL DEFAULT '{}',
  allowed_tools TEXT[] NOT NULL DEFAULT '{}',
  denied_tools TEXT[] NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE client_tokens (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
  token_hash VARCHAR(64) UNIQUE NOT NULL,
  token_prefix VARCHAR(12) NOT NULL,
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE admin_sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  session_id VARCHAR(128) UNIQUE NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_connector_tool_cache_connector ON connector_tool_cache(connector_id);
CREATE INDEX idx_client_tokens_hash ON client_tokens(token_hash);
CREATE INDEX idx_client_tokens_client ON client_tokens(client_id);
CREATE INDEX idx_client_policies_client ON client_policies(client_id);
CREATE INDEX idx_admin_sessions_session_id ON admin_sessions(session_id);
