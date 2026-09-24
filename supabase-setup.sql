-- ============================================================
-- code-secret-handler — Supabase Setup SQL
-- Run this in your Supabase Dashboard → SQL Editor
-- ============================================================

-- ── Table 1: Usage Telemetry ────────────────────────────────
CREATE TABLE IF NOT EXISTS csh_telemetry (
  id                   bigserial PRIMARY KEY,
  created_at           timestamptz DEFAULT now(),
  tool_version         text,
  os_platform          text,
  node_version         text,
  repo_url             text,
  owner                text,
  repo_name            text,
  git_platform         text,
  account_type         text,
  license_key_provided boolean DEFAULT false,
  timestamp            text
);

-- ── Table 2: Commercial License Keys ───────────────────────
CREATE TABLE IF NOT EXISTS license_keys (
  id          bigserial PRIMARY KEY,
  created_at  timestamptz DEFAULT now(),
  key         text UNIQUE NOT NULL,
  owner_name  text,
  email       text,
  is_active   boolean DEFAULT true,
  expires_at  timestamptz
);

-- ── Enable Row Level Security ───────────────────────────────
ALTER TABLE csh_telemetry  ENABLE ROW LEVEL SECURITY;
ALTER TABLE license_keys   ENABLE ROW LEVEL SECURITY;

-- ── RLS Policy: csh_telemetry ───────────────────────────────
-- Anon users (the CLI) can INSERT rows only (no SELECT/DELETE).
-- Only you (authenticated + service role) can read all rows.

CREATE POLICY "anon can insert telemetry"
  ON csh_telemetry
  FOR INSERT
  TO anon
  WITH CHECK (true);

-- ── RLS Policy: license_keys ────────────────────────────────
-- Anon users (the CLI) can SELECT key + is_active only.
-- Only you can INSERT / UPDATE / DELETE keys.

CREATE POLICY "anon can validate license keys"
  ON license_keys
  FOR SELECT
  TO anon
  USING (true);

-- ============================================================
-- How to add a commercial license key:
--   INSERT INTO license_keys (key, owner_name, email)
--   VALUES ('YOUR-UNIQUE-KEY-HERE', 'Acme Corp', 'acme@example.com');
--
-- How to revoke a key:
--   UPDATE license_keys SET is_active = false WHERE key = 'THE-KEY';
--
-- How to view all telemetry (in Supabase dashboard or SQL):
--   SELECT * FROM csh_telemetry ORDER BY created_at DESC;
-- ============================================================
