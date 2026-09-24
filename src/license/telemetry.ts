import https from 'https';
import fs from 'fs';
import path from 'path';
import { GitContext } from './gitContext';

// ─── Config (baked in at publish time) ───────────────────────────────────────

const SUPABASE_URL = 'https://onzfespujyixmzcrsrmc.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_wmKRmr4EANLYfpJyllpxRQ_IZUCOn9o';
const TABLE = 'csh_telemetry';

// ─── Payload ──────────────────────────────────────────────────────────────────

interface TelemetryPayload {
  tool_version: string;
  os_platform: string;
  node_version: string;
  repo_url: string | null;
  owner: string | null;
  repo_name: string | null;
  git_platform: string | null;
  account_type: string | null;
  license_key_provided: boolean;
  timestamp: string;
}

// ─── Version helper ───────────────────────────────────────────────────────────

function getToolVersion(): string {
  try {
    const pkgPath = path.join(__dirname, '..', '..', 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as { version?: string };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

// ─── HTTP POST (no external deps — pure Node https) ──────────────────────────

function postToSupabase(payload: TelemetryPayload): void {
  const body = JSON.stringify(payload);
  const url = new URL(`/rest/v1/${TABLE}`, SUPABASE_URL);

  const options = {
    hostname: url.hostname,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
      'Prefer': 'return=minimal',
    },
  };

  const req = https.request(options);
  req.on('error', () => { /* fire-and-forget — never throw */ });
  req.setTimeout(6000, () => { req.destroy(); });
  req.write(body);
  req.end();
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Sends a non-blocking, fire-and-forget telemetry ping to Supabase.
 *
 * Opt-out: set CSH_TELEMETRY=0 in the environment.
 *
 * What is collected:
 *   - Tool version, OS, Node.js version
 *   - Git remote URL, owner, repo name, platform (github/gitlab/etc.)
 *   - Whether the owner is an Org or personal User (via public GitHub API)
 *   - Whether a commercial license key was provided
 *   - Timestamp
 *
 * Nothing sensitive is ever collected (no secrets, no file contents, no code).
 */
export function sendTelemetry(gitCtx: GitContext | null, licenseKeyProvided: boolean): void {
  // Respect opt-out
  const telemetryEnv = process.env['CSH_TELEMETRY'];
  if (telemetryEnv === '0' || telemetryEnv === 'false') return;

  const payload: TelemetryPayload = {
    tool_version: getToolVersion(),
    os_platform: process.platform,
    node_version: process.version,
    repo_url: gitCtx?.repoUrl ?? null,
    owner: gitCtx?.owner ?? null,
    repo_name: gitCtx?.repoName ?? null,
    git_platform: gitCtx?.platform ?? null,
    account_type: gitCtx?.accountType ?? null,
    license_key_provided: licenseKeyProvided,
    timestamp: new Date().toISOString(),
  };

  // Fully async — does not await, does not block the CLI
  try {
    postToSupabase(payload);
  } catch {
    // Never crash the CLI due to telemetry
  }
}
