import https from 'https';
import chalk from 'chalk';
import { GitContext } from './gitContext';

// ─── Config ───────────────────────────────────────────────────────────────────

const SUPABASE_URL = 'https://onzfespujyixmzcrsrmc.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_wmKRmr4EANLYfpJyllpxRQ_IZUCOn9o';
const CONTACT_EMAIL = 'vic.grambo@gmail.com';

// ─── Supabase license key validator ──────────────────────────────────────────

/**
 * Checks the `license_keys` table in Supabase for a matching active key.
 * Returns true if the key is valid and active.
 */
function validateKeyOnline(licenseKey: string): Promise<boolean> {
  return new Promise((resolve) => {
    const encodedKey = encodeURIComponent(licenseKey);
    const url = new URL(
      `/rest/v1/license_keys?key=eq.${encodedKey}&is_active=eq.true&select=key`,
      SUPABASE_URL
    );

    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'GET',
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
        'Accept': 'application/json',
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const rows = JSON.parse(data) as unknown[];
          resolve(Array.isArray(rows) && rows.length > 0);
        } catch {
          resolve(false);
        }
      });
    });

    req.on('error', () => resolve(false));
    req.setTimeout(6000, () => { req.destroy(); resolve(false); });
    req.end();
  });
}

// ─── Hard-block banner ────────────────────────────────────────────────────────

function printBlockBanner(gitCtx: GitContext | null): void {
  const owner = gitCtx?.owner ?? 'Unknown';
  const repo  = gitCtx ? `${gitCtx.owner}/${gitCtx.repoName}` : 'Unknown';
  const type  = gitCtx?.accountType === 'Organization' ? 'GitHub Organization' : 'Organization / Company';
  const w = 65;
  const line = '─'.repeat(w);

  console.log('\n' + chalk.red('┌' + line + '┐'));
  const title = '  🚫  COMMERCIAL USE DETECTED — LICENSE REQUIRED';
  console.log(chalk.red('│') + chalk.bold.red(title.padEnd(w)) + chalk.red('│'));
  console.log(chalk.red('│' + ' '.repeat(w) + '│'));

  const rows = [
    `  This tool is free for personal use only.`,
    `  The scanned repo appears to belong to an organization:`,
    ``,
    `  Owner  : ${owner}  (${type})`,
    `  Repo   : ${repo}`,
    ``,
    `  To use code-secret-handler commercially or within an`,
    `  organization, you must obtain a commercial license.`,
    ``,
    `  Contact : ${CONTACT_EMAIL}`,
    `  Set     : CSH_LICENSE_KEY=<your-key>  to proceed`,
    ``,
    `  To opt out of telemetry: CSH_TELEMETRY=0`,
  ];

  for (const row of rows) {
    console.log(chalk.red('│') + chalk.yellow(row.padEnd(w)) + chalk.red('│'));
  }

  console.log(chalk.red('└' + line + '┘') + '\n');
}

// ─── Main export ──────────────────────────────────────────────────────────────

export interface LicenseCheckResult {
  /** Whether execution is allowed to continue */
  allowed: boolean;
  /** Whether a valid commercial license key was provided */
  licenseKeyProvided: boolean;
}

/**
 * Performs the full license check:
 *
 * 1. If CSH_LICENSE_KEY is set → validate it online against Supabase.
 *    - Valid   → allow (commercial user with a valid key)
 *    - Invalid → treat as unlicensed org and block
 *
 * 2. If no key and the owner is a GitHub Organization → hard-block with banner.
 *
 * 3. All other cases (personal user, unknown, no git remote) → allow freely.
 *
 * Hard-blocks call process.exit(1).
 */
export async function checkLicense(gitCtx: GitContext | null): Promise<LicenseCheckResult> {
  const licenseKey = process.env['CSH_LICENSE_KEY']?.trim();

  // ── Step 1: License key provided → validate online ──────────────────────────
  if (licenseKey) {
    console.log(chalk.gray('  🔑  Validating commercial license key…'));
    const valid = await validateKeyOnline(licenseKey);

    if (valid) {
      console.log(chalk.green('  ✅  Commercial license verified. Thank you!\n'));
      return { allowed: true, licenseKeyProvided: true };
    } else {
      // Invalid key — treat as unlicensed org
      console.log(chalk.red('  ❌  License key is invalid or expired.\n'));
      printBlockBanner(gitCtx);
      process.exit(1);
    }
  }

  // ── Step 2: No key → check if this is an org repo ───────────────────────────
  if (gitCtx?.accountType === 'Organization') {
    printBlockBanner(gitCtx);
    process.exit(1);
  }

  // ── Step 3: Personal user, unknown, or no git context → allow freely ────────
  return { allowed: true, licenseKeyProvided: false };
}
