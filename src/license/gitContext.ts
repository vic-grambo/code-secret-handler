import { execSync } from 'child_process';
import https from 'https';

// ─── Types ────────────────────────────────────────────────────────────────────

export type GitPlatform = 'github' | 'gitlab' | 'bitbucket' | 'other';
export type AccountType = 'Organization' | 'User' | 'unknown';

export interface GitContext {
  repoUrl: string;
  owner: string;
  repoName: string;
  platform: GitPlatform;
  accountType: AccountType;
}

// ─── Parse remote URL ─────────────────────────────────────────────────────────

/**
 * Parses a git remote URL (SSH or HTTPS) into owner, repo, and platform.
 * Supports:
 *   git@github.com:owner/repo.git
 *   https://github.com/owner/repo.git
 *   git@gitlab.com:owner/repo.git
 *   https://bitbucket.org/owner/repo.git
 */
function parseRemoteUrl(remoteUrl: string): { owner: string; repoName: string; platform: GitPlatform } | null {
  // SSH format: git@<host>:<owner>/<repo>.git
  const sshMatch = remoteUrl.match(/git@([^:]+):([^/]+)\/(.+?)(?:\.git)?$/);
  if (sshMatch) {
    const host = sshMatch[1].toLowerCase();
    const owner = sshMatch[2];
    const repoName = sshMatch[3];
    return { owner, repoName, platform: detectPlatform(host) };
  }

  // HTTPS format: https://<host>/<owner>/<repo>.git
  const httpsMatch = remoteUrl.match(/https?:\/\/([^/]+)\/([^/]+)\/(.+?)(?:\.git)?$/);
  if (httpsMatch) {
    const host = httpsMatch[1].toLowerCase();
    const owner = httpsMatch[2];
    const repoName = httpsMatch[3];
    return { owner, repoName, platform: detectPlatform(host) };
  }

  return null;
}

function detectPlatform(host: string): GitPlatform {
  if (host.includes('github')) return 'github';
  if (host.includes('gitlab')) return 'gitlab';
  if (host.includes('bitbucket')) return 'bitbucket';
  return 'other';
}

// ─── GitHub API: org vs user ──────────────────────────────────────────────────

/**
 * Calls the public unauthenticated GitHub API to determine whether an owner
 * is a personal User or an Organization. Returns 'unknown' on any failure.
 */
function fetchGitHubAccountType(owner: string): Promise<AccountType> {
  return new Promise((resolve) => {
    const options = {
      hostname: 'api.github.com',
      path: `/users/${encodeURIComponent(owner)}`,
      method: 'GET',
      headers: {
        'User-Agent': 'code-secret-handler',
        'Accept': 'application/vnd.github+json',
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data) as { type?: string };
          if (json.type === 'Organization') resolve('Organization');
          else if (json.type === 'User') resolve('User');
          else resolve('unknown');
        } catch {
          resolve('unknown');
        }
      });
    });

    req.on('error', () => resolve('unknown'));
    req.setTimeout(4000, () => { req.destroy(); resolve('unknown'); });
    req.end();
  });
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Reads the git remote origin URL from the target directory, parses it,
 * and (for GitHub repos) checks whether the owner is an Org or personal User.
 * Returns null if the directory has no git remote or is not a git repo.
 */
export async function getGitContext(targetDir: string): Promise<GitContext | null> {
  try {
    const rawUrl = execSync(`git -C "${targetDir}" config --get remote.origin.url`, {
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 4000,
    })
      .toString()
      .trim();

    if (!rawUrl) return null;

    const parsed = parseRemoteUrl(rawUrl);
    if (!parsed) return null;

    const { owner, repoName, platform } = parsed;

    // Only query GitHub API for GitHub repos (GitLab/Bitbucket have different APIs)
    let accountType: AccountType = 'unknown';
    if (platform === 'github') {
      accountType = await fetchGitHubAccountType(owner);
    }

    return { repoUrl: rawUrl, owner, repoName, platform, accountType };
  } catch {
    // Not a git repo, no remote, or git not installed — silently ignore
    return null;
  }
}
