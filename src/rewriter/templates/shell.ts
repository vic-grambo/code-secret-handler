import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites Shell / Bash / PowerShell files:
 *  - Replaces literal secret with `$KEY` (bash) or `$env:KEY` (PowerShell .ps1)
 */
export function rewriteShell(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  const isPowerShell = finding.file.endsWith('.ps1') || finding.file.endsWith('.psm1');
  const replacement = isPowerShell ? `$env:${envKey}` : `$${envKey}`;

  let rewrittenContent = fileContent;
  let replacements = 0;

  const quoteStyles = ["'", '"'];
  for (const q of quoteStyles) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${q}${escaped}${q}`, 'g');
    if (re.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(re, replacement);
      replacements++;
      break;
    }
  }

  // Also try unquoted (direct assignment VALUE)
  if (replacements === 0) {
    const escapedRaw = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const reRaw = new RegExp(`(?<==)${escapedRaw}(?=\\s|$)`, 'gm');
    if (reRaw.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(reRaw, replacement);
      replacements++;
    }
  }

  return {
    filePath: finding.file,
    originalContent: fileContent,
    rewrittenContent,
    replacements,
    dotenvInjected: false,
  };
}
