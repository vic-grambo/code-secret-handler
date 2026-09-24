import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites TOML files:
 *  - Replaces literal secret with a reference comment and env var placeholder.
 *  - TOML does not support env var interpolation natively, so we replace
 *    the value with "${KEY}" and add a guidance comment.
 */
export function rewriteToml(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;

  const quoteStyles = ['"', "'"];
  for (const q of quoteStyles) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${q}${escaped}${q}`, 'g');
    if (re.test(rewrittenContent)) {
      // Replace with env var reference as a string — note: not all TOML loaders support this
      rewrittenContent = rewrittenContent.replace(re, `"$\{${envKey}}"  # Set ${envKey} in environment`);
      replacements++;
      break;
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
