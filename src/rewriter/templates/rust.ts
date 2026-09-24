import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites Rust files:
 *  - Replaces literal secret with `std::env::var("KEY").expect("KEY not set")`
 */
export function rewriteRust(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;

  const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`"${escaped}"`, 'g');
  if (re.test(rewrittenContent)) {
    rewrittenContent = rewrittenContent.replace(
      re,
      `std::env::var("${envKey}").expect("${envKey} not set")`
    );
    replacements++;
  }

  return {
    filePath: finding.file,
    originalContent: fileContent,
    rewrittenContent,
    replacements,
    dotenvInjected: false,
  };
}
