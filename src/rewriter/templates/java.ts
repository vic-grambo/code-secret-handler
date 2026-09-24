import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites Java/Kotlin/Scala files:
 *  - Replaces literal secret with `System.getenv("KEY")`
 */
export function rewriteJava(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;

  const quoteStyles = ['"', "'"];
  for (const q of quoteStyles) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${q}${escaped}${q}`, 'g');
    if (re.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(re, `System.getenv("${envKey}")`);
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
