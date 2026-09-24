import { RewriteContext, RewriteResult } from '../../types';

/**
 * Generic fallback rewriter:
 *  - Replaces the literal secret with `${KEY}` wherever it appears as a quoted string.
 */
export function rewriteGeneric(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;

  const quoteStyles = ["'", '"', '`'];
  for (const q of quoteStyles) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${q}${escaped}${q}`, 'g');
    if (re.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(re, `"\${${envKey}}"`);
      replacements++;
      break;
    }
  }

  // Fallback: unquoted occurrence
  if (replacements === 0) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(escaped, 'g');
    if (re.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(re, `\${${envKey}}`);
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
