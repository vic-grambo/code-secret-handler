import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites Ruby files:
 *  - Replaces literal secret with `ENV['KEY']`
 *  - Injects `require 'dotenv/load'` if not present (when dotenv gem is used)
 */
export function rewriteRuby(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;
  let dotenvInjected = false;

  const quoteStyles = ["'", '"'];
  for (const q of quoteStyles) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${q}${escaped}${q}`, 'g');
    if (re.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(re, `ENV['${envKey}']`);
      replacements++;
      break;
    }
  }

  if (replacements === 0) return { filePath: finding.file, originalContent: fileContent, rewrittenContent: fileContent, replacements: 0, dotenvInjected: false };

  const hasDotenv = /require\s+['"]dotenv/.test(rewrittenContent);
  if (!hasDotenv) {
    rewrittenContent = `require 'dotenv/load'\n` + rewrittenContent;
    dotenvInjected = true;
  }

  return {
    filePath: finding.file,
    originalContent: fileContent,
    rewrittenContent,
    replacements,
    dotenvInjected,
  };
}
