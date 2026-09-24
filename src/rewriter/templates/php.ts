import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites PHP files:
 *  - Replaces literal secret with `getenv('KEY')`
 *  - Optionally adds a comment about vlucas/phpdotenv
 */
export function rewritePhp(ctx: RewriteContext): RewriteResult {
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
      rewrittenContent = rewrittenContent.replace(re, `getenv('${envKey}')`);
      replacements++;
      break;
    }
  }

  if (replacements === 0) return { filePath: finding.file, originalContent: fileContent, rewrittenContent: fileContent, replacements: 0, dotenvInjected: false };

  const hasDotenv = /Dotenv\\Dotenv|vlucas\/phpdotenv|Dotenv::createImmutable/i.test(rewrittenContent);
  if (!hasDotenv) {
    // Insert after opening <?php tag
    rewrittenContent = rewrittenContent.replace(
      /^<\?php\s*/,
      `<?php\n// TODO: Load .env via vlucas/phpdotenv: $dotenv = Dotenv\\Dotenv::createImmutable(__DIR__); $dotenv->load();\n`
    );
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
