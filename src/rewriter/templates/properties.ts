import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites .properties / .ini / .conf / .env files:
 *  - If the file IS the .env file, we skip rewriting (it is the target).
 *  - Otherwise replaces the literal value with `${KEY}` interpolation syntax
 *    (supported by Spring Boot, dotenv-expand, etc.).
 */
export function rewriteProperties(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey, file } = finding;

  // Skip if this is the .env file itself
  if (file.endsWith('.env') || file.endsWith('.envrc')) {
    return {
      filePath: file,
      originalContent: fileContent,
      rewrittenContent: fileContent,
      replacements: 0,
      dotenvInjected: false,
    };
  }

  let rewrittenContent = fileContent;
  let replacements = 0;

  const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(escaped, 'g');
  if (re.test(rewrittenContent)) {
    rewrittenContent = rewrittenContent.replace(re, `\${${envKey}}`);
    replacements++;
  }

  return {
    filePath: file,
    originalContent: fileContent,
    rewrittenContent,
    replacements,
    dotenvInjected: false,
  };
}
