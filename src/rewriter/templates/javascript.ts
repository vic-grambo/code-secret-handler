import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites JavaScript/TypeScript files:
 *  - Replaces the literal secret value with `process.env.KEY`
 *  - Injects `require('dotenv').config()` if not already present and the file
 *    is a CommonJS module (no import/export keywords), OR
 *    leaves an ESM hint comment if the file uses import/export.
 */
export function rewriteJavaScript(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;
  let dotenvInjected = false;

  // Build the replacement string — replace the quoted secret with process.env.KEY
  // We need to handle all quote styles: ', ", `
  const quoteStyles = ["'", '"', '`'];
  for (const q of quoteStyles) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${q}${escaped}${q}`, 'g');
    if (re.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(re, `process.env.${envKey}`);
      replacements++;
      break;
    }
  }

  if (replacements === 0) return { filePath: finding.file, originalContent: fileContent, rewrittenContent: fileContent, replacements: 0, dotenvInjected: false };

  // Detect module style
  const isESM = /^import\s+|^export\s+/m.test(fileContent);
  const hasDotenvRequire = /require\s*\(\s*['"`]dotenv['"`]\s*\)/i.test(rewrittenContent);
  const hasDotenvImport = /import\s+.*['"`]dotenv['"`]/i.test(rewrittenContent);

  if (!hasDotenvRequire && !hasDotenvImport) {
    if (isESM) {
      // For ESM, add a comment hint at the top (dotenv/config import)
      rewrittenContent = `// TODO: Add \`import 'dotenv/config';\` at the top of your entry point.\n` + rewrittenContent;
    } else {
      // CommonJS — inject require at top
      rewrittenContent = `require('dotenv').config();\n` + rewrittenContent;
    }
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
