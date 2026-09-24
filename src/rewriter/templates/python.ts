import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites Python files:
 *  - Replaces literal secret with `os.environ.get('KEY')`
 *  - Injects `import os` and optionally `from dotenv import load_dotenv; load_dotenv()`
 */
export function rewritePython(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;
  let dotenvInjected = false;

  const quoteStyles = ["'", '"', '"""', "'''"];
  for (const q of quoteStyles) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${q}${escaped}${q}`, 'g');
    if (re.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(re, `os.environ.get('${envKey}')`);
      replacements++;
      break;
    }
  }

  if (replacements === 0) return { filePath: finding.file, originalContent: fileContent, rewrittenContent: fileContent, replacements: 0, dotenvInjected: false };

  const hasOsImport = /^import os$/m.test(rewrittenContent) || /^import os\b/m.test(rewrittenContent);
  const hasDotenvImport = /from dotenv import/i.test(rewrittenContent) || /import dotenv/i.test(rewrittenContent);

  let preamble = '';

  if (!hasOsImport) {
    preamble += 'import os\n';
  }

  if (!hasDotenvImport) {
    preamble += 'from dotenv import load_dotenv\nload_dotenv()\n';
    dotenvInjected = true;
  }

  if (preamble) {
    rewrittenContent = preamble + rewrittenContent;
  }

  return {
    filePath: finding.file,
    originalContent: fileContent,
    rewrittenContent,
    replacements,
    dotenvInjected,
  };
}
