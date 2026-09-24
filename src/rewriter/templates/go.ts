import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites Go files:
 *  - Replaces literal secret with `os.Getenv("KEY")`
 *  - Injects `"os"` import if not already present
 */
export function rewriteGo(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;
  let dotenvInjected = false;

  const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`"${escaped}"`, 'g');
  if (re.test(rewrittenContent)) {
    rewrittenContent = rewrittenContent.replace(re, `os.Getenv("${envKey}")`);
    replacements++;
  }

  if (replacements === 0) {
    // Try backtick strings (raw string literals in Go)
    const reBacktick = new RegExp('`' + escaped + '`', 'g');
    if (reBacktick.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(reBacktick, `os.Getenv("${envKey}")`);
      replacements++;
    }
  }

  if (replacements === 0) return { filePath: finding.file, originalContent: fileContent, rewrittenContent: fileContent, replacements: 0, dotenvInjected: false };

  // Inject "os" import if not present
  const hasOsImport = /import\s+(?:"os"|[\s\S]*?"os"[\s\S]*?\))/.test(rewrittenContent);
  if (!hasOsImport) {
    // Add to existing import block if present
    if (/^import\s*\(/.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(/^(import\s*\()/, '$1\n\t"os"');
    } else if (/^import\s+"/.test(rewrittenContent)) {
      // Single import — convert to block
      rewrittenContent = rewrittenContent.replace(
        /^(import\s+"[^"]+")$/m,
        '$1\nimport "os"'
      );
    } else {
      // No import block yet — find package statement and insert after
      rewrittenContent = rewrittenContent.replace(
        /^(package\s+\w+\s*\n)/m,
        '$1\nimport "os"\n'
      );
    }
    dotenvInjected = true; // "os" counts as env-access injection
  }

  return {
    filePath: finding.file,
    originalContent: fileContent,
    rewrittenContent,
    replacements,
    dotenvInjected,
  };
}
