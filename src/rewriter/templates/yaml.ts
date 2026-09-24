import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites YAML files:
 *  - Replaces literal secret with `${KEY}` (shell-style substitution)
 *  - Adds a comment suggesting the use of an env-var substitution tool.
 */
export function rewriteYaml(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;

  const quoteStyles = ["'", '"', ''];
  for (const q of quoteStyles) {
    const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${q}${escaped}${q}`, 'g');
    if (re.test(rewrittenContent)) {
      rewrittenContent = rewrittenContent.replace(re, `\${${envKey}}`);
      replacements++;
      break;
    }
  }

  if (replacements > 0 && !/# env-var substitution/i.test(rewrittenContent)) {
    rewrittenContent =
      `# Note: Use envsubst, docker-compose, or a similar tool to substitute \${...} env vars.\n` +
      rewrittenContent;
  }

  return {
    filePath: finding.file,
    originalContent: fileContent,
    rewrittenContent,
    replacements,
    dotenvInjected: false,
  };
}
