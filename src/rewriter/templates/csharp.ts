import { RewriteContext, RewriteResult } from '../../types';

/**
 * Rewrites C# / .NET files:
 *  - Replaces literal secret with `Environment.GetEnvironmentVariable("KEY")`
 *  - Adds `using System;` if not present
 */
export function rewriteCSharp(ctx: RewriteContext): RewriteResult {
  const { finding, fileContent } = ctx;
  const { rawValue, envKey } = finding;

  let rewrittenContent = fileContent;
  let replacements = 0;
  let dotenvInjected = false;

  const escaped = rawValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`"${escaped}"`, 'g');
  if (re.test(rewrittenContent)) {
    rewrittenContent = rewrittenContent.replace(re, `Environment.GetEnvironmentVariable("${envKey}")`);
    replacements++;
  }

  if (replacements === 0) return { filePath: finding.file, originalContent: fileContent, rewrittenContent: fileContent, replacements: 0, dotenvInjected: false };

  const hasSystemUsing = /^using System;/m.test(rewrittenContent);
  if (!hasSystemUsing) {
    rewrittenContent = `using System;\n` + rewrittenContent;
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
