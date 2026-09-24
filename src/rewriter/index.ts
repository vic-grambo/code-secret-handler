import fs from 'fs';
import { Finding, Language, RewriteContext, RewriteResult } from '../types';
import { detectLanguage } from './langDetector';
import { rewriteJavaScript } from './templates/javascript';
import { rewritePython } from './templates/python';
import { rewriteJava } from './templates/java';
import { rewriteGo } from './templates/go';
import { rewriteRuby } from './templates/ruby';
import { rewritePhp } from './templates/php';
import { rewriteCSharp } from './templates/csharp';
import { rewriteRust } from './templates/rust';
import { rewriteShell } from './templates/shell';
import { rewriteYaml } from './templates/yaml';
import { rewriteProperties } from './templates/properties';
import { rewriteToml } from './templates/toml';
import { rewriteGeneric } from './templates/generic';

type RewriterFn = (ctx: RewriteContext) => RewriteResult;

const REWRITERS: Record<Language, RewriterFn> = {
  javascript: rewriteJavaScript,
  typescript: rewriteJavaScript,  // TS uses same accessor as JS
  python: rewritePython,
  java: rewriteJava,
  go: rewriteGo,
  ruby: rewriteRuby,
  php: rewritePhp,
  csharp: rewriteCSharp,
  rust: rewriteRust,
  shell: rewriteShell,
  yaml: rewriteYaml,
  toml: rewriteToml,
  properties: rewriteProperties,
  generic: rewriteGeneric,
};

/**
 * Groups findings by file, applies the correct language rewriter to each file,
 * and writes the updated content back to disk.
 *
 * @returns Array of RewriteResult, one per modified file.
 */
export function rewriteFiles(findings: Finding[], dryRun = false): RewriteResult[] {
  // Group findings by file
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (!byFile.has(finding.file)) byFile.set(finding.file, []);
    byFile.get(finding.file)!.push(finding);
  }

  const results: RewriteResult[] = [];

  for (const [filePath, fileFindings] of byFile) {
    let fileContent: string;
    try {
      fileContent = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const language = detectLanguage(filePath);
    const rewriterFn = REWRITERS[language];

    // Apply each finding's rewrite sequentially on the evolving content
    let currentContent = fileContent;
    let totalReplacements = 0;
    let dotenvInjected = false;

    for (const finding of fileFindings) {
      const ctx: RewriteContext = {
        finding,
        language,
        fileContent: currentContent,
      };

      const result = rewriterFn(ctx);
      if (result.replacements > 0) {
        currentContent = result.rewrittenContent;
        totalReplacements += result.replacements;
        if (result.dotenvInjected) dotenvInjected = true;
      }
    }

    const finalResult: RewriteResult = {
      filePath,
      originalContent: fileContent,
      rewrittenContent: currentContent,
      replacements: totalReplacements,
      dotenvInjected,
    };

    results.push(finalResult);

    if (!dryRun && totalReplacements > 0) {
      fs.writeFileSync(filePath, currentContent, 'utf-8');
    }
  }

  return results;
}
