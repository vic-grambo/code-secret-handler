import fs from 'fs';
import path from 'path';
import { ScanSummary, Finding, Severity } from '../types';

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: '![critical](https://img.shields.io/badge/severity-CRITICAL-red)',
  high: '![high](https://img.shields.io/badge/severity-HIGH-orange)',
  medium: '![medium](https://img.shields.io/badge/severity-MEDIUM-yellow)',
  low: '![low](https://img.shields.io/badge/severity-LOW-blue)',
};

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🚨',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
};

function maskValue(value: string): string {
  if (value.length <= 8) return '`' + '*'.repeat(value.length) + '`';
  const masked = value.slice(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.slice(-4);
  return '`' + masked + '`';
}

function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!map.has(f.file)) map.set(f.file, []);
    map.get(f.file)!.push(f);
  }
  return map;
}

/**
 * Writes a Markdown report suitable for GitHub/GitLab issue or PR comments.
 */
export function writeMarkdownReport(summary: ScanSummary, outputPath: string): void {
  const { findings, filesScanned, filesWithSecrets, totalFindings, dryRun, envFile, scannedAt, targetDir } = summary;

  const lines: string[] = [];

  lines.push('# 🔐 Code Secret Handler — Scan Report\n');
  lines.push(`> Generated: \`${scannedAt}\`\n`);
  lines.push(`- **Target directory:** \`${targetDir}\`  `);
  lines.push(`- **Files scanned:** ${filesScanned}  `);
  lines.push(`- **Files with secrets:** ${filesWithSecrets}  `);
  lines.push(`- **Total secrets found:** **${totalFindings}**  `);
  lines.push(`- **Env file:** \`${envFile}\`  `);
  if (dryRun) lines.push(`- ⚠️ **DRY RUN** — no files were modified`);
  lines.push('');

  if (totalFindings === 0) {
    lines.push('## ✅ No hardcoded secrets detected!\n');
    lines.push('Great job keeping your codebase clean.\n');
  } else {
    // Severity summary table
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) bySeverity[f.rule.severity]++;

    lines.push('## Summary\n');
    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    for (const [sev, count] of Object.entries(bySeverity)) {
      if (count === 0) continue;
      lines.push(`| ${SEVERITY_EMOJI[sev as Severity]} ${sev.toUpperCase()} | ${count} |`);
    }
    lines.push('');

    // Findings by file
    lines.push('## Findings\n');
    const byFile = groupByFile(findings);

    for (const [filePath, fileFindings] of byFile) {
      const relPath = path.relative(targetDir, filePath);
      lines.push(`### 📄 \`${relPath}\`\n`);
      lines.push('| Line | Col | Severity | Rule | Description | Env Key | Masked Value |');
      lines.push('|------|-----|----------|------|-------------|---------|--------------|');

      for (const f of fileFindings) {
        lines.push(
          `| ${f.line} | ${f.column} | ${SEVERITY_EMOJI[f.rule.severity]} ${f.rule.severity.toUpperCase()} | \`${f.rule.id}\` | ${f.rule.description} | \`${f.envKey}\` | ${maskValue(f.rawValue)} |`
        );
      }
      lines.push('');

      // Code snippet for each finding
      for (const f of fileFindings) {
        lines.push('<details>');
        lines.push(`<summary>Line ${f.line} — <code>${f.rule.id}</code></summary>\n`);
        lines.push('```');
        lines.push(f.lineContent);
        lines.push('```\n');
        lines.push('</details>\n');
      }
    }

    // Recommendations
    lines.push('## 🛡️ Recommendations\n');
    lines.push('1. Verify the changes made to your source files.');
    lines.push('2. Ensure `.env` is listed in `.gitignore`.');
    lines.push('3. Rotate any secrets that may have been exposed in git history.');
    lines.push('4. Consider using a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).');
    lines.push('5. Set up a pre-commit hook to prevent future secret leaks.');
    lines.push('');
  }

  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  fs.writeFileSync(outputPath, lines.join('\n'), 'utf-8');
}
