import fs from 'fs';
import path from 'path';
import { ScanSummary } from '../types';

/**
 * Writes a JSON report of the scan summary to disk.
 * The raw secret values are masked in the report.
 */
export function writeJsonReport(summary: ScanSummary, outputPath: string): void {
  const sanitized = {
    ...summary,
    findings: summary.findings.map(f => ({
      file: f.file,
      line: f.line,
      column: f.column,
      envKey: f.envKey,
      ruleId: f.rule.id,
      description: f.rule.description,
      severity: f.rule.severity,
      // Mask the value in the report
      maskedValue: maskValue(f.rawValue),
      lineContent: f.lineContent.trim(),
    })),
  };

  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  fs.writeFileSync(outputPath, JSON.stringify(sanitized, null, 2), 'utf-8');
}

function maskValue(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return value.slice(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.slice(-4);
}
