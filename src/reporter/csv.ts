import fs from 'fs';
import path from 'path';
import { ScanSummary } from '../types';

function escapeCsv(value: string): string {
  // If value contains comma, newline, or double quote, wrap in quotes
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function maskValue(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return value.slice(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.slice(-4);
}

/**
 * Writes a CSV report of the scan findings.
 */
export function writeCsvReport(summary: ScanSummary, outputPath: string): void {
  const headers = [
    'File',
    'Line',
    'Column',
    'Severity',
    'Rule ID',
    'Description',
    'Env Key',
    'Masked Value',
    'Line Content',
  ];

  const rows = summary.findings.map(f => [
    f.file,
    String(f.line),
    String(f.column),
    f.rule.severity,
    f.rule.id,
    f.rule.description,
    f.envKey,
    maskValue(f.rawValue),
    f.lineContent.trim(),
  ]);

  const csvLines = [
    headers.map(escapeCsv).join(','),
    ...rows.map(row => row.map(escapeCsv).join(',')),
  ];

  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  fs.writeFileSync(outputPath, csvLines.join('\n'), 'utf-8');
}
