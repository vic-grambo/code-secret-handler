import path from 'path';
import { ReportFormat, ScanSummary } from '../types';
import { printConsoleReport } from './console';
import { writeJsonReport } from './json';
import { writeCsvReport } from './csv';
import { writeMarkdownReport } from './markdown';

const EXT_MAP: Record<Exclude<ReportFormat, 'console'>, string> = {
  json: 'json',
  csv: 'csv',
  markdown: 'md',
};

/**
 * Derives the default output file path for a given report format.
 */
export function defaultOutputPath(format: ReportFormat, targetDir: string): string {
  if (format === 'console') return '';
  const ext = EXT_MAP[format];
  return path.join(targetDir, `secret-scan-report.${ext}`);
}

/**
 * Runs the appropriate reporter(s) based on the chosen format.
 * Always prints a console summary; file reporters write to outputPath.
 *
 * @returns The output file path (empty string for console-only).
 */
export function runReporter(
  format: ReportFormat,
  summary: ScanSummary,
  outputPath?: string
): string {
  // Always print the console report
  printConsoleReport(summary);

  if (format === 'console') return '';

  const filePath = outputPath || defaultOutputPath(format, summary.targetDir);

  switch (format) {
    case 'json':
      writeJsonReport(summary, filePath);
      break;
    case 'csv':
      writeCsvReport(summary, filePath);
      break;
    case 'markdown':
      writeMarkdownReport(summary, filePath);
      break;
  }

  return filePath;
}
