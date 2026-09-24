import chalk from 'chalk';
import path from 'path';
import { ScanSummary, Finding, Severity } from '../types';

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(s),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow.bold(s),
  low: (s) => chalk.blue(s),
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '🚨',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
};

function maskValue(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return value.slice(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.slice(-4);
}

function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!map.has(f.file)) map.set(f.file, []);
    map.get(f.file)!.push(f);
  }
  return map;
}

export function printConsoleReport(summary: ScanSummary): void {
  const { findings, filesScanned, filesWithSecrets, totalFindings, dryRun, envFile, scannedAt } = summary;

  console.log('\n' + chalk.bold.cyan('═'.repeat(70)));
  console.log(chalk.bold.cyan('  🔐  CODE SECRET HANDLER — Scan Report'));
  console.log(chalk.bold.cyan('═'.repeat(70)));
  console.log(chalk.gray(`  Scanned at : ${scannedAt}`));
  console.log(chalk.gray(`  Target dir : ${summary.targetDir}`));
  console.log(chalk.gray(`  Env file   : ${envFile}`));
  if (dryRun) console.log(chalk.yellow('  ⚠️  DRY RUN MODE — No files were modified'));
  console.log('');

  if (totalFindings === 0) {
    console.log(chalk.green.bold('  ✅  No hardcoded secrets detected. Great job!\n'));
    return;
  }

  // Summary line
  console.log(
    chalk.bold(`  Found ${chalk.red(String(totalFindings))} secret(s) across `) +
    chalk.bold(`${chalk.red(String(filesWithSecrets))} file(s) `) +
    chalk.gray(`(${filesScanned} files scanned)`)
  );
  console.log('');

  // Severity breakdown
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) bySeverity[f.rule.severity]++;
  console.log('  Severity breakdown:');
  for (const [sev, count] of Object.entries(bySeverity)) {
    if (count === 0) continue;
    const colored = SEVERITY_COLORS[sev as Severity];
    console.log(`    ${SEVERITY_ICONS[sev as Severity]}  ${colored(sev.padEnd(8))}  ${count}`);
  }
  console.log('');

  // Per-file findings
  const byFile = groupByFile(findings);
  for (const [filePath, fileFindings] of byFile) {
    const relPath = path.relative(summary.targetDir, filePath);
    console.log(chalk.underline.bold(`  📄 ${relPath}`));

    for (const f of fileFindings) {
      const sevColor = SEVERITY_COLORS[f.rule.severity];
      const icon = SEVERITY_ICONS[f.rule.severity];
      console.log(
        `    ${icon} ${sevColor(`[${f.rule.severity.toUpperCase()}]`)} ` +
        chalk.cyan(`Line ${f.line}:${f.column}`) +
        `  ${chalk.gray(f.rule.description)}`
      );
      console.log(
        `       Rule ID : ${chalk.gray(f.rule.id)}`
      );
      console.log(
        `       Value   : ${chalk.red(maskValue(f.rawValue))}`
      );
      console.log(
        `       Env Key : ${chalk.green(f.envKey)}`
      );
      if (!dryRun) {
        console.log(
          `       Context : ${chalk.dim(f.lineContent.trim().slice(0, 80))}`
        );
      }
      console.log('');
    }
  }

  console.log(chalk.bold.cyan('═'.repeat(70)));

  if (!dryRun) {
    console.log(chalk.green.bold(`\n  ✅  ${totalFindings} secret(s) moved to ${chalk.underline(envFile)}`));
    console.log(chalk.yellow(`  ⚠️  Verify source file changes, then add .env to .gitignore!\n`));
  } else {
    console.log(chalk.yellow(`\n  ℹ️  Dry run complete. Run without --dry-run to apply changes.\n`));
  }
}
