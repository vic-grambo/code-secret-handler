#!/usr/bin/env node

import { Command } from 'commander';
import path from 'path';
import fs from 'fs';
import chalk from 'chalk';
import { CliOptions, ReportFormat } from './types';
import { runScanner } from './scanner';
import { writeEnvFile } from './env/envWriter';
import { rewriteFiles } from './rewriter';
import { runReporter, defaultOutputPath } from './reporter';
import { confirmChanges, askBackupPreference } from './interactive/confirm';
import { getGitContext } from './license/gitContext';
import { checkLicense } from './license/licenseCheck';
import { sendTelemetry } from './license/telemetry';

const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8')
);

const program = new Command();

program
  .name('code-secret-handler')
  .alias('csh')
  .description(
    chalk.cyan('🔐 Scans your codebase for hardcoded secrets, moves them to .env, and rewrites source files.')
  )
  .version(pkg.version, '-v, --version', 'Output the current version')
  .argument('[target-dir]', 'Directory to scan (default: current directory)', '.')
  .option('-r, --report <format>', 'Report format: console | json | csv | markdown', 'console')
  .option('-o, --output <file>', 'Report output file path (auto-derived if omitted)')
  .option('-e, --env-file <path>', 'Target .env file path', '.env')
  .option('--dry-run', 'Scan and report only — do not write any files', false)
  .option('--no-rewrite', 'Write .env but skip source-file rewriting')
  .addHelpText('after', `
${chalk.bold('Examples:')}
  ${chalk.cyan('$ csh .')}                                  Scan current directory
  ${chalk.cyan('$ csh ./my-app --dry-run')}                Scan without modifying files
  ${chalk.cyan('$ csh ./my-app -r markdown -o report.md')} Scan and write Markdown report
  ${chalk.cyan('$ csh ./my-app -e secrets/.env')}          Use a custom .env path
  ${chalk.cyan('$ csh ./my-app --no-rewrite')}             Write .env only, skip source rewrites
  `);

program.action(async (targetDirArg: string, opts: Record<string, unknown>) => {
  console.log(chalk.bold.cyan('\n🔐  Code Secret Handler\n'));

  const targetDir = path.resolve(targetDirArg || '.');

  // ── License & telemetry (runs before anything else) ──────────────────────
  const gitCtx = await getGitContext(targetDir);
  const { licenseKeyProvided } = await checkLicense(gitCtx);
  sendTelemetry(gitCtx, licenseKeyProvided);
  // ─────────────────────────────────────────────────────────────────────────

  const report = ((opts['report'] as string) || 'console').toLowerCase() as ReportFormat;
  const envFile = path.resolve(targetDir, (opts['envFile'] as string) || '.env');
  const dryRun = Boolean(opts['dryRun']);
  const noRewrite = !Boolean(opts['rewrite']);
  const outputArg = opts['output'] as string | undefined;
  const outputPath = outputArg
    ? path.resolve(outputArg)
    : report !== 'console'
    ? defaultOutputPath(report, targetDir)
    : undefined;

  const _options: CliOptions = { targetDir, report, output: outputPath, envFile, dryRun, noRewrite };

  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    console.error(chalk.red(`❌  Target directory not found: ${targetDir}`));
    process.exit(1);
  }

  const validFormats: ReportFormat[] = ['console', 'json', 'csv', 'markdown'];
  if (!validFormats.includes(report)) {
    console.error(chalk.red(`❌  Invalid report format: "${report}". Choose from: ${validFormats.join(', ')}`));
    process.exit(1);
  }

  let summary = await runScanner(targetDir, envFile);
  summary.dryRun = dryRun;
  if (outputPath) summary.reportFile = outputPath;

  const reportFile = runReporter(report, summary, outputPath);
  if (reportFile) {
    console.log(chalk.green(`\n  📄 Report written to: ${chalk.underline(reportFile)}\n`));
  }

  if (summary.totalFindings === 0) process.exit(0);

  if (dryRun) {
    console.log(chalk.yellow('  ℹ️  Dry run mode — no changes applied.\n'));
    process.exit(0);
  }

  const approved = await confirmChanges(summary, noRewrite);
  if (!approved) {
    console.log(chalk.yellow('\n  ❌  Aborted — no changes made.\n'));
    process.exit(0);
  }

  let backupChoice: 'backup' | 'skip' | 'abort' = 'skip';
  if (!noRewrite && summary.totalFindings > 0) {
    backupChoice = await askBackupPreference();
    if (backupChoice === 'abort') {
      console.log(chalk.yellow('\n  ❌  Aborted — no changes made.\n'));
      process.exit(0);
    }
  }

  const written = writeEnvFile(envFile, summary.findings);
  console.log(chalk.green(`\n  ✅  ${written} secret(s) written to ${chalk.underline(envFile)}`));

  if (!noRewrite) {
    const results = rewriteFiles(summary.findings, false);
    let totalRewrites = 0;
    for (const result of results) {
      if (result.replacements === 0) continue;
      if (backupChoice === 'backup') {
        fs.writeFileSync(`${result.filePath}.bak`, result.originalContent, 'utf-8');
      }
      totalRewrites += result.replacements;
      const relPath = path.relative(targetDir, result.filePath);
      console.log(
        chalk.cyan(`  ✏️  ${relPath}`) +
        chalk.gray(` — ${result.replacements} replacement(s)`) +
        (result.dotenvInjected ? chalk.yellow(' + dotenv injected') : '')
      );
    }
    console.log(chalk.green(`\n  ✅  ${totalRewrites} replacement(s) across ${results.filter(r => r.replacements > 0).length} file(s)`));
  }

  console.log(chalk.bold.yellow('\n  ⚠️  IMPORTANT:'));
  console.log(chalk.yellow('     1. Add .env to your .gitignore if not already done.'));
  console.log(chalk.yellow('     2. Rotate any secrets that may have been committed to Git history.'));
  console.log(chalk.yellow('     3. Review all modified source files before committing.\n'));

  process.exit(0);
});

program.parse(process.argv);
