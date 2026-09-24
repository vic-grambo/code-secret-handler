import { input, confirm, select } from '@inquirer/prompts';
import chalk from 'chalk';
import path from 'path';
import { Finding, ScanSummary } from '../types';

/**
 * Shows a summary of planned changes and asks the user to confirm before proceeding.
 * Returns true if the user approves, false if they decline.
 */
export async function confirmChanges(summary: ScanSummary, noRewrite: boolean): Promise<boolean> {
  if (summary.totalFindings === 0) return false;

  console.log('\n' + chalk.bold.yellow('📋  Planned Changes:'));
  console.log(chalk.gray('─'.repeat(60)));

  // Group by file
  const byFile = new Map<string, Finding[]>();
  for (const f of summary.findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file)!.push(f);
  }

  // Print .env changes
  console.log(chalk.bold(`\n  1. Write to ${chalk.underline(summary.envFile)}:`));
  for (const f of summary.findings) {
    console.log(chalk.green(`     + ${f.envKey}="***"`));
  }

  if (!noRewrite) {
    console.log(chalk.bold(`\n  2. Rewrite ${byFile.size} source file(s):`));
    for (const [filePath, fileFindings] of byFile) {
      const relPath = path.relative(summary.targetDir, filePath);
      console.log(chalk.cyan(`     📄 ${relPath}  (${fileFindings.length} change(s))`));
    }
  }

  console.log(chalk.gray('\n─'.repeat(60)));

  const answer = await confirm({
    message: `Apply ${summary.totalFindings} change(s) to .env${noRewrite ? '' : ' and source files'}?`,
    default: true,
  });

  return answer;
}

/**
 * Asks the user to confirm backup before proceeding.
 * Returns 'backup', 'skip', or 'abort'.
 */
export async function askBackupPreference(): Promise<'backup' | 'skip' | 'abort'> {
  const choice = await select({
    message: 'Source files will be modified. How would you like to handle backups?',
    choices: [
      { name: 'Create .bak backup of each modified file', value: 'backup' },
      { name: 'Skip backup (rely on Git)', value: 'skip' },
      { name: 'Abort — do not make any changes', value: 'abort' },
    ],
  });
  return choice as 'backup' | 'skip' | 'abort';
}

/**
 * Prompts for a custom .env file path override.
 */
export async function askEnvFilePath(defaultPath: string): Promise<string> {
  const answer = await input({
    message: 'Path for the .env file:',
    default: defaultPath,
  });
  return answer;
}
