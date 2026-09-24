import ora from 'ora';
import path from 'path';
import fs from 'fs';
import { Finding, ScanSummary } from '../types';
import { walkFiles } from './fileWalker';
import { scanFile, deduplicateEnvKeys } from './detector';

/**
 * Reads existing keys from a .env file to seed the deduplication set.
 */
function readExistingEnvKeys(envFilePath: string): Set<string> {
  const keys = new Set<string>();
  if (!fs.existsSync(envFilePath)) return keys;

  const content = fs.readFileSync(envFilePath, 'utf-8');
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) keys.add(trimmed.slice(0, eqIdx).trim());
  }
  return keys;
}

/**
 * Main scanner orchestrator.
 * Walks the target directory, scans every file, deduplicates env keys,
 * and returns a full ScanSummary.
 */
export async function runScanner(targetDir: string, envFilePath: string): Promise<ScanSummary> {
  const spinner = ora({
    text: `Discovering files in ${path.resolve(targetDir)} …`,
    color: 'cyan',
  }).start();

  let files: string[];
  try {
    files = await walkFiles(targetDir);
  } catch (err) {
    spinner.fail('Failed to walk directory');
    throw err;
  }

  spinner.text = `Scanning ${files.length} files for secrets …`;

  const allFindings: Finding[] = [];
  const filesWithSecrets = new Set<string>();

  for (const filePath of files) {
    const fileFindings = scanFile(filePath);
    if (fileFindings.length > 0) {
      allFindings.push(...fileFindings);
      filesWithSecrets.add(filePath);
    }
    spinner.text = `Scanned ${files.indexOf(filePath) + 1}/${files.length} files — ${allFindings.length} secret(s) found so far …`;
  }

  spinner.succeed(
    `Scan complete: ${files.length} files scanned, ${allFindings.length} secret(s) found in ${filesWithSecrets.size} file(s).`
  );

  // Deduplicate env keys, considering what's already in .env
  const existingKeys = readExistingEnvKeys(envFilePath);
  const deduplicated = deduplicateEnvKeys(allFindings, existingKeys);

  return {
    targetDir: path.resolve(targetDir),
    filesScanned: files.length,
    filesWithSecrets: filesWithSecrets.size,
    totalFindings: deduplicated.length,
    findings: deduplicated,
    envFile: path.resolve(envFilePath),
    dryRun: false, // set by caller
    scannedAt: new Date().toISOString(),
  };
}
