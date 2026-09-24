import fs from 'fs';
import path from 'path';
import { Finding } from '../types';

/**
 * Parses an existing .env file into a map of key → value.
 */
function parseEnvFile(filePath: string): Map<string, string> {
  const map = new Map<string, string>();
  if (!fs.existsSync(filePath)) return map;

  const lines = fs.readFileSync(filePath, 'utf-8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim().replace(/^['"`]|['"`]$/g, '');
    map.set(key, value);
  }
  return map;
}

/**
 * Appends or creates a .env file with the given findings.
 * Keys that already exist in the file are skipped (deduplication was done earlier).
 *
 * @returns number of entries written
 */
export function writeEnvFile(envFilePath: string, findings: Finding[]): number {
  const absPath = path.resolve(envFilePath);

  // Ensure parent dir exists
  const dir = path.dirname(absPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const existing = parseEnvFile(absPath);
  const lines: string[] = [];
  let written = 0;

  // Group findings by source file for a readable header
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file)!.push(f);
  }

  const header = `\n# ─── Added by code-secret-handler on ${new Date().toISOString()} ───\n`;
  lines.push(header);

  for (const [file, fileFindings] of byFile) {
    lines.push(`# Source: ${file}`);
    for (const finding of fileFindings) {
      if (existing.has(finding.envKey)) {
        // Should not happen due to dedup, but be safe
        finding.alreadyInEnv = true;
        continue;
      }
      // Escape value: wrap in double quotes, escape embedded double quotes
      const safeValue = finding.rawValue.replace(/"/g, '\\"');
      lines.push(`${finding.envKey}="${safeValue}"`);
      existing.set(finding.envKey, finding.rawValue);
      written++;
    }
    lines.push('');
  }

  if (written > 0) {
    fs.appendFileSync(absPath, lines.join('\n'), 'utf-8');
  }

  return written;
}
