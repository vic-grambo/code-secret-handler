import fs from 'fs';
import path from 'path';
import { Finding, Rule } from '../types';
import { ALL_RULES } from './rules';

/**
 * Values that are commonly used as placeholder/example values — skip these.
 */
const PLACEHOLDER_PATTERNS = [
  /^your[_-]/i,
  /^xxx+$/i,
  /^<.+>$/,                  // <YOUR_KEY>
  /^\$\{.+\}$/,              // ${MY_VAR}
  /^\$[A-Z_]+$/,             // $MY_VAR
  /^process\.env\./,
  /^os\.environ/,
  /^ENV\[/,
  /^System\.getenv/,
  /^getenv\(/,
  /^placeholder$/i,
  /^changeme$/i,
  /^change_me$/i,
  /^replace_?me$/i,
  /^todo$/i,
  /^fixme$/i,
  /^insert[_-]?here$/i,
  /^example$/i,
  /^test$/i,
  /^dummy$/i,
  /^fake$/i,
  /^mock$/i,
  /^secret$/i,               // bare word "secret" — likely a placeholder
  /^password$/i,             // bare word "password"
  /^12345+$/,
  /^0{8,}$/,
  /^1{8,}$/,
  /^null$/i,
  /^undefined$/i,
  /^none$/i,
  /^empty$/i,
  /^n\/a$/i,
];

/**
 * Minimum lengths for secret values to avoid false positives.
 */
const MIN_SECRET_LENGTH = 4;

/**
 * Returns true if the value looks like a placeholder/template value.
 */
function isPlaceholder(value: string): boolean {
  if (value.length < MIN_SECRET_LENGTH) return true;
  return PLACEHOLDER_PATTERNS.some(p => p.test(value));
}

/**
 * Generates the env variable name for a finding using context from the line.
 * Falls back to the rule's envKeyPrefix.
 */
export function generateEnvKeyBase(rule: Rule, lineContent: string, filePath: string): string {
  // Try to infer a more specific name from the variable name on the line
  const assignmentMatch = lineContent.match(
    /(?:const|let|var|val|final|private|public|protected|static)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:[:=])/
  );

  if (assignmentMatch) {
    const varName = assignmentMatch[1]
      .replace(/([a-z])([A-Z])/g, '$1_$2') // camelCase → snake_case
      .toUpperCase();

    // Only use var name if it looks meaningful and is not too generic
    const genericNames = new Set(['VALUE', 'VAL', 'V', 'S', 'K', 'KEY', 'DATA', 'RESULT', 'RES', 'X', 'Y']);
    if (!genericNames.has(varName) && varName.length > 2) {
      return varName;
    }
  }

  // Fall back to the rule's prefix
  return rule.envKeyPrefix;
}

/**
 * Scans a single file for secrets using all rules.
 * Returns a list of raw findings (envKey not yet deduplicated).
 */
export function scanFile(filePath: string): Finding[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    // Binary or unreadable — skip
    return [];
  }

  // Skip files larger than 5 MB
  const stats = fs.statSync(filePath);
  if (stats.size > 5 * 1024 * 1024) return [];

  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const lineContent = lines[lineIdx];

    // Skip comment-only lines (best-effort)
    const trimmed = lineContent.trim();
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('/*') ||
      trimmed.startsWith('<!--')
    ) {
      continue;
    }

    for (const rule of ALL_RULES) {
      // Reset lastIndex for global regexes
      rule.pattern.lastIndex = 0;

      const match = rule.pattern.exec(lineContent);
      if (!match) continue;

      const rawValue = match[rule.valueGroup] ?? match[0];
      if (!rawValue || isPlaceholder(rawValue)) continue;

      const column = lineContent.indexOf(rawValue) + 1;
      const envKey = generateEnvKeyBase(rule, lineContent, filePath);

      findings.push({
        file: path.resolve(filePath),
        line: lineIdx + 1,
        column,
        rule,
        rawValue,
        lineContent,
        envKey,
      });

      // Only match first rule per line to avoid duplicates
      break;
    }
  }

  return findings;
}

/**
 * Deduplicates env keys across all findings.
 * If two findings would share the same key, appends _2, _3, etc.
 * Also accepts existing .env keys to avoid collisions with them.
 */
export function deduplicateEnvKeys(findings: Finding[], existingKeys: Set<string>): Finding[] {
  const usedKeys = new Set<string>(existingKeys);

  return findings.map(finding => {
    let candidate = finding.envKey;
    if (usedKeys.has(candidate)) {
      let suffix = 2;
      while (usedKeys.has(`${candidate}_${suffix}`)) suffix++;
      candidate = `${candidate}_${suffix}`;
    }
    usedKeys.add(candidate);
    return { ...finding, envKey: candidate };
  });
}
