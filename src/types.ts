// ─── Severity levels ─────────────────────────────────────────────────────────
export type Severity = 'critical' | 'high' | 'medium' | 'low';

// ─── Report output formats ────────────────────────────────────────────────────
export type ReportFormat = 'console' | 'json' | 'csv' | 'markdown';

// ─── A single secret-detection rule ──────────────────────────────────────────
export interface Rule {
  /** Unique rule identifier, e.g. "aws-access-key" */
  id: string;
  /** Human-readable description */
  description: string;
  /**
   * Regex that matches the whole assignment / value line.
   * Must have at least one capture group for the secret value.
   */
  pattern: RegExp;
  /** Index of the capture group that contains the raw secret value (1-based) */
  valueGroup: number;
  /** Prefix used when auto-generating the env var name, e.g. "AWS_ACCESS_KEY" */
  envKeyPrefix: string;
  /** Severity classification */
  severity: Severity;
}

// ─── A detected secret occurrence ────────────────────────────────────────────
export interface Finding {
  /** Absolute path to the source file */
  file: string;
  /** 1-based line number */
  line: number;
  /** 1-based column where the secret value starts */
  column: number;
  /** The rule that triggered this finding */
  rule: Rule;
  /** The raw secret value extracted from source */
  rawValue: string;
  /** The full matched line (for context) */
  lineContent: string;
  /** Generated env var name (set after deduplication) */
  envKey: string;
  /** Whether this finding was already present in the .env file */
  alreadyInEnv?: boolean;
}

// ─── CLI options ──────────────────────────────────────────────────────────────
export interface CliOptions {
  /** Directory to scan (default: cwd) */
  targetDir: string;
  /** Report output format */
  report: ReportFormat;
  /** Report output file path (auto-derived if omitted) */
  output?: string;
  /** Path to .env file (default: <targetDir>/.env) */
  envFile: string;
  /** Scan only — do not write any files */
  dryRun: boolean;
  /** Write .env but skip source-file rewriting */
  noRewrite: boolean;
}

// ─── Language identifiers ─────────────────────────────────────────────────────
export type Language =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'java'
  | 'go'
  | 'ruby'
  | 'php'
  | 'csharp'
  | 'rust'
  | 'shell'
  | 'yaml'
  | 'toml'
  | 'properties'
  | 'generic';

// ─── Context passed to a language rewriter ───────────────────────────────────
export interface RewriteContext {
  finding: Finding;
  language: Language;
  fileContent: string;
}

// ─── Result of a rewrite operation ───────────────────────────────────────────
export interface RewriteResult {
  filePath: string;
  originalContent: string;
  rewrittenContent: string;
  /** Number of replacements made */
  replacements: number;
  /** Whether a dotenv import/require was injected */
  dotenvInjected: boolean;
}

// ─── Summary of a full scan run ──────────────────────────────────────────────
export interface ScanSummary {
  targetDir: string;
  filesScanned: number;
  filesWithSecrets: number;
  totalFindings: number;
  findings: Finding[];
  envFile: string;
  reportFile?: string;
  dryRun: boolean;
  scannedAt: string; // ISO 8601
}
