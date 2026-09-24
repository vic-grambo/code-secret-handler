import path from 'path';
import { Language } from '../types';

/**
 * Maps file extensions to language identifiers.
 */
const EXT_MAP: Record<string, Language> = {
  // JavaScript / TypeScript
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.vue': 'javascript',     // Vue SFCs use JS/TS — use JS accessor
  '.svelte': 'javascript',  // Svelte uses JS
  // Python
  '.py': 'python',
  '.pyw': 'python',
  // Java / Kotlin / Scala
  '.java': 'java',
  '.kt': 'java',
  '.kts': 'java',
  '.scala': 'java',
  '.groovy': 'java',
  // Go
  '.go': 'go',
  // Ruby
  '.rb': 'ruby',
  '.rake': 'ruby',
  '.gemspec': 'ruby',
  // PHP
  '.php': 'php',
  '.php3': 'php',
  '.php4': 'php',
  '.php5': 'php',
  '.phtml': 'php',
  // C# / .NET
  '.cs': 'csharp',
  '.vb': 'csharp',
  '.fs': 'csharp',
  '.fsx': 'csharp',
  // Rust
  '.rs': 'rust',
  // Shell
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.fish': 'shell',
  '.ps1': 'shell',
  '.psm1': 'shell',
  '.bat': 'shell',
  '.cmd': 'shell',
  // Config formats (YAML, TOML, properties)
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.toml': 'toml',
  '.ini': 'properties',
  '.properties': 'properties',
  '.conf': 'properties',
  '.env': 'properties',
};

/**
 * Exact filename mappings (no extension or special names).
 */
const FILENAME_MAP: Record<string, Language> = {
  Dockerfile: 'shell',
  Makefile: 'shell',
  '.env': 'properties',
  '.envrc': 'shell',
  '.bashrc': 'shell',
  '.zshrc': 'shell',
  '.profile': 'shell',
  Gemfile: 'ruby',
  Rakefile: 'ruby',
};

/**
 * Detects the programming language of a file by its path.
 * Falls back to 'generic' if unknown.
 */
export function detectLanguage(filePath: string): Language {
  const basename = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();

  // Check exact filename first
  if (FILENAME_MAP[basename]) return FILENAME_MAP[basename];

  // Check extension
  if (ext && EXT_MAP[ext]) return EXT_MAP[ext];

  return 'generic';
}
