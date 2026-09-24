import fs from 'fs';
import path from 'path';
import ignore, { Ignore } from 'ignore';
import fg from 'fast-glob';

/**
 * File extensions we will attempt to scan for secrets.
 * Binary and compiled files are excluded.
 */
const SCANNABLE_EXTENSIONS = new Set([
  // Web / JS ecosystem
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte',
  // Config / env
  '.env', '.env.local', '.env.development', '.env.staging', '.env.production',
  '.json', '.jsonc', '.json5',
  '.yaml', '.yml',
  '.toml',
  '.ini',
  '.properties',
  '.conf', '.config',
  '.xml',
  // Backend languages
  '.py', '.rb', '.php', '.java', '.kt', '.kts', '.scala',
  '.go', '.rs', '.cs', '.vb', '.fs', '.fsx',
  '.cpp', '.c', '.h', '.hpp', '.cc',
  '.swift', '.m', '.mm',
  '.dart',
  '.ex', '.exs',  // Elixir
  '.erl', '.hrl', // Erlang
  '.clj', '.cljs', // Clojure
  '.hs', '.lhs',  // Haskell
  '.lua',
  '.pl', '.pm',   // Perl
  '.r', '.R',     // R
  // Shell / scripting
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.bat', '.cmd',
  // Infrastructure as code
  '.tf', '.tfvars', // Terraform
  '.hcl',
  '.dockerfile',
  // Misc
  '.gradle', '.groovy',
  '.sql',
  '.graphql', '.gql',
  '.proto',
  '.md', '.mdx', '.txt', '.log',
]);

/**
 * File names (without extension, or exact names) that should always be scanned.
 */
const SCANNABLE_FILENAMES = new Set([
  'Dockerfile', 'docker-compose', 'docker-compose.yml', 'docker-compose.yaml',
  '.env', '.envrc', 'Makefile', 'Procfile', 'Gemfile', 'Rakefile',
  '.npmrc', '.yarnrc', '.pypirc', '.netrc', '.htpasswd',
]);

/**
 * Patterns for paths that should always be excluded regardless of .gitignore.
 */
const ALWAYS_IGNORE_GLOBS = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/__pycache__/**',
  '**/*.pyc',
  '**/*.pyo',
  '**/vendor/**',
  '**/.yarn/**',
  '**/.pnp.*',
  '**/coverage/**',
  '**/.nyc_output/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/*.map',
  '**/*.lock',        // package-lock.json, yarn.lock, etc.
  '**/Cargo.lock',
  '**/*.png', '**/*.jpg', '**/*.jpeg', '**/*.gif', '**/*.ico',
  '**/*.svg', '**/*.webp', '**/*.avif',
  '**/*.woff', '**/*.woff2', '**/*.ttf', '**/*.eot',
  '**/*.pdf', '**/*.zip', '**/*.tar', '**/*.gz', '**/*.tgz',
  '**/*.exe', '**/*.dll', '**/*.so', '**/*.dylib',
  '**/*.jar', '**/*.war', '**/*.ear', '**/*.class',
  '**/*.DS_Store',
];

/**
 * Loads a .gitignore file from the given directory and returns an `ignore` instance.
 */
function loadGitIgnore(dir: string): Ignore {
  const ig = ignore();
  const gitignorePath = path.join(dir, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const content = fs.readFileSync(gitignorePath, 'utf-8');
    ig.add(content);
  }
  // Also check nested .gitignore files by adding the built-in always-ignore patterns
  ig.add(ALWAYS_IGNORE_GLOBS.map(g => g.replace(/\*\*\//g, '')));
  return ig;
}

/**
 * Determines whether a file is scannable based on its extension or filename.
 */
function isScannableFile(filePath: string): boolean {
  const basename = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();

  if (SCANNABLE_FILENAMES.has(basename)) return true;
  if (ext && SCANNABLE_EXTENSIONS.has(ext)) return true;

  // Files with no extension that look like config files
  if (!ext && basename.startsWith('.')) return true;

  return false;
}

/**
 * Recursively walks `targetDir` and returns the absolute paths of all
 * scannable files, respecting the nearest .gitignore.
 */
export async function walkFiles(targetDir: string): Promise<string[]> {
  const absoluteDir = path.resolve(targetDir);
  const ig = loadGitIgnore(absoluteDir);

  const allFiles = await fg('**/*', {
    cwd: absoluteDir,
    absolute: true,
    onlyFiles: true,
    dot: true,
    ignore: ALWAYS_IGNORE_GLOBS,
    followSymbolicLinks: false,
  });

  return allFiles.filter(filePath => {
    const relative = path.relative(absoluteDir, filePath);
    // Apply gitignore rules
    if (ig.ignores(relative)) return false;
    // Apply extension/filename filter
    if (!isScannableFile(filePath)) return false;
    return true;
  });
}
