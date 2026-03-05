import { readdir, readFile } from 'node:fs/promises';
import { join, extname, basename } from 'node:path';
import type { Language, DiscoveredFile } from '../../types/index.js';

/** Extension → Language mapping. TypeScript maps to 'javascript'. */
const EXTENSION_MAP: Record<string, Language> = {
  '.py': 'python',
  '.pyw': 'python',
  '.pyi': 'python',
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'javascript',
  '.mts': 'javascript',
  '.cts': 'javascript',
  '.tsx': 'javascript',
  '.go': 'go',
  '.java': 'java',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'c',
  '.hpp': 'c',
  '.cc': 'c',
  '.cxx': 'c',
  '.rs': 'rust',
};

/** Directories and patterns always ignored regardless of config. */
const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules',
  'vendor',
  '.git',
  'dist',
  'build',
  '__pycache__',
]);

/** File patterns always ignored (checked against basename). */
const DEFAULT_IGNORE_GLOBS = [
  '*.min.js',
  '*.bundle.js',
  '*.map',
  'package-lock.json',
  'yarn.lock',
  'go.sum',
];

export interface DiscoverOptions {
  /** Glob patterns to exclude */
  ignore?: string[];
  /** Path to ignore file (relative to scanRoot), default: .postquantignore */
  ignoreFile?: string;
  /** Maximum files to return */
  maxFiles?: number;
  /** Only return files for this language */
  language?: Language;
}

/**
 * Discover source files in a directory tree.
 * Returns files with detected language, filtered by ignore patterns and options.
 */
export async function discoverFiles(
  scanRoot: string,
  options: DiscoverOptions = {},
): Promise<DiscoveredFile[]> {
  const { ignore = [], ignoreFile, maxFiles = 10000, language } = options;

  // Load custom ignore patterns from ignore file
  const customIgnores = ignoreFile
    ? await loadIgnoreFile(join(scanRoot, ignoreFile))
    : [];

  const allIgnorePatterns = [...DEFAULT_IGNORE_GLOBS, ...ignore, ...customIgnores];

  const entries = await readdir(scanRoot, { recursive: true, withFileTypes: false });
  const results: DiscoveredFile[] = [];

  for (const entry of entries) {
    if (results.length >= maxFiles) break;

    const relativePath = typeof entry === 'string' ? entry : String(entry);

    // Skip files in default-ignored directories
    if (isInIgnoredDir(relativePath)) continue;

    // Check file extension for language
    const ext = extname(relativePath);
    const lang = EXTENSION_MAP[ext];
    if (!lang) continue;

    // Apply language filter
    if (language && lang !== language) continue;

    // Check against ignore patterns
    if (matchesAnyPattern(relativePath, allIgnorePatterns)) continue;

    results.push({ path: relativePath, language: lang });
  }

  return results;
}

/**
 * Check if a relative path is inside a default-ignored directory.
 */
function isInIgnoredDir(relativePath: string): boolean {
  const parts = relativePath.split('/');
  return parts.some((part) => DEFAULT_IGNORE_DIRS.has(part));
}

/**
 * Simple glob matching. Supports:
 * - `*` matches any characters except /
 * - `**` matches any characters including /
 * - Trailing `/` matches directory prefixes
 * - `#` comment lines are skipped
 * - Empty lines are skipped
 */
function matchesAnyPattern(filePath: string, patterns: string[]): boolean {
  const fileName = basename(filePath);

  for (const pattern of patterns) {
    if (matchesPattern(filePath, fileName, pattern)) return true;
  }
  return false;
}

function matchesPattern(filePath: string, fileName: string, pattern: string): boolean {
  // Directory pattern (trailing /)
  if (pattern.endsWith('/')) {
    const dirName = pattern.slice(0, -1);
    return filePath.startsWith(dirName + '/') || filePath.includes('/' + dirName + '/');
  }

  // Pattern with path separator — match against full path
  if (pattern.includes('/')) {
    return globMatch(pattern, filePath);
  }

  // Simple filename pattern — match against basename
  return globMatch(pattern, fileName);
}

/**
 * Minimal glob matcher. Converts glob to regex.
 * Supports * (any non-/ chars) and ** (any chars including /).
 */
function globMatch(pattern: string, str: string): boolean {
  let regexStr = '^';
  let i = 0;

  while (i < pattern.length) {
    const ch = pattern[i];

    if (ch === '*' && pattern[i + 1] === '*') {
      // ** matches everything including /
      regexStr += '.*';
      i += 2;
      // Skip trailing / after **
      if (pattern[i] === '/') i++;
    } else if (ch === '*') {
      // * matches everything except /
      regexStr += '[^/]*';
      i++;
    } else if (ch === '?') {
      regexStr += '[^/]';
      i++;
    } else if ('.+^${}()|[]\\'.includes(ch)) {
      regexStr += '\\' + ch;
      i++;
    } else {
      regexStr += ch;
      i++;
    }
  }

  regexStr += '$';

  try {
    return new RegExp(regexStr).test(str);
  } catch {
    return false;
  }
}

/**
 * Load ignore patterns from a file. Skips blank lines and comments (#).
 * Returns empty array if file doesn't exist.
 */
async function loadIgnoreFile(filePath: string): Promise<string[]> {
  try {
    const content = await readFile(filePath, 'utf-8');
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
  } catch {
    return [];
  }
}
