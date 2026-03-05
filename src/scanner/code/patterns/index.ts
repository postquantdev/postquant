import type { CryptoPattern, Language } from '../../../types/index.js';
import { pythonPatterns } from './python.js';
import { javascriptPatterns } from './javascript.js';
import { goPatterns } from './go.js';
import { javaPatterns } from './java.js';
import { cPatterns } from './c.js';
import { rustPatterns } from './rust.js';

const patternsByLanguage: Record<Language, CryptoPattern[]> = {
  python: pythonPatterns,
  javascript: javascriptPatterns,
  go: goPatterns,
  java: javaPatterns,
  c: cPatterns,
  rust: rustPatterns,
};

/** Get all patterns for a specific language. */
export function getPatterns(language: Language): CryptoPattern[] {
  return patternsByLanguage[language] ?? [];
}

/** Get all patterns across all languages. */
export function getAllPatterns(): CryptoPattern[] {
  return Object.values(patternsByLanguage).flat();
}

export { pythonPatterns, javascriptPatterns, goPatterns, javaPatterns, cPatterns, rustPatterns };
