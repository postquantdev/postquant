import type { Language } from '../../../../types/index.js';
import type { ASTPattern } from './types.js';
import { pythonASTPatterns } from './python.js';
import { javascriptASTPatterns } from './javascript.js';

const patternsByLanguage: Partial<Record<Language, ASTPattern[]>> = {
  python: pythonASTPatterns,
  javascript: javascriptASTPatterns,
};

export function getASTPatterns(language: Language): ASTPattern[] {
  return patternsByLanguage[language] ?? [];
}

export function hasASTPatterns(language: Language): boolean {
  return (patternsByLanguage[language]?.length ?? 0) > 0;
}
