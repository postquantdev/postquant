import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { getPatterns } from './patterns/index.js';
import type { CodeFinding, CryptoPattern, Language } from '../../types/index.js';

/**
 * Result of matching a file on disk — includes both findings and raw content
 * so downstream stages (e.g. risk assessor) can inspect surrounding code
 * without re-reading the file.
 */
export interface MatchFileResult {
  findings: CodeFinding[];
  content: string;
}

/**
 * Scan a file on disk and return code findings alongside the file content.
 */
export async function matchFile(
  filePath: string,
  language: Language,
): Promise<MatchFileResult> {
  const content = await fs.promises.readFile(filePath, 'utf-8');
  const relativeName = path.basename(filePath);
  const findings = matchFileContent(content, language, relativeName);
  return { findings, content };
}

/**
 * Scan file content (string) against patterns for a given language.
 * Returns CodeFinding[] with line numbers, confidence, etc.
 */
export function matchFileContent(
  content: string,
  language: Language,
  fileName: string,
): CodeFinding[] {
  const patterns = getPatterns(language);
  if (patterns.length === 0 || content.length === 0) return [];

  const lines = content.split('\n');

  // Phase 1: Pre-scan for imports to determine confidence
  const importHits = new Set<string>();
  for (const line of lines) {
    for (const pattern of patterns) {
      if (!pattern.importPatterns) continue;
      if (pattern.importPatterns.some((re) => re.test(line))) {
        importHits.add(pattern.id);
      }
    }
  }

  // Phase 2: Line-by-line matching with comment filtering
  const findings: CodeFinding[] = [];
  let inBlockComment = false;
  let blockCommentStyle: 'c' | 'python' | null = null;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    // --- Block comment tracking ---
    if (inBlockComment) {
      if (
        blockCommentStyle === 'c' &&
        trimmed.includes('*/')
      ) {
        inBlockComment = false;
        blockCommentStyle = null;
      } else if (
        blockCommentStyle === 'python' &&
        (trimmed.includes('"""') || trimmed.includes("'''"))
      ) {
        inBlockComment = false;
        blockCommentStyle = null;
      }
      continue;
    }

    // Detect start of block comments
    if (
      (language === 'javascript' || language === 'go' || language === 'java') &&
      trimmed.startsWith('/*')
    ) {
      if (!trimmed.includes('*/')) {
        inBlockComment = true;
        blockCommentStyle = 'c';
      }
      continue;
    }

    if (language === 'python') {
      if (trimmed.startsWith('"""') || trimmed.startsWith("'''")) {
        const opener = trimmed.slice(0, 3);
        const rest = trimmed.slice(3);
        if (rest.includes(opener)) {
          // Single-line triple-quoted string (e.g., """docstring""") — skip entirely
          continue;
        } else {
          // Multi-line docstring start
          inBlockComment = true;
          blockCommentStyle = 'python';
          continue;
        }
      }
    }

    // Skip single-line comments
    if (language === 'python' && trimmed.startsWith('#')) continue;
    if (
      (language === 'javascript' || language === 'go' || language === 'java') &&
      trimmed.startsWith('//')
    ) continue;

    // Skip Java block comment single-line: /** ... */
    if (
      (language === 'javascript' || language === 'go' || language === 'java') &&
      trimmed.startsWith('/*') &&
      trimmed.includes('*/')
    ) continue;

    // Strip inline comments for matching
    const codeLine = stripInlineComment(trimmed, language);

    // Skip lines that are pure string literals (heuristic)
    if (isPureStringLiteral(codeLine, language)) continue;

    // Phase 2: Match call patterns
    for (const pattern of patterns) {
      if (pattern.callPatterns.some((re) => re.test(codeLine))) {
        const lineNumber = i + 1; // 1-indexed

        // Determine confidence
        let confidence = pattern.confidence;
        if (pattern.importPatterns && pattern.importPatterns.length > 0) {
          confidence = importHits.has(pattern.id) ? 'high' : 'medium';
        }

        // Extract key size if extractor defined
        let keySize: number | undefined;
        let risk = pattern.risk;
        if (pattern.keySizeExtractor) {
          const match = pattern.keySizeExtractor.exec(codeLine);
          if (match) {
            // Find first non-undefined capture group
            const sizeStr = match.slice(1).find((g) => g !== undefined);
            if (sizeStr) {
              keySize = parseInt(sizeStr, 10);
              if (pattern.keySizeRisk && !isNaN(keySize)) {
                risk = pattern.keySizeRisk(keySize);
              }
            }
          }
        }

        findings.push({
          patternId: pattern.id,
          file: fileName,
          line: lineNumber,
          matchedLine: trimmed,
          language,
          category: pattern.category,
          algorithm: pattern.algorithm,
          keySize,
          risk,
          reason: pattern.description,
          migration: pattern.migration,
          confidence,
        });

        // Don't match the same line against more patterns of the same id
        break;
      }
    }
  }

  return findings;
}

/**
 * Strip inline comments from a code line.
 */
function stripInlineComment(line: string, language: Language): string {
  if (language === 'python') {
    // Simple heuristic: find # not inside quotes
    return stripAfterChar(line, '#');
  }
  if (language === 'javascript' || language === 'go' || language === 'java') {
    return stripAfterStr(line, '//');
  }
  return line;
}

function stripAfterChar(line: string, char: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === char && !inSingle && !inDouble) {
      return line.slice(0, i).trim();
    }
  }
  return line;
}

function stripAfterStr(line: string, str: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (
      !inSingle &&
      !inDouble &&
      line.slice(i, i + str.length) === str
    ) {
      return line.slice(0, i).trim();
    }
  }
  return line;
}

/**
 * Heuristic: detect if a line is a pure string assignment (variable = "...").
 */
function isPureStringLiteral(line: string, language: Language): boolean {
  if (language === 'python') {
    // Lines like: message = "Use rsa.generate_private_key() ..."
    if (/^\w+\s*=\s*["'].*["']\s*$/.test(line)) return true;
    if (/^\w+\s*=\s*['"].*['"]$/.test(line)) return true;
  }
  if (language === 'javascript' || language === 'java') {
    // Lines like: const message = "Use ...";
    if (/^(?:const|let|var|String)\s+\w+\s*=\s*["'`].*["'`]\s*;?\s*$/.test(line)) return true;
  }
  if (language === 'go') {
    // Lines like: msg := "rsa.GenerateKey is vulnerable"
    if (/^\w+\s*:?=\s*".*"\s*$/.test(line)) return true;
  }
  return false;
}
