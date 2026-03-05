import type { CodeFinding } from '../../../types/index.js';

/**
 * Merge regex and AST findings with dedup.
 *
 * Dedup key: file + patternId + line (with +/-1 tolerance).
 * When both match: AST version wins (higher confidence, enriched data).
 * Regex-only: pass through.
 * AST-only: append at end.
 */
export function mergeFindings(
  regexFindings: CodeFinding[],
  astFindings: CodeFinding[],
): CodeFinding[] {
  if (astFindings.length === 0) return regexFindings;
  if (regexFindings.length === 0) return astFindings;

  // Index AST findings by file + patternId + line (and adjacent lines)
  const astIndex = new Map<string, CodeFinding>();
  for (const af of astFindings) {
    for (const offset of [0, -1, 1]) {
      const key = dedupKey(af.file, af.patternId, af.line + offset);
      if (!astIndex.has(key) || offset === 0) {
        astIndex.set(key, af);
      }
    }
  }

  const merged: CodeFinding[] = [];
  const matchedAstKeys = new Set<string>();

  // Pass 1: Walk regex findings, upgrade where AST has a match
  for (const rf of regexFindings) {
    const key = dedupKey(rf.file, rf.patternId, rf.line);
    const af = astIndex.get(key);
    if (af) {
      merged.push(af);
      matchedAstKeys.add(dedupKey(af.file, af.patternId, af.line));
    } else {
      merged.push(rf);
    }
  }

  // Pass 2: Add AST-only findings (not matched by any regex finding)
  for (const af of astFindings) {
    const key = dedupKey(af.file, af.patternId, af.line);
    if (!matchedAstKeys.has(key)) {
      merged.push(af);
    }
  }

  return merged;
}

function dedupKey(file: string, patternId: string, line: number): string {
  return `${file}:${patternId}:${line}`;
}
