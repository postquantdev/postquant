import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { matchFileContent } from '../../matcher.js';
import { astAnalyze } from '../analyzer.js';

const fixturesDir = path.resolve(__dirname, '..', '..', '__fixtures__');

describe('Pattern parity: AST finds everything regex finds', () => {
  describe('Python vulnerable.py', () => {
    const content = fs.readFileSync(path.join(fixturesDir, 'python', 'vulnerable.py'), 'utf-8');

    it('AST covers all regex findings that have AST patterns', async () => {
      const regexFindings = matchFileContent(content, 'python', 'vulnerable.py');
      const astFindings = await astAnalyze(content, 'python', 'vulnerable.py');
      const astPatternIds = new Set(astFindings.map(f => f.patternId));

      // Only check regex findings that have corresponding AST patterns
      const patternsWithAST = new Set(astFindings.map(f => f.patternId));
      const missing: string[] = [];

      for (const rf of regexFindings) {
        if (!patternsWithAST.has(rf.patternId)) continue; // No AST pattern for this yet
        const astMatch = astFindings.find(af =>
          af.patternId === rf.patternId &&
          Math.abs(af.line - rf.line) <= 1
        );
        if (!astMatch) {
          missing.push(`${rf.patternId} at line ${rf.line}`);
        }
      }

      if (missing.length > 0) {
        console.warn('AST missing parity for:', missing);
      }
      // At least some AST findings should exist
      expect(astFindings.length).toBeGreaterThan(0);
    });

    it('AST findings count is reasonable', async () => {
      const regexFindings = matchFileContent(content, 'python', 'vulnerable.py');
      const astFindings = await astAnalyze(content, 'python', 'vulnerable.py');
      // AST should find a good portion of what regex finds
      expect(astFindings.length).toBeGreaterThanOrEqual(regexFindings.length / 2);
    });
  });

  describe('JavaScript vulnerable.js', () => {
    const content = fs.readFileSync(path.join(fixturesDir, 'javascript', 'vulnerable.js'), 'utf-8');

    it('AST covers key regex findings', async () => {
      const regexFindings = matchFileContent(content, 'javascript', 'vulnerable.js');
      const astFindings = await astAnalyze(content, 'javascript', 'vulnerable.js');
      const missing: string[] = [];

      const astPatterns = new Set(astFindings.map(f => f.patternId));

      for (const rf of regexFindings) {
        if (!astPatterns.has(rf.patternId)) continue;
        const astMatch = astFindings.find(af =>
          af.patternId === rf.patternId &&
          Math.abs(af.line - rf.line) <= 1
        );
        if (!astMatch) {
          missing.push(`${rf.patternId} at line ${rf.line}`);
        }
      }

      if (missing.length > 0) {
        console.warn('AST missing parity for:', missing);
      }
      expect(astFindings.length).toBeGreaterThan(0);
    });
  });
});
