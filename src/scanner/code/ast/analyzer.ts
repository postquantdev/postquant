import type { CodeFinding, Language } from '../../../types/index.js';
import { getParser, getLanguage, hasASTSupport } from './parser.js';
import { resolveImports, type ImportMap } from './import-resolver.js';
import { resolveVariables } from './variable-resolver.js';
import { detectScope } from './scope-detector.js';
import { getASTPatterns, hasASTPatterns } from './patterns/index.js';
import type { ASTPattern } from './patterns/types.js';
import { Query, type Node } from 'web-tree-sitter';

/**
 * Analyze source code using tree-sitter AST.
 * Returns CodeFinding[] with confidence='verified' and scope info.
 * Returns empty array for unsupported languages or on any error.
 */
export async function astAnalyze(
  content: string,
  language: Language,
  fileName: string,
): Promise<CodeFinding[]> {
  if (!hasASTSupport(language) || !hasASTPatterns(language)) {
    return [];
  }

  try {
    const parser = await getParser();
    const lang = await getLanguage(language);
    if (!lang) return [];

    parser.setLanguage(lang);
    const tree = parser.parse(content);
    if (!tree) return [];

    const astLang = language as 'python' | 'javascript';
    const imports = resolveImports(tree, astLang);
    const variables = resolveVariables(tree, astLang);
    const patterns = getASTPatterns(language);
    const lines = content.split('\n');

    const findings: CodeFinding[] = [];

    for (const pattern of patterns) {
      let query: Query;
      try {
        query = new Query(lang, pattern.query);
      } catch {
        continue; // Skip patterns with invalid queries
      }

      const matches = query.matches(tree.rootNode);

      for (const match of matches) {
        const captures = new Map<string, Node>();
        for (const capture of match.captures) {
          captures.set(capture.name, capture.node);
        }

        // Check method name constraint
        if (pattern.methodNames) {
          const methodNode = captures.get('method');
          if (!methodNode || !pattern.methodNames.includes(methodNode.text)) continue;
        }

        // Check import constraint
        if (pattern.requiredImports && pattern.requiredImports.length > 0) {
          const objNode = captures.get('obj');
          if (!objNode || !matchesImportConstraint(objNode.text, pattern, imports)) continue;
        }

        // Check first argument pattern
        if (pattern.firstArgPattern) {
          const argsNode = captures.get('args');
          if (!argsNode) continue;
          const firstArg = getFirstArgText(argsNode);
          if (!firstArg || !pattern.firstArgPattern.test(firstArg)) continue;
        }

        // Determine line from the call site
        const callNode = captures.get('method') ?? captures.get('obj');
        if (!callNode) continue;

        const line = callNode.startPosition.row + 1;
        const scope = detectScope(tree, line, astLang);
        const matchedLine = lines[callNode.startPosition.row]?.trim() ?? '';

        findings.push({
          patternId: pattern.id,
          file: fileName,
          line,
          matchedLine,
          language,
          category: pattern.category,
          algorithm: pattern.algorithm,
          risk: pattern.risk,
          reason: pattern.description,
          migration: pattern.migration,
          confidence: 'verified',
          scopeInfo: scope,
          astEnriched: true,
        });
      }
    }

    return findings;
  } catch {
    return [];
  }
}

function matchesImportConstraint(
  objName: string,
  pattern: ASTPattern,
  imports: ImportMap,
): boolean {
  if (!pattern.requiredImports) return true;

  const originalName = imports.getOriginalName(objName);

  return pattern.requiredImports.some((req) => {
    if (req.symbol) {
      // from X import Y — check if objName resolves to Y
      return originalName === req.symbol || objName === req.symbol;
    }
    // import X — check if objName is a known module
    return imports.modules.has(objName) || imports.modules.has(originalName);
  });
}

function getFirstArgText(argsNode: Node): string | null {
  // arguments node: first named child is the first argument
  for (let i = 0; i < argsNode.namedChildCount; i++) {
    const arg = argsNode.namedChild(i)!;
    return arg.text;
  }
  return null;
}
