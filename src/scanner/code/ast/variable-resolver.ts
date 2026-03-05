import type { Tree, Node } from 'web-tree-sitter';

interface VarEntry {
  value: string | number;
  line: number; // 1-indexed
}

export interface VariableMap {
  /** Get latest string value of a variable */
  getString(name: string): string | undefined;
  /** Get latest number value of a variable */
  getNumber(name: string): number | undefined;
  /** Get string value of a variable as it was at a specific line */
  getStringAtLine(name: string, line: number): string | undefined;
}

export function resolveVariables(tree: Tree, language: 'python' | 'javascript'): VariableMap {
  const entries = new Map<string, VarEntry[]>();

  function record(name: string, value: string | number, line: number) {
    if (!entries.has(name)) entries.set(name, []);
    entries.get(name)!.push({ value, line });
  }

  walkAssignments(tree.rootNode, language, record);

  return {
    getString(name: string): string | undefined {
      const list = entries.get(name);
      if (!list || list.length === 0) return undefined;
      const last = list[list.length - 1];
      return typeof last.value === 'string' ? last.value : undefined;
    },
    getNumber(name: string): number | undefined {
      const list = entries.get(name);
      if (!list || list.length === 0) return undefined;
      const last = list[list.length - 1];
      return typeof last.value === 'number' ? last.value : undefined;
    },
    getStringAtLine(name: string, line: number): string | undefined {
      const list = entries.get(name);
      if (!list) return undefined;
      let best: VarEntry | undefined;
      for (const entry of list) {
        if (entry.line <= line) best = entry;
      }
      return best && typeof best.value === 'string' ? best.value : undefined;
    },
  };
}

function walkAssignments(
  node: Node,
  language: 'python' | 'javascript',
  record: (name: string, value: string | number, line: number) => void,
) {
  if (language === 'python') {
    walkPythonAssignments(node, record);
  } else {
    walkJavaScriptAssignments(node, record);
  }
}

function walkPythonAssignments(
  node: Node,
  record: (name: string, value: string | number, line: number) => void,
) {
  if (node.type === 'assignment') {
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    if (left?.type === 'identifier' && right) {
      const val = extractLiteral(right);
      if (val !== undefined) {
        record(left.text, val, left.startPosition.row + 1);
      }
    }
  }

  for (let i = 0; i < node.childCount; i++) {
    walkPythonAssignments(node.child(i)!, record);
  }
}

function walkJavaScriptAssignments(
  node: Node,
  record: (name: string, value: string | number, line: number) => void,
) {
  // variable_declarator: const/let/var name = value
  if (node.type === 'variable_declarator') {
    const nameNode = node.childForFieldName('name');
    const valueNode = node.childForFieldName('value');
    if (nameNode?.type === 'identifier' && valueNode) {
      const val = extractLiteral(valueNode);
      if (val !== undefined) {
        record(nameNode.text, val, nameNode.startPosition.row + 1);
      }
    }
  }

  // assignment_expression: name = value
  if (node.type === 'assignment_expression') {
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    if (left?.type === 'identifier' && right) {
      const val = extractLiteral(right);
      if (val !== undefined) {
        record(left.text, val, left.startPosition.row + 1);
      }
    }
  }

  for (let i = 0; i < node.childCount; i++) {
    walkJavaScriptAssignments(node.child(i)!, record);
  }
}

function extractLiteral(node: Node): string | number | undefined {
  // Python: string has string_content child; JS: string has string_fragment child
  if (node.type === 'string') {
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i)!;
      if (child.type === 'string_content' || child.type === 'string_fragment') {
        return child.text;
      }
    }
    // Fallback: strip quotes
    const text = node.text;
    if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
      return text.slice(1, -1);
    }
    return text;
  }

  // Python integer
  if (node.type === 'integer') {
    const num = parseInt(node.text, 10);
    return isNaN(num) ? undefined : num;
  }

  // JS number
  if (node.type === 'number') {
    const num = parseInt(node.text, 10);
    return isNaN(num) ? undefined : num;
  }

  return undefined;
}
