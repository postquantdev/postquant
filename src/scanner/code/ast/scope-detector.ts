import type { Tree, Node } from 'web-tree-sitter';
import type { ScopeInfo } from '../../../types/index.js';

/**
 * Detect the enclosing scope for a given line number in the AST.
 * Line is 1-indexed to match CodeFinding.line.
 */
export function detectScope(
  tree: Tree,
  line: number,
  language: 'python' | 'javascript',
): ScopeInfo {
  const row = line - 1; // tree-sitter uses 0-indexed rows
  const node = tree.rootNode.descendantForPosition({ row, column: 0 });

  let functionName: string | undefined;
  let className: string | undefined;
  let isTestCode = false;
  let isConditionalPath = false;

  let current: Node | null = node;

  while (current) {
    if (language === 'python') {
      checkPythonScope(current, {
        setFunction: (name) => { if (!functionName) functionName = name; },
        setClass: (name) => { if (!className) className = name; },
        setTest: () => { isTestCode = true; },
        setConditional: () => { isConditionalPath = true; },
      });
    } else {
      checkJavaScriptScope(current, {
        setFunction: (name) => { if (!functionName) functionName = name; },
        setClass: (name) => { if (!className) className = name; },
        setTest: () => { isTestCode = true; },
        setConditional: () => { isConditionalPath = true; },
      });
    }

    current = current.parent;
  }

  return { functionName, className, isTestCode, isConditionalPath };
}

interface ScopeCallbacks {
  setFunction: (name: string) => void;
  setClass: (name: string) => void;
  setTest: () => void;
  setConditional: () => void;
}

function checkPythonScope(node: Node, cb: ScopeCallbacks) {
  if (node.type === 'function_definition') {
    const nameNode = node.childForFieldName('name');
    if (nameNode) {
      cb.setFunction(nameNode.text);
      if (nameNode.text.startsWith('test_') || nameNode.text.startsWith('test')) {
        cb.setTest();
      }
    }
    // Check for pytest decorators on parent decorated_definition
    const parent = node.parent;
    if (parent?.type === 'decorated_definition') {
      for (let i = 0; i < parent.namedChildCount; i++) {
        const child = parent.namedChild(i)!;
        if (child.type === 'decorator' && /pytest\.(fixture|mark)/.test(child.text)) {
          cb.setTest();
        }
      }
    }
  }

  if (node.type === 'class_definition') {
    const nameNode = node.childForFieldName('name');
    if (nameNode) {
      cb.setClass(nameNode.text);
      if (nameNode.text.startsWith('Test')) {
        cb.setTest();
      }
    }
  }

  if (node.type === 'try_statement') {
    cb.setConditional();
  }

  if (node.type === 'if_statement' || node.type === 'elif_clause' || node.type === 'else_clause') {
    cb.setConditional();
  }
}

function checkJavaScriptScope(node: Node, cb: ScopeCallbacks) {
  // function declarations
  if (node.type === 'function_declaration') {
    const nameNode = node.childForFieldName('name');
    if (nameNode) cb.setFunction(nameNode.text);
  }

  // arrow functions assigned to variables: const X = () => { ... }
  if (node.type === 'variable_declarator') {
    const nameNode = node.childForFieldName('name');
    const valueNode = node.childForFieldName('value');
    if (nameNode && valueNode?.type === 'arrow_function') {
      cb.setFunction(nameNode.text);
    }
  }

  // method definitions in classes
  if (node.type === 'method_definition') {
    const nameNode = node.childForFieldName('name');
    if (nameNode) cb.setFunction(nameNode.text);
  }

  // class declarations
  if (node.type === 'class_declaration') {
    const nameNode = node.childForFieldName('name');
    if (nameNode) cb.setClass(nameNode.text);
  }

  // describe/it/test blocks
  if (node.type === 'call_expression') {
    const funcNode = node.childForFieldName('function');
    if (funcNode && /^(describe|it|test|beforeEach|afterEach|beforeAll|afterAll)$/.test(funcNode.text)) {
      cb.setTest();
    }
  }

  // try/catch
  if (node.type === 'try_statement') {
    cb.setConditional();
  }

  if (node.type === 'if_statement') {
    cb.setConditional();
  }
}
