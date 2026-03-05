import type { Tree, Node } from 'web-tree-sitter';

export interface ImportMap {
  /** Module-level imports (import X / import X as Y) — key is local name */
  modules: Set<string>;
  /** Symbol-level imports (from X import Y) — key is local name, value is fully-qualified path */
  symbols: Map<string, string>;
  /** Alias map — key is alias, value is original name */
  aliases: Map<string, string>;
  /** Resolve a local name to its original (un-aliased) name */
  getOriginalName(localName: string): string;
}

export function resolveImports(tree: Tree, language: 'python' | 'javascript'): ImportMap {
  if (language === 'python') return resolvePythonImports(tree);
  return resolveJavaScriptImports(tree);
}

function resolvePythonImports(tree: Tree): ImportMap {
  const modules = new Set<string>();
  const symbols = new Map<string, string>();
  const aliases = new Map<string, string>();

  const root = tree.rootNode;

  for (let i = 0; i < root.childCount; i++) {
    const node = root.child(i)!;

    if (node.type === 'import_statement') {
      // import X or import X as Y
      // Field 'name' can appear multiple times
      processImportNames(node, (name, alias) => {
        if (alias) {
          modules.add(alias);
          aliases.set(alias, name);
        } else {
          modules.add(name);
        }
      });
    } else if (node.type === 'import_from_statement') {
      // from X import Y, Z or from X import Y as Z
      const moduleNode = node.childForFieldName('module_name');
      const moduleName = moduleNode?.text ?? '';

      processImportNames(node, (name, alias) => {
        const localName = alias ?? name;
        symbols.set(localName, `${moduleName}.${name}`);
        if (alias) {
          aliases.set(alias, name);
        }
      });
    }
  }

  return {
    modules,
    symbols,
    aliases,
    getOriginalName(localName: string): string {
      return aliases.get(localName) ?? localName;
    },
  };
}

/** Walk named children looking for dotted_name and aliased_import nodes used as import names. */
function processImportNames(
  node: Node,
  callback: (name: string, alias: string | null) => void,
) {
  const moduleNode = node.childForFieldName('module_name');

  for (let j = 0; j < node.namedChildCount; j++) {
    const child = node.namedChild(j)!;

    // Skip the module_name in from-import statements
    if (child === moduleNode) continue;

    if (child.type === 'dotted_name') {
      callback(child.text, null);
    } else if (child.type === 'aliased_import') {
      const nameNode = child.childForFieldName('name');
      const aliasNode = child.childForFieldName('alias');
      if (nameNode && aliasNode) {
        callback(nameNode.text, aliasNode.text);
      } else if (nameNode) {
        callback(nameNode.text, null);
      }
    }
  }
}

function resolveJavaScriptImports(tree: Tree): ImportMap {
  // Placeholder — implemented in Task 5
  const modules = new Set<string>();
  const symbols = new Map<string, string>();
  const aliases = new Map<string, string>();

  return {
    modules,
    symbols,
    aliases,
    getOriginalName(localName: string): string {
      return aliases.get(localName) ?? localName;
    },
  };
}
