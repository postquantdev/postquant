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
  const modules = new Set<string>();
  const symbols = new Map<string, string>();
  const aliases = new Map<string, string>();

  const root = tree.rootNode;

  for (let i = 0; i < root.childCount; i++) {
    const node = root.child(i)!;

    if (node.type === 'import_statement') {
      // import X from 'Y' / import { X } from 'Y' / import { X as Z } from 'Y'
      const sourceNode = node.childForFieldName('source');
      const moduleName = extractStringContent(sourceNode);
      if (!moduleName) continue;

      // Walk import_clause children
      for (let j = 0; j < node.namedChildCount; j++) {
        const child = node.namedChild(j)!;
        if (child.type === 'import_clause') {
          processJSImportClause(child, moduleName, modules, symbols, aliases);
        }
      }
    } else if (node.type === 'lexical_declaration' || node.type === 'variable_declaration') {
      // const X = require('Y') / const { X } = require('Y')
      for (let j = 0; j < node.namedChildCount; j++) {
        const declarator = node.namedChild(j)!;
        if (declarator.type !== 'variable_declarator') continue;

        const valueNode = declarator.childForFieldName('value');
        if (!valueNode || valueNode.type !== 'call_expression') continue;

        const funcNode = valueNode.childForFieldName('function');
        if (!funcNode || funcNode.text !== 'require') continue;

        const argsNode = valueNode.childForFieldName('arguments');
        const moduleName = extractFirstArgString(argsNode);
        if (!moduleName) continue;

        const nameNode = declarator.childForFieldName('name');
        if (!nameNode) continue;

        if (nameNode.type === 'identifier') {
          // const crypto = require('crypto')
          modules.add(nameNode.text);
        } else if (nameNode.type === 'object_pattern') {
          // const { createHash, createHmac } = require('crypto')
          for (let k = 0; k < nameNode.namedChildCount; k++) {
            const prop = nameNode.namedChild(k)!;
            if (prop.type === 'shorthand_property_identifier_pattern') {
              symbols.set(prop.text, `${moduleName}.${prop.text}`);
            } else if (prop.type === 'pair_pattern') {
              const key = prop.childForFieldName('key');
              const value = prop.childForFieldName('value');
              if (key && value) {
                symbols.set(value.text, `${moduleName}.${key.text}`);
                aliases.set(value.text, key.text);
              }
            }
          }
        }
      }
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

function processJSImportClause(
  clause: Node,
  moduleName: string,
  modules: Set<string>,
  symbols: Map<string, string>,
  aliases: Map<string, string>,
) {
  for (let i = 0; i < clause.namedChildCount; i++) {
    const child = clause.namedChild(i)!;

    if (child.type === 'identifier') {
      // Default import: import crypto from 'crypto'
      symbols.set(child.text, moduleName);
    } else if (child.type === 'named_imports') {
      // Named imports: import { X, Y as Z } from 'mod'
      for (let j = 0; j < child.namedChildCount; j++) {
        const spec = child.namedChild(j)!;
        if (spec.type === 'import_specifier') {
          const nameNode = spec.childForFieldName('name');
          const aliasNode = spec.childForFieldName('alias');
          if (nameNode && aliasNode) {
            symbols.set(aliasNode.text, `${moduleName}.${nameNode.text}`);
            aliases.set(aliasNode.text, nameNode.text);
          } else if (nameNode) {
            symbols.set(nameNode.text, `${moduleName}.${nameNode.text}`);
          }
        }
      }
    } else if (child.type === 'namespace_import') {
      // import * as X from 'mod'
      const nameNode = child.namedChild(0);
      if (nameNode) {
        modules.add(nameNode.text);
      }
    }
  }
}

function extractStringContent(node: Node | null): string | null {
  if (!node || node.type !== 'string') return null;
  // String node has string_fragment child
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i)!;
    if (child.type === 'string_fragment') return child.text;
  }
  return null;
}

function extractFirstArgString(argsNode: Node | null): string | null {
  if (!argsNode) return null;
  for (let i = 0; i < argsNode.namedChildCount; i++) {
    const arg = argsNode.namedChild(i)!;
    if (arg.type === 'string') return extractStringContent(arg);
  }
  return null;
}
