import { Parser, Language } from 'web-tree-sitter';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

type ASTLanguage = 'python' | 'javascript';

const GRAMMAR_FILES: Record<ASTLanguage, string> = {
  python: 'tree-sitter-python.wasm',
  javascript: 'tree-sitter-typescript.wasm',
};

let parserInstance: Parser | null = null;
let initPromise: Promise<void> | null = null;
const loadedLanguages = new Map<string, Language>();

function getTreeSitterWasmPath(): string {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  return join(__dirname, '..', '..', '..', '..', 'node_modules', 'web-tree-sitter', 'web-tree-sitter.wasm');
}

async function ensureInit(): Promise<void> {
  if (!initPromise) {
    initPromise = Parser.init({
      locateFile: () => getTreeSitterWasmPath(),
    });
  }
  await initPromise;
}

export async function getParser(): Promise<Parser> {
  await ensureInit();
  if (!parserInstance) {
    parserInstance = new Parser();
  }
  return parserInstance;
}

export async function getLanguage(lang: string): Promise<Language | null> {
  if (loadedLanguages.has(lang)) return loadedLanguages.get(lang)!;

  const grammarFile = GRAMMAR_FILES[lang as ASTLanguage];
  if (!grammarFile) return null;

  try {
    await ensureInit();
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const wasmPath = join(__dirname, '..', '..', '..', '..', 'grammars', grammarFile);
    const language = await Language.load(wasmPath);
    loadedLanguages.set(lang, language);
    return language;
  } catch {
    return null;
  }
}

/** Check whether a language has AST support. */
export function hasASTSupport(lang: string): boolean {
  return lang in GRAMMAR_FILES;
}

/** Reset parser state — for testing only. */
export function resetParser(): void {
  parserInstance = null;
  initPromise = null;
  loadedLanguages.clear();
}

// Re-export types for consumers
export type { Language };
