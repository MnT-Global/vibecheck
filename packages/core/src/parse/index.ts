import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import Parser from "web-tree-sitter";
import type { Lang, SyntaxNode, SyntaxTree } from "../types.js";

const require = createRequire(import.meta.url);

/** Directory holding the prebuilt grammar .wasm files (a runtime dependency). */
function wasmsDir(): string {
  return join(dirname(require.resolve("tree-sitter-wasms/package.json")), "out");
}

/** Which grammar handles which language. JS grammar covers JSX; TS/TSX are separate. */
const GRAMMAR_FILE: Record<Lang, string | null> = {
  js: "tree-sitter-javascript.wasm",
  jsx: "tree-sitter-javascript.wasm",
  ts: "tree-sitter-typescript.wasm",
  tsx: "tree-sitter-tsx.wasm",
  json: null,
  env: null,
  other: null,
};

let initPromise: Promise<void> | null = null;
const grammars = new Map<string, Parser.Language>();
let parser: Parser | null = null;

async function ensureInit(): Promise<Parser> {
  if (!initPromise) initPromise = Parser.init();
  await initPromise;
  if (!parser) parser = new Parser();
  return parser;
}

async function loadGrammar(file: string): Promise<Parser.Language> {
  const cached = grammars.get(file);
  if (cached) return cached;
  const lang = await Parser.Language.load(join(wasmsDir(), file));
  grammars.set(file, lang);
  return lang;
}

/** True for languages we build an AST for. */
export function isParsable(lang: Lang): boolean {
  return GRAMMAR_FILE[lang] !== null;
}

/** Parse source into a tree-sitter tree, or undefined for non-code languages. */
export async function parseText(text: string, lang: Lang): Promise<SyntaxTree | undefined> {
  const file = GRAMMAR_FILE[lang];
  if (!file) return undefined;
  const p = await ensureInit();
  const grammar = await loadGrammar(file);
  p.setLanguage(grammar);
  return p.parse(text);
}

/** Depth-first walk; visitor may return false to stop descending into a node. */
export function walk(node: SyntaxNode, visit: (n: SyntaxNode) => unknown): void {
  if (visit(node) === false) return;
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) walk(child, visit);
  }
}

/** Collect every node whose type is in `types`. */
export function findNodes(root: SyntaxNode, types: ReadonlySet<string>): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  walk(root, (n) => {
    if (types.has(n.type)) out.push(n);
  });
  return out;
}
