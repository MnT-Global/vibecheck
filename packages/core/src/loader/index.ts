import { readFile, readdir, stat } from "node:fs/promises";
import { basename, extname, join, relative, sep } from "node:path";
import ignore from "ignore";
import { isParsable, parseText } from "../parse/index.js";
import type { Lang, ScanContext, ScanNote, ScanOptions, SourceFile } from "../types.js";
import { parseDependencies } from "./lockfile.js";
import { extractRoutes } from "./routes.js";

const DEFAULT_MAX_FILES = 5000;
const DEFAULT_MAX_FILE_BYTES = 1_500_000;

/** Directories never worth scanning (vendored, generated, VCS). */
const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "out",
  "coverage",
  ".turbo",
  ".vercel",
  "vendor",
  ".cache",
]);

const INCLUDED_LANGS: ReadonlySet<Lang> = new Set(["js", "jsx", "ts", "tsx", "json", "env"]);

function classify(path: string): Lang {
  const b = basename(path);
  if (b === ".env" || b.startsWith(".env")) return "env";
  const ext = extname(path).toLowerCase();
  switch (ext) {
    case ".js":
    case ".mjs":
    case ".cjs":
      return "js";
    case ".jsx":
      return "jsx";
    case ".ts":
    case ".mts":
    case ".cts":
      return "ts";
    case ".tsx":
      return "tsx";
    case ".json":
      return "json";
    default:
      return "other";
  }
}

/** Minified/generated files we never scan even if the extension says code. */
function isNoise(path: string): boolean {
  return /\.min\.(js|css)$/.test(path) || path.endsWith(".d.ts");
}

/** Cheap client-boundary heuristic (refined in later sprints for SEC-02). */
function detectClient(relPath: string, text: string): boolean {
  if (/^["']use client["']/m.test(text)) return true;
  const p = relPath.split(sep).join("/");
  if (/\/api\//.test(p) || /(^|\/)(app\/api|lib\/server|server)\//.test(p)) return false;
  if (/(^|\/)(components|src\/components)\//.test(p)) return true;
  if (/(^|\/)pages\//.test(p) && !/(^|\/)pages\/api\//.test(p)) return true;
  return false;
}

async function loadIgnorer(root: string): Promise<ReturnType<typeof ignore>> {
  const ig = ignore();
  try {
    const gitignore = await readFile(join(root, ".gitignore"), "utf8");
    ig.add(gitignore);
  } catch {
    // no .gitignore — fine
  }
  return ig;
}

async function* walkDir(
  dir: string,
  root: string,
  ig: ReturnType<typeof ignore>,
): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true, encoding: "utf8" }).catch(() => null);
  if (!entries) return;
  for (const entry of entries) {
    const abs = join(dir, entry.name);
    const rel = relative(root, abs).split(sep).join("/");
    if (!rel) continue;
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      if (ig.ignores(`${rel}/`)) continue;
      yield* walkDir(abs, root, ig);
    } else if (entry.isFile()) {
      if (ig.ignores(rel)) continue;
      yield abs;
    }
  }
}

/** Build the ScanContext: all I/O (walk, read, parse) happens here, once, up front. */
export async function buildContext(root: string, options: ScanOptions = {}): Promise<ScanContext> {
  // A nonexistent or non-directory root must fail LOUDLY. Otherwise the walk yields zero files,
  // zero findings score a perfect 100, and vibecheck reports "A+" for a path that was never
  // scanned — a dangerous false "all clear". (This is the #1 misuse: passing a URL or a typo'd
  // path.) Validate up front and throw a clear error the CLI can surface.
  const rootStat = await stat(root).catch(() => null);
  if (!rootStat) throw new Error(`path not found: ${root}`);
  if (!rootStat.isDirectory()) {
    throw new Error(`not a directory: ${root} — point vibecheck at a project folder`);
  }

  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const ig = await loadIgnorer(root);

  const files: SourceFile[] = [];
  const notes: ScanNote[] = [];
  let truncated = false;

  for await (const abs of walkDir(root, root, ig)) {
    if (files.length >= maxFiles) {
      truncated = true;
      break;
    }
    const rel = relative(root, abs).split(sep).join("/");
    const lang = classify(rel);
    if (!INCLUDED_LANGS.has(lang) || isNoise(rel)) continue;

    let size: number;
    try {
      size = (await stat(abs)).size;
    } catch {
      continue;
    }
    if (size > maxBytes) {
      notes.push({ level: "info", message: `skipped ${rel} (>${maxBytes} bytes)` });
      continue;
    }

    let text: string;
    try {
      text = await readFile(abs, "utf8");
    } catch {
      continue;
    }

    const file: SourceFile = {
      path: rel,
      absPath: abs,
      lang,
      text,
      lines: text.length === 0 ? 0 : text.split("\n").length,
      isClient: detectClient(rel, text),
    };
    if (isParsable(lang)) {
      file.tree = await parseText(text, lang);
    }
    files.push(file);
  }

  if (truncated) {
    notes.push({
      level: "warn",
      message: `file cap reached (${maxFiles}); scan may be incomplete`,
    });
  }

  const { routes, notes: routeNotes } = extractRoutes(files);
  notes.push(...routeNotes);
  const dependencies = await parseDependencies(files, root);

  return {
    root,
    files,
    routes,
    dependencies,
    notes,
    options: {
      experimental: options.experimental ?? false,
      gitHistory: options.gitHistory ?? false,
      allowPrivate: options.allowPrivate ?? false,
      ...options,
    },
  };
}
