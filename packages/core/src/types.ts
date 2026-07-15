import type Parser from "web-tree-sitter";

/** Tree-sitter node/tree aliases (kept local so checks don't import the parser directly). */
export type SyntaxNode = Parser.SyntaxNode;
export type SyntaxTree = Parser.Tree;

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium";
export type Tier = "structural" | "flow";

export type Category =
  | "secrets"
  | "injection"
  | "auth"
  | "commerce"
  | "web"
  | "perf"
  | "prod"
  | "deps";

export type Lang = "js" | "ts" | "jsx" | "tsx" | "json" | "env" | "other";

/** A single reported issue, always anchored to real code the user can verify. */
export interface Finding {
  id: string; // e.g. "SEC-01"
  category: Category;
  severity: Severity;
  confidence: Confidence;
  title: string;
  file: string; // repo-relative path
  line: number; // 1-indexed
  column: number; // 0-indexed
  evidence: string; // the actual code, truncated; secret VALUES redacted
  fix: string;
  docsUrl?: string;
}

/** A non-finding note surfaced in the report (honesty signals, e.g. F8 routes-unmapped). */
export interface ScanNote {
  level: "info" | "warn";
  message: string;
}

export interface SourceFile {
  path: string; // repo-relative
  absPath: string;
  lang: Lang;
  text: string;
  lines: number;
  isClient: boolean; // reachable by the browser bundle (SEC-02 boundary)
  tree?: SyntaxTree; // present only for parsed languages
}

export type Framework =
  | "express"
  | "next-app"
  | "next-pages"
  | "fastify"
  | "koa"
  | "hono"
  | "remix"
  | "node-http"
  | "unknown";

export interface Route {
  method: string; // GET/POST/... or "ALL"
  path: string;
  file: string;
  line: number;
  framework: Framework;
  isMutating: boolean; // POST/PUT/PATCH/DELETE
  looksSensitive: boolean; // /admin|/orders|/checkout|...
  handlerNode?: SyntaxNode;
}

/** A resolved dependency from a lockfile. */
export interface Dependency {
  name: string;
  version: string;
  dev: boolean;
}

/** A known vulnerability affecting a dependency version (from OSV/GHSA). */
export interface Advisory {
  id: string; // e.g. GHSA-p6mc-m468-83gw
  severity: Severity;
  summary: string;
  fixed?: string; // first fixed version, if known
}

/** name@version → advisories. */
export type AdvisoryMap = Map<string, Advisory[]>;

export interface ScanOptions {
  /** Allow scanning even when the tree looks like it has private/secret files (reserved). */
  allowPrivate?: boolean;
  /** Opt-in git-history secret pass (OFF by default — CTO F7). Not wired in v0.1.0. */
  gitHistory?: boolean;
  /** Enable flow-tier / experimental checks (OFF by default — ADR-001). */
  experimental?: boolean;
  /** Skip the (network) OSV dependency lookup even under --experimental. */
  offline?: boolean;
  /** Inject advisories (tests / hosted) instead of fetching from OSV. */
  advisories?: AdvisoryMap;
  maxFiles?: number;
  maxFileBytes?: number;
}

export interface ScanContext {
  root: string;
  files: SourceFile[];
  routes: Route[];
  dependencies: Dependency[];
  advisories?: AdvisoryMap;
  notes: ScanNote[];
  options: Required<Pick<ScanOptions, "experimental" | "gitHistory" | "allowPrivate">> &
    ScanOptions;
}

/** A check is a PURE function over a fully-built ScanContext. No I/O inside. */
export interface Check {
  id: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  tier: Tier;
  title: string;
  /** Stack-neutrality gate: false => N/A, category excluded from the denominator. */
  appliesTo(ctx: ScanContext): boolean;
  run(ctx: ScanContext): Finding[];
}

export type Grade =
  | "A+"
  | "A"
  | "A-"
  | "B+"
  | "B"
  | "B-"
  | "C+"
  | "C"
  | "C-"
  | "D+"
  | "D"
  | "D-"
  | "F";

export interface CategoryScore {
  category: Category;
  applicable: boolean;
  max: number;
  earned: number;
  findings: number;
}

export interface Report {
  root: string;
  grade: Grade;
  score: number; // 0-100
  findings: Finding[];
  categoryScores: CategoryScore[];
  notes: ScanNote[];
  filesScanned: number;
  durationMs: number;
}
