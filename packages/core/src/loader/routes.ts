import { basename } from "node:path";
import { walk } from "../parse/index.js";
import type { Route, ScanNote, SourceFile, SyntaxNode } from "../types.js";
import { stringLiteralValue } from "./redact.js";

const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "all"]);
/** Receiver identifiers that look like a router/app (so named-handler routes still match). */
const ROUTER_NAMES = new Set(["app", "router", "route", "routes", "server", "r", "api"]);
const FUNCTION_NODES = new Set([
  "arrow_function",
  "function",
  "function_expression",
  "generator_function",
]);
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const SENSITIVE =
  /(^|\/)(admin|internal|orders?|users?|customers?|payments?|refunds?|settings|config|checkout|cart)(\/|$|\?|:)/i;

/** Coarse "this file runs a server" signal — used only for the F8 honesty note. */
const SERVER_SIGNAL =
  /\b(?:http|https)\.createServer\b|\bcreateServer\s*\(|\bexpress\s*\(|\bnew\s+Koa\b|\bnew\s+Hono\b|\bfastify\s*\(|\.listen\s*\(/;

const NEXT_ROUTE_EXPORT =
  /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*=/g;

function isSensitive(path: string): boolean {
  return SENSITIVE.test(path);
}

/** Express/Koa/Hono-style: `<id>.get("/path", handler)`. */
function extractExpressRoutes(file: SourceFile, out: Route[]): void {
  if (!file.tree) return;
  walk(file.tree.rootNode, (node: SyntaxNode) => {
    if (node.type !== "call_expression") return;
    const callee = node.childForFieldName("function");
    if (!callee || callee.type !== "member_expression") return;
    const prop = callee.childForFieldName("property");
    if (!prop) return;
    const method = prop.text.toLowerCase();
    if (!ROUTE_METHODS.has(method)) return;
    const args = node.childForFieldName("arguments");
    const first = args?.namedChild(0);
    if (!first || first.type !== "string") return;
    const path = stringLiteralValue(first);

    // Discriminate real routes from Map.get("k") / searchParams.get("k") / axios.post(url, body):
    // a route path starts with "/", AND either a handler function is passed or the receiver
    // looks like a router/app.
    if (!path.startsWith("/")) return;
    const receiver = callee.childForFieldName("object");
    const receiverName = receiver?.type === "identifier" ? receiver.text.toLowerCase() : "";
    let hasFunctionArg = false;
    if (args) {
      for (let i = 1; i < args.namedChildCount; i++) {
        const a = args.namedChild(i);
        if (a && FUNCTION_NODES.has(a.type)) {
          hasFunctionArg = true;
          break;
        }
      }
    }
    if (!hasFunctionArg && !ROUTER_NAMES.has(receiverName)) return;
    const httpMethod = method === "all" ? "ALL" : method.toUpperCase();
    out.push({
      method: httpMethod,
      path,
      file: file.path,
      line: node.startPosition.row + 1,
      framework: "express",
      isMutating: MUTATING.has(httpMethod),
      looksSensitive: isSensitive(path),
      handlerNode: node,
    });
  });
}

/** Next.js App Router: an `app/.../route.{ts,js}` file exporting HTTP-verb handlers. */
function extractNextAppRoutes(file: SourceFile, out: Route[]): void {
  const base = basename(file.path);
  if (!/^route\.(t|j)sx?$/.test(base) || !/(^|\/)app\//.test(file.path)) return;
  const urlPath = `/${file.path.replace(/(^|\/)app\//, "").replace(/\/route\.(t|j)sx?$/, "")}`;
  NEXT_ROUTE_EXPORT.lastIndex = 0;
  for (const m of file.text.matchAll(NEXT_ROUTE_EXPORT)) {
    const method = (m[1] ?? m[2]) as string;
    const line = file.text.slice(0, m.index).split("\n").length;
    out.push({
      method,
      path: urlPath,
      file: file.path,
      line,
      framework: "next-app",
      isMutating: MUTATING.has(method),
      looksSensitive: isSensitive(urlPath),
    });
  }
}

/**
 * Extract routes across all files. F8 honesty rule (CTO review): if a file clearly runs a
 * server but we mapped zero routes from it, say so — never let "found nothing" read as "safe".
 */
export function extractRoutes(files: SourceFile[]): { routes: Route[]; notes: ScanNote[] } {
  const routes: Route[] = [];
  const notes: ScanNote[] = [];

  for (const file of files) {
    if (file.lang === "json" || file.lang === "env") continue;
    extractExpressRoutes(file, routes);
    extractNextAppRoutes(file, routes);
  }

  const serverFiles = files.filter(
    (f) => f.lang !== "json" && f.lang !== "env" && SERVER_SIGNAL.test(f.text),
  );
  if (serverFiles.length > 0 && routes.length === 0) {
    notes.push({
      level: "info",
      message:
        "Server code detected but no routes could be mapped (unrecognized framework/router). " +
        "Auth, commerce, and performance checks may be incomplete — verify manually.",
    });
  }

  return { routes, notes };
}
