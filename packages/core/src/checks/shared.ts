/** Files whose findings are noise: tests, examples, fixtures, stories, mocks. */
const TEST_OR_EXAMPLE =
  /(^|\/)(__tests__|__mocks__|__fixtures__|test|tests|examples?|fixtures?|mocks?)(\/|$)|\.(test|spec|stories)\.[jt]sx?$/i;

export function isTestOrExampleFile(path: string): boolean {
  return TEST_OR_EXAMPLE.test(path);
}

/** Obvious dummy/placeholder values that are not real secrets. */
const PLACEHOLDER =
  /^(?:x+|\.+|your[-_ ].*|my[-_ ].*|changeme|example|dummy|test|placeholder|todo|xxx+|<[^>]*>|\$\{[^}]*\}|(.)\1{5,})$/i;

export function isPlaceholderSecret(value: string): boolean {
  if (PLACEHOLDER.test(value)) return true;
  if (/(?:example|placeholder|your[-_]?key|xxxx|dummy|redacted)/i.test(value)) return true;
  return false;
}

/** Return the (0-indexed) source line for evidence quoting. */
export function lineAt(text: string, row: number): string {
  return text.split("\n")[row] ?? "";
}

/** Coarse signal that a file runs an HTTP server (used to scope server-only checks). */
const SERVER_SIGNAL =
  /\b(?:http|https)\.createServer\b|\bcreateServer\s*\(|\bexpress\s*\(|\bnew\s+Koa\b|\bnew\s+Hono\b|\bfastify\s*\(|\.listen\s*\(|from\s+["']express["']|require\(["']express["']\)/;

export function looksServerSide(text: string): boolean {
  return SERVER_SIGNAL.test(text);
}
