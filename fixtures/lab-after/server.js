/* ============================================================================
 *  AFTER — the same store, re-architected by MnT.  Same features, every vuln
 *  from ../before closed, and the load pathology removed. Zero dependencies.
 *
 *  Fixes, one-to-one with the before/ vulnerabilities:
 *   • Injection/XSS  → safe string search, HTML-escaped output (no new Function)
 *   • Access control → /admin/orders requires a bearer token; PII redacted
 *   • Validation     → checkout validates types/ranges, rejects bad input
 *   • Secrets        → payment key read from env, never returned to clients
 *   • Performance    → DB loaded ONCE into memory + indexed; no per-request disk
 *   • Abuse          → a simple fixed-window rate limiter
 * ==========================================================================*/
const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const STORE = path.join(__dirname, "..", "data", "store.json");
const PAYMENT_API_KEY = process.env.PAYMENT_API_KEY || "test_key_from_env";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "admin-2024";

// Load once at boot; index for O(1) lookups. No disk on the hot path.
const data = JSON.parse(fs.readFileSync(STORE, "utf8"));
const byId = new Map(data.products.map((p) => [p.id, p]));
const byCat = new Map();
for (const p of data.products) {
  if (!byCat.has(p.category)) byCat.set(p.category, []);
  byCat.get(p.category).push(p);
}

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Fixed-window rate limiter: 100 req / 10s / IP.
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const w = hits.get(ip);
  if (!w || now > w.reset) {
    hits.set(ip, { n: 1, reset: now + 10_000 });
    return false;
  }
  w.n++;
  return w.n > 100;
}

function send(res, code, body, type = "application/json") {
  res.writeHead(code, { "content-type": type });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

const server = http.createServer((req, res) => {
  const ip = req.socket.remoteAddress || "?";
  if (limited(ip)) return send(res, 429, { error: "rate limited" });

  const u = new URL(req.url, "http://localhost");
  const p = u.pathname;

  // Product list — served from the in-memory index.
  if (p === "/products") {
    const cat = u.searchParams.get("category");
    const list = cat ? byCat.get(cat) || [] : data.products;
    return send(res, 200, { count: list.length, products: list.slice(0, 50) });
  }

  // Search — plain, safe substring match; output HTML-escaped. No code exec.
  if (p === "/search") {
    const q = (u.searchParams.get("q") || "").slice(0, 80);
    const needle = q.toLowerCase();
    const results = needle ? data.products.filter((x) => x.name.toLowerCase().includes(needle)) : [];
    return send(res, 200, `<h1>Results for ${esc(q)}</h1><p>${results.length} products</p>`, "text/html");
  }

  // Admin orders — authenticated, and PII stays server-side.
  if (p === "/admin/orders") {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (token !== ADMIN_TOKEN) return send(res, 401, { error: "unauthorized" });
    const safe = data.orders.map((o) => ({ id: o.id, total: o.total, items: o.items }));
    return send(res, 200, { orders: safe });
  }

  // Checkout — validated; no secret leakage; no per-request disk write.
  if (p === "/checkout" && req.method === "POST") {
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 10_000) req.destroy();
    });
    req.on("end", () => {
      let body = {};
      try {
        body = JSON.parse(raw || "{}");
      } catch {
        return send(res, 400, { error: "invalid JSON" });
      }
      const prod = byId.get(Number(body.productId));
      const qty = Number(body.qty);
      if (!prod) return send(res, 404, { error: "unknown product" });
      if (!Number.isInteger(qty) || qty < 1 || qty > 99)
        return send(res, 400, { error: "qty must be an integer 1–99" });
      const total = prod.price * qty;
      return send(res, 200, { ok: true, total }); // no key in the response
    });
    return;
  }

  if (p === "/" || p === "/health") return send(res, 200, { store: "hardened demo", ok: true });
  return send(res, 404, { error: "not found" });
});

const PORT = process.env.PORT || 4002;
server.listen(PORT, "127.0.0.1", () => console.log(`AFTER store on http://127.0.0.1:${PORT} [READY]`));
