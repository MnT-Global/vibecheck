/* ============================================================================
 *  BEFORE — the "vibe-coded" store.  INTENTIONALLY VULNERABLE. Localhost only.
 *  This is the kind of code an AI codegen / no-code tool happily ships and a
 *  founder deploys — it demos fine, then breaks (and leaks) at real scale.
 *  Do NOT copy, deploy, or expose. See ../README.md.
 * ==========================================================================*/
const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const STORE = path.join(__dirname, "..", "data", "store.json");

// ⚠ Secret hardcoded in source (ends up in git history / the client bundle).
const PAYMENT_API_KEY = "sk_live_MnTfixtureFAKE";

// ⚠ Reads + parses the ENTIRE database from disk, synchronously, on EVERY
//    request. Fine with 10 products; it serializes the event loop at 4000.
function db() {
  return JSON.parse(fs.readFileSync(STORE, "utf8"));
}

function send(res, code, body, type = "application/json") {
  res.writeHead(code, { "content-type": type });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://localhost");
  const p = u.pathname;

  try {
    // Product list — re-reads + re-scans the whole DB every time.
    if (p === "/products") {
      const data = db();
      const cat = u.searchParams.get("category");
      const list = cat ? data.products.filter((x) => x.category === cat) : data.products;
      return send(res, 200, { count: list.length, products: list.slice(0, 50) });
    }

    // ⚠ INJECTION: builds a filter from user input with new Function() — remote
    //    code execution. Also ⚠ reflected XSS: echoes `q` into HTML unescaped.
    if (p === "/search") {
      const q = u.searchParams.get("q") || "";
      const data = db();
      let results = [];
      try {
        const fn = new Function("p", `return (${q === "" ? "true" : "p.name.includes('" + q + "')"})`);
        results = data.products.filter(fn);
      } catch (e) {
        return send(res, 200, `<h1>Results for ${q}</h1><p>error: ${e.message}</p>`, "text/html");
      }
      return send(
        res,
        200,
        `<h1>Results for ${q}</h1><p>${results.length} products</p>`,
        "text/html",
      );
    }

    // ⚠ BROKEN ACCESS CONTROL: "admin" order data, no authentication at all.
    if (p === "/admin/orders") {
      const data = db();
      return send(res, 200, { orders: data.orders }); // leaks emails + card_last4
    }

    // ⚠ NO INPUT VALIDATION: negative quantity → negative total (price theft).
    //    Also writes the ENTIRE DB back to disk, synchronously, per checkout.
    if (p === "/checkout" && req.method === "POST") {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        let body = {};
        try {
          body = JSON.parse(raw || "{}");
        } catch {}
        const data = db();
        const prod = data.products.find((x) => x.id === Number(body.productId));
        const qty = body.qty; // never validated
        const total = prod ? prod.price * qty : 0;
        data.orders.push({ id: data.orders.length + 1, total, items: qty });
        fs.writeFileSync(STORE, JSON.stringify(data)); // ⚠ sync write on hot path
        return send(res, 200, { ok: true, total, key: PAYMENT_API_KEY });
      });
      return;
    }

    if (p === "/" || p === "/health") return send(res, 200, { store: "vibe-coded demo", ok: true });
    return send(res, 404, { error: "not found" });
  } catch (e) {
    return send(res, 500, { error: String(e.message) });
  }
});

const PORT = process.env.PORT || 4001;
server.listen(PORT, "127.0.0.1", () => console.log(`BEFORE store on http://127.0.0.1:${PORT} [READY]`));
