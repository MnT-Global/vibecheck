// The hardened equivalent — nothing trusts raw request input.
const db = require("./db");
const ALLOWED_HOSTS = new Set(["hooks.example.com"]);

async function checkout(req, res) {
  // price looked up server-side; quantity validated
  const product = await db.getProduct(req.body.productId);
  const qty = Number(req.body.qty);
  const total = product.price * qty;

  // parameterized query
  const rows = await db.query("SELECT * FROM orders WHERE user = $1", [req.body.user]);

  // fetch only allowlisted hosts
  const url = new URL(req.body.callbackUrl);
  const hook = ALLOWED_HOSTS.has(url.host) ? await fetch(url) : null;

  // fixed, non-user path
  res.sendFile(path.join(__dirname, "invoices", "latest.pdf"));

  return { total, rows, hook };
}

module.exports = { checkout };
