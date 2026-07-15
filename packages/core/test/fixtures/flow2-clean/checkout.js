const db = require("./db");
const helmet = require("helmet");
app.use(helmet());

async function checkout(req, res) {
  // discount validated server-side
  const coupon = await validateCoupon(req.body.code);
  const total = subtotal - coupon.amount;

  // batched query (no per-item loop)
  const items = await db.findMany({ id: { in: req.body.ids } });

  // fixed key; literal merge
  config.knownKey = sanitize(req.body.value);
  Object.assign(settings, { theme: "dark" });

  res.setHeader("content-type", "text/html");
  res.end(`<h1>total ${total} for ${items.length} items</h1>`);
}

module.exports = { checkout };
