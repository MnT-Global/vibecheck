const db = require("./db");

async function checkout(req, res) {
  // COM-04: a client-supplied discount subtracted from the total.
  const total = subtotal - req.body.discount;

  // PERF-03: a DB query inside a loop (N+1).
  const items = [];
  for (const id of req.body.ids) {
    items.push(await db.findOne({ id }));
  }

  // INJ-04: user-controlled property key + merge of raw request body.
  config[req.body.key] = req.body.value;
  Object.assign(settings, req.body);

  // DEP-02: HTML served with no security headers.
  res.setHeader("content-type", "text/html");
  res.end(`<h1>total ${total} for ${items.length} items</h1>`);
}

module.exports = { checkout };
