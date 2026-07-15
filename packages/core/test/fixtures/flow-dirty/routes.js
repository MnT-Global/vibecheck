// A checkout/API file with several flow-tier vulnerabilities.
const db = require("./db");

async function checkout(req, res) {
  // COM-01: total computed from a client-supplied price.
  const total = req.body.price * req.body.qty;

  // INJ-02: query built by interpolation.
  const rows = await db.query(`SELECT * FROM orders WHERE user = '${req.body.user}'`);

  // WEB-02: server fetches a user-supplied URL.
  const hook = await fetch(req.body.callbackUrl);

  // WEB-03: user-controlled path served from disk.
  res.sendFile(path.join(__dirname, "invoices", req.query.file));

  return { total, rows, hook };
}

module.exports = { checkout };
