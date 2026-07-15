const express = require("express");
const app = express();

app.get("/health", (req, res) => res.json({ ok: true }));
app.post("/admin/orders", (req, res) => res.json({ orders: [] }));
app.delete("/users/:id", (req, res) => res.json({ deleted: true }));

app.listen(3000);
