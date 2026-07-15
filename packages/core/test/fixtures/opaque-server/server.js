// Server code that routes via an opaque handler map — not statically mappable.
const http = require("http");
const handlers = require("./handlers");

const server = http.createServer((req, res) => {
  const fn = handlers[req.url];
  if (fn) return fn(req, res);
  res.end("not found");
});

server.listen(3000);
