const { execFile } = require("child_process");

// A regex .exec on user input must NOT be flagged as command injection.
const NAME = /^[a-z0-9_-]+$/i;

function convert(file) {
  if (!NAME.exec(file)) throw new Error("bad name");
  return execFile("convert", [file, "out.png"]);
}

module.exports = { convert };
