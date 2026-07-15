const { execSync } = require("child_process");

function convert(file) {
  return execSync("convert " + file + " out.png");
}

module.exports = { convert };
