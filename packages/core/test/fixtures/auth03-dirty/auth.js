const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "sup3r-admin-9000";

function login(req) {
  const password = req.body.password;
  if (password === "hunter2secret") return true;
  return false;
}

module.exports = { ADMIN_TOKEN, login };
