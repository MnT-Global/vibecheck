const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

function login(req, storedHash) {
  const password = req.body.password;
  return verify(password, storedHash);
}

module.exports = { ADMIN_TOKEN, login };
