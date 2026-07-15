const authToken = process.env.STRIPE_SECRET_KEY;

function handle() {
  console.log("using key", process.env.STRIPE_SECRET_KEY);
  logger.info("auth token is", authToken);
}

module.exports = { handle };
