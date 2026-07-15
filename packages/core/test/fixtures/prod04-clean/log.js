function handle(orderId) {
  console.log("processing order", orderId);
  logger.info("done");
}

module.exports = { handle };
