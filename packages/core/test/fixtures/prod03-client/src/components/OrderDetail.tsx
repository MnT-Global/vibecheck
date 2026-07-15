// A client-side React component. Showing err.message in a toast is normal UI, NOT a server
// leak — PROD-03 must not flag this (it used to, producing a wall of false lows on frontends).
export function OrderDetail() {
  async function updateStatus() {
    try {
      await api.updateStatus();
    } catch (error) {
      showErrorToast(error.message || "Failed to update status");
    }
  }
  return updateStatus;
}
