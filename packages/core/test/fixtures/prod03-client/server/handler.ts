// A server request handler. Returning err.message in the HTTP response IS a real leak —
// PROD-03 must still flag this even after we start skipping client files.
export async function handler(req: Request, res: Response) {
  try {
    await doWork();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
