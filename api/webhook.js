export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
  const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

  if (req.method === "GET") {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    if (mode === "subscribe" && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }

    return res.status(403).send("Forbidden");
  }

  if (req.method === "POST") {
    try {
      const body = req.body;

      if (MAKE_WEBHOOK_URL) {
        await fetch(MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      }

      return res.status(200).send("EVENT_RECEIVED");
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }

  return res.status(405).send("Method Not Allowed");
}
