import crypto from "crypto";

export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
  const APP_SECRET = process.env.META_APP_SECRET;
  const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

  if (req.method === "GET") {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    if (mode === "subscribe" && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(403).send("Verification failed");
  }

  if (req.method === "POST") {
    const signature = req.headers["x-hub-signature-256"];
    const rawBody =
      typeof req.body === "string" ? req.body : JSON.stringify(req.body);

    if (!signature) return res.status(400).send("Missing signature");

    const expected =
      "sha256=" +
      crypto.createHmac("sha256", APP_SECRET).update(rawBody).digest("hex");

    if (signature !== expected) {
      return res.status(403).send("Invalid signature");
    }

    const body = req.body;
    const change = body?.entry?.[0]?.changes?.[0]?.value || {};
    const message = change?.messages?.[0] || null;
    const contact = change?.contacts?.[0] || null;
    const status = change?.statuses?.[0] || null;

    const cleanedPayload = {
      object: body?.object || null,
      event_time: new Date().toISOString(),
      from: message?.from || status?.recipient_id || null,
      profile_name: contact?.profile?.name || null,
      message_id: message?.id || status?.id || null,
      message_type: message?.type || null,
      text: message?.text?.body || null,
      button_reply_id: message?.button?.payload || null,
      button_reply_text: message?.button?.text || null,
      interactive_reply_id:
        message?.interactive?.button_reply?.id ||
        message?.interactive?.list_reply?.id ||
        null,
      interactive_reply_title:
        message?.interactive?.button_reply?.title ||
        message?.interactive?.list_reply?.title ||
        null,
      status: status?.status || null,
      timestamp: message?.timestamp || status?.timestamp || null,
      raw_minimal: change
    };

    if (MAKE_WEBHOOK_URL) {
      await fetch(MAKE_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cleanedPayload)
      });
    }

    return res.status(200).send("EVENT_RECEIVED");
  }

  return res.status(405).send("Method not allowed");
}
