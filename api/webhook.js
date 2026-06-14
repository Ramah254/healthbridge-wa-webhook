import crypto from "crypto";

export const config = {
  api: {
    bodyParser: false
  }
};

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => { data += chunk; });
    req.on("end", () => { resolve(data); });
    req.on("error", reject);
  });
}

function safeEqual(a, b) {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

async function forwardToWebhook(url, payload) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
  } catch {
    // Silent — Meta already received 200
  } finally {
    clearTimeout(timeout);
  }
}

export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
  const APP_SECRET = process.env.META_APP_SECRET;

  // ── GET: Meta verification handshake ─────────────────────────────────────
  if (req.method === "GET") {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];
    if (mode === "subscribe" && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(403).send("Verification failed");
  }

  if (req.method !== "POST") {
    return res.status(405).send("Method not allowed");
  }

  if (!APP_SECRET) {
    return res.status(500).send("Server misconfigured");
  }

  // ── Signature verification ────────────────────────────────────────────────
  const signature = req.headers["x-hub-signature-256"];
  if (!signature) {
    return res.status(400).send("Missing signature");
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch {
    return res.status(400).send("Unable to read request body");
  }

  const expectedSignature =
    "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(rawBody).digest("hex");

  if (!safeEqual(signature, expectedSignature)) {
    return res.status(403).send("Invalid signature");
  }

  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return res.status(400).send("Invalid JSON");
  }

  const change = body?.entry?.[0]?.changes?.[0]?.value || {};
  const message = change?.messages?.[0] || null;
  const status = change?.statuses?.[0] || null;

  // ── INBOUND MESSAGE ───────────────────────────────────────────────────────
  // Forward to BOTH MCH and OPD inbound scenarios.
  // Each Make scenario checks if the phone number belongs to their patients
  // and exits silently if not — no double processing.
  if (message) {
    const inboundPayload = {
      object: body?.object || null,
      event_time: new Date().toISOString(),
      from: message.from || null,
      message_id: message.id || null,
      message_type: message.type || null,
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
      timestamp: message.timestamp || null
    };

    const inboundTargets = [
      process.env.MCH_WEBHOOK_URL,
      process.env.OPD_WEBHOOK_URL
    ].filter(Boolean);

    await Promise.all(inboundTargets.map(url => forwardToWebhook(url, inboundPayload)));
  }

  // ── STATUS UPDATE ─────────────────────────────────────────────────────────
  if (status) {
    const statusType = status?.status;

    // "sent" and "read" dropped here — zero Make ops consumed
    if (statusType === "sent" || statusType === "read") {
      return res.status(200).send("EVENT_RECEIVED");
    }

    // "delivered" and "failed" go to the shared Status Handler scenario
    // That one scenario searches MCH + OPD sheets by MetaMessageSID
    if (statusType === "delivered" || statusType === "failed") {
      const statusPayload = {
        event_time: new Date().toISOString(),
        status: statusType,
        message_id: status.id || null,              // MetaMessageSID — row lookup key
        recipient_id: status.recipient_id || null,  // patient phone number
        timestamp: status.timestamp || null,
        error_code: status?.errors?.[0]?.code || null,   // e.g. 131026 undeliverable
        error_title: status?.errors?.[0]?.title || null
      };

      const statusTargets = [
  process.env.MCH_STATUS_WEBHOOK_URL,
  process.env.OPD_STATUS_WEBHOOK_URL
].filter(Boolean);
await Promise.all(statusTargets.map(url => forwardToWebhook(url, statusPayload)));
    }
  }

  return res.status(200).send("EVENT_RECEIVED");
}
