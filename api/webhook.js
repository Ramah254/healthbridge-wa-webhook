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

    req.on("data", (chunk) => {
      data += chunk;
    });

    req.on("end", () => {
      resolve(data);
    });

    req.on("error", reject);
  });
}

function safeEqual(a, b) {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");

  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
  const APP_SECRET = process.env.META_APP_SECRET;
  
  // We no longer rely on just one webhook URL
  // We will dynamically check process.env later

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

  const cleanedPayload = {
    object: body?.object || null,
    event_time: new Date().toISOString(),
    from: message?.from || status?.recipient_id || null,
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
    timestamp: message?.timestamp || status?.timestamp || null
  };

  // Build an array of webhooks to trigger
  const webhooks = [];
  
  if (process.env.MAKE_WEBHOOK_URL) {
    webhooks.push(process.env.MAKE_WEBHOOK_URL);
  }
  
  if (process.env.MCH_WEBHOOK_URL) {
    webhooks.push(process.env.MCH_WEBHOOK_URL);
  }

  // Forward to all available webhooks concurrently
  if (webhooks.length > 0) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      await Promise.all(
        webhooks.map((url) =>
          fetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify(cleanedPayload),
            signal: controller.signal
          }).catch((err) => {
            console.error(`Error forwarding to ${url}:`, err.message);
          })
        )
      );

      clearTimeout(timeout);
    } catch (error) {
      console.error("Webhook forwarding error:", error.message);
    }
  }

  return res.status(200).send("EVENT_RECEIVED");
}
