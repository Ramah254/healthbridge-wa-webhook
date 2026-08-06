import crypto from "crypto";

export const config = {
  api: {
    bodyParser: false
  }
};

// ── System-aware routing tables ─────────────────────────────────────────────
// Button texts unique to one system route to that system only.
// Anything ambiguous, shared, or free text still goes to both.
// All matching is case-insensitive and trimmed.

const MCH_ONLY_BUTTONS = new Set([
  // English (T1 to T8)
  "confirmed", "ask a question", "contact clinic",
  "i'm doing well", "have concerns",
  "baby has arrived", "not yet",
  "vaccines given", "not given yet",
  "doing well",
  "yes i will attend", "need to reschedule",
  "i am okay", "need support",
  // Swahili (T1 to T8)
  "nimethibitisha", "uliza swali", "wasiliana na kliniki",
  "niko salama", "nina wasiwasi", "nipigie simu",
  "mtoto amezaliwa", "bado", "nahitaji msaada",
  "amepata chanjo", "bado hajapata",
  "naendelea vizuri",
  "nitahudhuria", "nahitaji kuahirisha",
  "niko sawa", "nashukuru", "nahitaji kuongea",
  
  // New additions from PART D
  "rebook my visit",
  "already attended",
  "delivery plan confirmed",
  "need help planning",
  "ndiyo nitahudhuria",
  "nahitaji kubadilisha",
  "nipigiwe simu",
  "panga ziara upya",
  "nilishahudhuria",
  "mpango umethibitishwa"
]);

const OPD_ONLY_BUTTONS = new Set([
  "improving", "not improving",
  "treatment working", "still have symptoms"
]);

// "i am fine", "need assistance", "request callback", "callback" and any
// unrecognized button stay shared. They exist or may exist in both systems.

function normalize(text) {
  return (text || "").trim().toLowerCase();
}

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
    // Silent. Meta already received 200
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
  // Button replies unique to one system route to that system only.
  // Free text, opt-outs and unknown buttons go to both.
  if (message) {
    const buttonText =
      message?.button?.text ||
      message?.interactive?.button_reply?.title ||
      message?.interactive?.list_reply?.title ||
      null;

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
      context_id: message?.context?.id || null,
      timestamp: message.timestamp || null
    };

    const norm = normalize(buttonText);
    let inboundTargets;
    if (norm && MCH_ONLY_BUTTONS.has(norm)) {
      inboundTargets = [process.env.MCH_WEBHOOK_URL];
    } else if (norm && OPD_ONLY_BUTTONS.has(norm)) {
      inboundTargets = [process.env.OPD_WEBHOOK_URL];
    } else {
      inboundTargets = [
        process.env.MCH_WEBHOOK_URL,
        process.env.OPD_WEBHOOK_URL
      ];
    }
    inboundTargets = inboundTargets.filter(Boolean);

    await Promise.all(inboundTargets.map(url => forwardToWebhook(url, inboundPayload)));
  }

  // ── STATUS UPDATE ─────────────────────────────────────────────────────────
  if (status) {
    const statusType = status?.status;

    // "sent" and "read" dropped here. Zero Make ops consumed
    if (statusType === "sent" || statusType === "read") {
      return res.status(200).send("EVENT_RECEIVED");
    }

    // "delivered" and "failed" route by biz_opaque_callback_data.
    // Make outbound sends will stamp "MCH" or "OPD" on every message.
    // Until that lands, or if the field is absent, fall back to both.
    if (statusType === "delivered" || statusType === "failed") {
      const statusPayload = {
        event_time: new Date().toISOString(),
        status: statusType,
        message_id: status.id || null,              // MetaMessageSID, row lookup key
        recipient_id: status.recipient_id || null,  // patient phone number
        timestamp: status.timestamp || null,
        error_code: status?.errors?.[0]?.code || null,   // e.g. 131026 undeliverable
        error_title: status?.errors?.[0]?.title || null,
        biz_data: status?.biz_opaque_callback_data || null
      };

      const bizData = normalize(status?.biz_opaque_callback_data);
      let statusTargets;
      if (bizData === "mch") {
        statusTargets = [process.env.MCH_STATUS_WEBHOOK_URL];
      } else if (bizData === "opd") {
        statusTargets = [process.env.OPD_STATUS_WEBHOOK_URL];
      } else {
        statusTargets = [
          process.env.MCH_STATUS_WEBHOOK_URL,
          process.env.OPD_STATUS_WEBHOOK_URL
        ];
      }
      statusTargets = statusTargets.filter(Boolean);

      await Promise.all(statusTargets.map(url => forwardToWebhook(url, statusPayload)));
    }
  }

  return res.status(200).send("EVENT_RECEIVED");
}
