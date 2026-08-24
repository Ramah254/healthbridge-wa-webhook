/**
 * POST /api/mch-report
 *
 * Turns two Monthly_Metrics rows into the finished HealthBridge MCH monthly
 * PDF, uploads it to Vercel Blob storage, and returns a plain JSON object
 * containing a public URL.
 *
 * ---------------------------------------------------------------------------
 * WHY IT WORKS THIS WAY (do not "simplify" this back to returning the PDF)
 * ---------------------------------------------------------------------------
 * Make.com could not be made to carry the PDF bytes from this endpoint into
 * the Google Drive upload module. Three different transports were tried and
 * each one corrupted the file in a different way:
 *
 *   1. Raw binary response  + {{160.data}}
 *        -> Drive received: {"0":37,"1":80,"2":68,...}   (JSON byte map)
 *   2. JSON {pdfBase64}     + {{160.data.pdfBase64}}
 *        -> Drive received: 37,80,68,70,45,...           (comma-joined ints)
 *   3. Plain base64 body    + {{toBinary(160.data; "base64")}}
 *        -> Drive received: 147267 bytes of binary garbage (length preserved,
 *           contents wrong -- a 1:1 mis-encoding of the base64 text)
 *
 * All three are Make coercing a buffer through generic stringification. Rather
 * than keep guessing at its internals, this version takes Make out of the
 * binary path completely: the PDF never travels through a Make module as data.
 * Vercel writes the file to Blob storage and hands Make a URL, which is just
 * text. Make then uses its "Get a File" HTTP module -- purpose-built to fetch
 * a URL into a proper Make file buffer -- and passes that to Google Drive.
 * Each tool does the job it was designed for.
 *
 * ---------------------------------------------------------------------------
 * Body:
 * {
 *   "secret":   "<MCH_REPORT_SECRET>",
 *   "meta":     { facility, reportMonth, nextMonth, preparedFor, generatedOn },
 *   "current":  { ...Monthly_Metrics row for the reporting month },
 *   "previous": { ...Monthly_Metrics row for the month before },
 *   "format":   "pdf" | "html"        // html returns the markup, for design work
 * }
 *
 * Returns (format "pdf"):
 * {
 *   "url":      "https://<blob-host>/mch-reports/....pdf",
 *   "filename": "MCH-Impact-Report-July-2026.pdf",
 *   "bytes":    112233
 * }
 *
 * Env vars required:
 *   MCH_REPORT_SECRET      shared secret, must match what Make sends
 *   ANTHROPIC_API_KEY      used to draft the narrative sections
 *   BLOB_READ_WRITE_TOKEN  auto-injected by Vercel once a Blob store is
 *                          connected to the project (Storage tab -> Blob)
 *
 * Vercel project settings required:
 *   Node.js Version = 22.x or later (@sparticuz/chromium 147+ requires it).
 */

const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------- helpers

const pct = (n, d) => (!d ? 0 : Math.round((100 * n) / d));

const num = (v) => Number(v || 0);

/** Long form used on the KPI cards. */
function delta(cur, prev, unit, inverted) {
  const d = cur - prev;
  if (d === 0) return { text: "No change", cls: "flat" };
  const sign = d > 0 ? "+" : "\u2212";
  let cls = d > 0 ? "up" : "down";
  if (inverted) cls = cls === "up" ? "down" : "up";
  return { text: `${sign}${Math.abs(d)}${unit} vs last month`, cls };
}

/** Compact form used in the Change column of the table. */
function short(cur, prev, unit) {
  const d = cur - prev;
  if (d === 0) return "\u2013";
  return `${d > 0 ? "+" : "\u2212"}${Math.abs(d)}${unit}`;
}

// token -> [sourceKey, unit, invertedDirection]
const SPEC = {
  ACTIVE_MOTHERS: ["ActiveMothers", "", false],
  NEW_ENROLLMENTS: ["NewEnrollments", "", false],
  MESSAGES_SENT: ["MessagesSent", "", false],
  RESPONSE_RATE: ["ResponseRate", "%", false],
  REMINDERS_SENT: ["RemindersSent", "", false],
  ATTENDANCE_RATE: ["AttendanceRate", "%", false],
  NOSHOW_RATE: ["NoShowRate", "%", true],
  NOSHOWS_RECOVERED: ["NoShowsRecovered", "", false],
  IMMUNIZATION_REMINDERS: ["ImmunizationReminders", "", false],
  DELIVERIES_CONFIRMED: ["DeliveriesConfirmed", "", false],
  FACILITY_SHARE: ["FacilityShare", "%", false],
  FACILITY_DELIVERIES: ["FacilityDeliveries", "", false],
  ESCALATIONS: ["Escalations", "", false],
  DANGER_SIGNS: ["DangerSignAlerts", "", false],
  OPT_OUTS: ["OptOuts", "", true],
};

/** Adds the rates that Monthly_Metrics does not store directly. */
function derive(row) {
  const r = {};
  for (const k of Object.keys(row)) r[k] = num(row[k]);
  r.AttendanceRate = pct(r.AttendanceConfirmed, r.RemindersSent);
  r.NoShowRate = pct(r.NoShows, r.RemindersSent);
  r.FacilityShare = pct(r.FacilityDeliveries, r.DeliveriesConfirmed);
  return r;
}

function buildTokens(cur, prev) {
  const v = {};
  for (const [token, [key, unit, inverted]] of Object.entries(SPEC)) {
    const c = cur[key];
    const p = prev[key];
    const d = delta(c, p, unit, inverted);
    v[token] = c.toLocaleString("en-KE");
    v[`${token}_PREV`] = p.toLocaleString("en-KE");
    v[`${token}_DELTA`] = d.text;
    v[`${token}_CLASS`] = d.cls;
    v[`${token}_SHORT`] = short(c, p, unit);
  }
  // Escalations and danger signs are directionally ambiguous: more could mean
  // better detection, fewer could mean fewer emergencies. Show them uncoloured
  // rather than implying a verdict the number does not support.
  v.ESCALATIONS_CLASS = "flat";
  v.DANGER_SIGNS_CLASS = "flat";
  v.REVENUE = cur.EstimatedRevenueKES.toLocaleString("en-KE");
  return v;
}

// ---------------------------------------------------------------- narrative

const NARRATIVE_KEYS = [
  "HEADLINE", "CHANGED_TITLE", "CHANGED_BODY", "REVENUE_NOTE", "SIGNOFF",
  "ACTIVE_MOTHERS_MEAN", "NEW_ENROLLMENTS_MEAN", "MESSAGES_SENT_MEAN",
  "RESPONSE_RATE_MEAN", "REMINDERS_SENT_MEAN", "ATTENDANCE_RATE_MEAN",
  "NOSHOW_RATE_MEAN", "NOSHOWS_RECOVERED_MEAN", "IMMUNIZATION_REMINDERS_MEAN",
  "DELIVERIES_CONFIRMED_MEAN", "FACILITY_SHARE_MEAN", "ESCALATIONS_MEAN",
  "DANGER_SIGNS_MEAN", "OPT_OUTS_MEAN",
  "ACTION_1_TITLE", "ACTION_1_BODY",
  "ACTION_2_TITLE", "ACTION_2_BODY",
  "ACTION_3_TITLE", "ACTION_3_BODY",
];

const SYSTEM_PROMPT = `You write the written sections of HealthBridge Solutions' monthly MCH
follow-up report. The reader is the medical director of a Kenyan private hospital. The author is
Ramadhan Omar, a Registered Nurse and the founder of HealthBridge.

Rules:
- Use ONLY the numbers supplied. Never invent a figure, a cause, or a patient detail.
- Where you assert a cause, mark it as a reading of the data, not a fact.
- Plain professional English. No marketing language, no exclamation marks, no em dashes.
- If a number moved the wrong way, say so plainly. Do not spin it.
- If the month was flat or the caseload is tiny, say that rather than manufacturing a story.
- HEADLINE and CHANGED_TITLE are spoken sentences, not headers. Sentence case only (capitalise
  only the first word and proper nouns). Never title-case them, never format them as a label
  followed by a colon, and never restate the month/facility/report name in them.
  Bad:  "July 2026 MCH Follow-Up Report: No Messaging Activity on a Caseload of 13 Active Mothers"
  Bad:  "Key Changes from June to July 2026"
  Good: "No messages went out in July despite a growing caseload."
  Good: "Enrollment stopped and escalations spiked with no messages sent to explain them."
  Say the single most important thing that happened, the way you'd say it out loud to the
  director, not the way you'd title a slide.
- CHANGED_BODY must be 2 to 3 <p> paragraphs of raw HTML, no other tags.
- Every *_MEAN is one or two sentences, max 22 words, no HTML.
- Each ACTION_*_BODY is 2 to 4 sentences and must reference a specific number from the data.
- SIGNOFF is a short personal close from Ramadhan to the director, 3 to 4 sentences.
- Return ONLY a JSON object with exactly these keys, no preamble and no markdown fences:
${NARRATIVE_KEYS.join(", ")}`;

async function draftNarrative(meta, cur, prev) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 4000,
      system: SYSTEM_PROMPT,
      messages: [{
        role: "user",
        content:
          `Facility: ${meta.facility}\nReporting month: ${meta.reportMonth}\n` +
          `Next month: ${meta.nextMonth}\nPrepared for: ${meta.preparedFor}\n\n` +
          `THIS MONTH:\n${JSON.stringify(cur, null, 2)}\n\n` +
          `LAST MONTH:\n${JSON.stringify(prev, null, 2)}`,
      }],
    }),
  });

  if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  const text = data.content.filter(b => b.type === "text").map(b => b.text).join("");
  const clean = text.replace(/```json|```/g, "").trim();

  let parsed;
  try {
    parsed = JSON.parse(clean);
  } catch (e) {
    throw new Error(`Narrative was not valid JSON: ${clean.slice(0, 400)}`);
  }
  const missing = NARRATIVE_KEYS.filter(k => !parsed[k]);
  if (missing.length) throw new Error(`Narrative missing keys: ${missing.join(", ")}`);
  return parsed;
}

// ---------------------------------------------------------------- render

function fillTemplate(tokens) {
  const tplPath = path.join(process.cwd(), "templates", "mch-report-template.html");
  let html = fs.readFileSync(tplPath, "utf-8");

  // The Change column uses the compact delta; swap those in before the generic pass.
  for (const token of Object.keys(SPEC)) {
    html = html.replace(
      `class="chg {{${token}_CLASS}}">{{${token}_DELTA}}`,
      `class="chg {{${token}_CLASS}}">${tokens[`${token}_SHORT`]}`
    );
  }
  for (const [k, val] of Object.entries(tokens)) {
    html = html.split(`{{${k}}}`).join(String(val));
  }

  const leftover = [...new Set((html.match(/\{\{[A-Z0-9_]+\}\}/g) || []))];
  if (leftover.length) throw new Error(`Unfilled tokens: ${leftover.join(", ")}`);
  return html;
}

/**
 * Chromium and puppeteer-core are loaded lazily. @sparticuz/chromium 147+ is
 * ESM-only, so a top-level require() would crash the function on cold start
 * even for requests that never render a PDF.
 */
async function toPdf(html) {
  const { default: chromium } = await import("@sparticuz/chromium");
  const { default: puppeteer } = await import("puppeteer-core");

  const browser = await puppeteer.launch({
    args: chromium.args,
    defaultViewport: chromium.defaultViewport,
    executablePath: await chromium.executablePath(),
    headless: chromium.headless,
  });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });
    return await page.pdf({
      format: "A4",
      printBackground: true,
      preferCSSPageSize: true,
    });
  } finally {
    await browser.close();
  }
}

// ---------------------------------------------------------------- handler

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "POST only" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;

    if (!process.env.MCH_REPORT_SECRET || body.secret !== process.env.MCH_REPORT_SECRET) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const meta = body.meta || {};
    const cur = derive(body.current || {});
    const prev = derive(body.previous || {});

    const narrative = await draftNarrative(meta, cur, prev);

    const tokens = {
      ...buildTokens(cur, prev),
      ...narrative,
      FACILITY: meta.facility,
      REPORT_MONTH: meta.reportMonth,
      NEXT_MONTH: meta.nextMonth,
      PREPARED_FOR: meta.preparedFor,
      GENERATED_ON: meta.generatedOn,
    };

    const html = fillTemplate(tokens);

    if (body.format === "html") {
      res.setHeader("content-type", "text/html; charset=utf-8");
      return res.status(200).send(html);
    }

    const pdf = await toPdf(html);

    const safeMonth = String(meta.reportMonth || "report").replace(/\s+/g, "-");
    const filename = `MCH-Impact-Report-${safeMonth}.pdf`;

    // Upload to Blob storage and hand back a URL. Vercel's auto-injected env
    // var name for a connected store isn't always the plain BLOB_READ_WRITE_TOKEN
    // -- it can be store-prefixed (e.g. blob_READ_WRITE_TOKEN). Check both
    // rather than betting on one.
    const blobToken = process.env.BLOB_READ_WRITE_TOKEN || process.env.blob_READ_WRITE_TOKEN;
    if (!blobToken) {
      throw new Error(
        "No Blob token found in either BLOB_READ_WRITE_TOKEN or blob_READ_WRITE_TOKEN. " +
        "Check Vercel -> Storage -> mchblob -> .env.local tab for the exact variable name, " +
        "and confirm it's set under Settings -> Environment Variables for Production."
      );
    }

    // addRandomSuffix keeps re-runs for the same month from overwriting each
    // other, which matters while testing and is harmless in production.
    const { put } = await import("@vercel/blob");
    const blob = await put(`mch-reports/${filename}`, pdf, {
      access: "public",
      contentType: "application/pdf",
      addRandomSuffix: true,
      token: blobToken,
    });

    return res.status(200).json({
      url: blob.url,
      filename,
      bytes: pdf.length,
    });
  } catch (err) {
    console.error("mch-report failed:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
};

module.exports.config = { maxDuration: 60 };
