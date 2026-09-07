/**
 * POST /api/immunization-passport
 *
 * Renders a mother's Digital Immunization Passport (KEPI dose record) as a
 * PDF with an embedded QR code, uploads it to Vercel Blob, and returns a
 * plain JSON URL. Same transport pattern as odpc-report.js and mch-report.js:
 * Make cannot carry raw PDF bytes without corruption, so this endpoint does
 * the rendering itself and hands back a Blob URL for Make to pull with
 * http:ActionGetFile before sending it on via WhatsApp document header.
 *
 * ---------------------------------------------------------------------------
 * Body:
 * {
 *   "secret": "<PASSPORT_REPORT_SECRET>",
 *   "motherId": "MCH-2026-xxxxxxxx",
 *   "motherName": "Jane Doe",
 *   "babyName": "Baby Doe",
 *   "dob": "12/08/2026",
 *   "facility": "Example Hospital",
 *   "generatedOn": "6 September 2026",
 *   "doses": [
 *     { "label": "BCG / OPV-0 (birth)", "status": "given", "date": "12/08/2026" },
 *     { "label": "6-week: Penta-1, OPV-1, PCV10-1, Rota-1", "status": "given", "date": "24/09/2026" },
 *     { "label": "10-week: Penta-2, OPV-2, PCV10-2, Rota-2", "status": "due", "date": "" }
 *   ]
 * }
 *
 * "status" is "given" or "due". Rows are rendered in the order supplied —
 * Make should send all applicable KEPI stages, birth through 18 months,
 * whether or not each has been given yet.
 *
 * Returns:
 * { "url": "...", "filename": "Immunization-Passport-Baby-Doe.pdf", "bytes": 12345 }
 *
 * Env vars required:
 *   PASSPORT_REPORT_SECRET  shared secret, must match what Make sends
 *   BLOB_READ_WRITE_TOKEN   (or blob_READ_WRITE_TOKEN) — same Blob store as mch-report/odpc-report
 *
 * Vercel project settings required: same project as odpc-report.js/mch-report.js.
 * package.json needs "qrcode" added as a dependency (no native deps, pure JS).
 *
 * QR code content is a plain verification string (record ID, child's name,
 * DOB) — not a link to a live verification page. Standing that page up is a
 * later enhancement; v1 keeps the scope to "produce a trustworthy-looking,
 * presentable record", which is what schools/daycares actually need.
 */

const fs = require("fs");
const path = require("path");

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function buildDoseRows(doses) {
  if (!Array.isArray(doses) || !doses.length) {
    return `<tr><td colspan="3" style="color:#94A3B8;">No dose records available yet.</td></tr>`;
  }
  return doses
    .map((d) => {
      const given = String(d.status || "").toLowerCase() === "given";
      const statusHtml = given
        ? `<span class="status-given">Given</span>`
        : `<span class="status-due">Due</span>`;
      const dateHtml = given ? esc(d.date || "") : "—";
      return `<tr>
        <td>${esc(d.label || "")}</td>
        <td class="num">${statusHtml}</td>
        <td class="date">${dateHtml}</td>
      </tr>`;
    })
    .join("\n");
}

function fillTemplate(tokens) {
  const tplPath = path.join(process.cwd(), "templates", "immunization-passport-template.html");
  let html = fs.readFileSync(tplPath, "utf-8");
  for (const [k, val] of Object.entries(tokens)) {
    html = html.split(`{{${k}}}`).join(String(val));
  }
  const leftover = [...new Set((html.match(/\{\{[A-Z0-9_]+\}\}/g) || []))];
  if (leftover.length) throw new Error(`Unfilled tokens: ${leftover.join(", ")}`);
  return html;
}

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
    return await page.pdf({ format: "A4", printBackground: true, preferCSSPageSize: true });
  } finally {
    await browser.close();
  }
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "POST only" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;

    if (!process.env.PASSPORT_REPORT_SECRET || body.secret !== process.env.PASSPORT_REPORT_SECRET) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const t = {
      motherId: body.motherId || "",
      motherName: body.motherName || "",
      babyName: body.babyName || "Baby",
      dob: body.dob || "",
      facility: body.facility || "",
      generatedOn: body.generatedOn || "",
      doses: Array.isArray(body.doses) ? body.doses : [],
    };

    const QRCode = require("qrcode");
    const qrText =
      `HealthBridge KEPI Record | ${t.motherId} | ${t.babyName} | DOB ${t.dob} | ${t.facility}`;
    const qrDataUri = await QRCode.toDataURL(qrText, { margin: 1, width: 240 });

    const tokens = {
      BABY_NAME: esc(t.babyName),
      DOB: esc(t.dob),
      MOTHER_NAME: esc(t.motherName),
      FACILITY: esc(t.facility),
      MOTHER_ID: esc(t.motherId),
      GENERATED_ON: esc(t.generatedOn),
      QR_DATA_URI: qrDataUri,
      DOSE_ROWS: buildDoseRows(t.doses),
    };

    const html = fillTemplate(tokens);

    if (body.format === "html") {
      res.setHeader("content-type", "text/html; charset=utf-8");
      return res.status(200).send(html);
    }

    const pdf = await toPdf(html);

    const safeBaby = String(t.babyName || "Baby").replace(/\s+/g, "-");
    const filename = `Immunization-Passport-${safeBaby}.pdf`;

    const blobToken = process.env.BLOB_READ_WRITE_TOKEN || process.env.blob_READ_WRITE_TOKEN;
    if (!blobToken) {
      throw new Error(
        "No Blob token found in either BLOB_READ_WRITE_TOKEN or blob_READ_WRITE_TOKEN. " +
        "Same store as mch-report.js/odpc-report.js (mchblob) — confirm it's linked to this project too."
      );
    }

    const { put } = await import("@vercel/blob");
    const blob = await put(`immunization-passports/${filename}`, pdf, {
      access: "public",
      contentType: "application/pdf",
      addRandomSuffix: true,
      token: blobToken,
    });

    return res.status(200).json({ url: blob.url, filename, bytes: pdf.length });
  } catch (err) {
    console.error("immunization-passport failed:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
};

module.exports.config = { maxDuration: 60 };
