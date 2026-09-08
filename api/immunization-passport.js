/**
 * POST /api/immunization-passport
 *
 * Renders a mother's Digital Immunization Passport (KEPI dose record) as a
 * PDF with an embedded QR code, uploads it to Vercel Blob, and returns a
 * plain JSON URL. Same transport pattern as odpc-report.js and mch-report.js.
 *
 * Body: { secret, motherId, motherName, babyName, dob, facility, generatedOn,
 *         doses: [{label, status, date}], format? }
 * Returns: { url, filename, bytes }
 *
 * Env vars: PASSPORT_REPORT_SECRET, BLOB_READ_WRITE_TOKEN (or blob_READ_WRITE_TOKEN)
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

    // Verification URL — scanned by schools/daycares to confirm authenticity
    const verifyUrl =
      `https://healthbridge-wa-webhook.vercel.app/api/verify` +
      `?id=${encodeURIComponent(t.motherId)}` +
      `&name=${encodeURIComponent(t.babyName)}` +
      `&dob=${encodeURIComponent(t.dob)}` +
      `&facility=${encodeURIComponent(t.facility)}` +
      `&issued=${encodeURIComponent(t.generatedOn)}`;

    const qrDataUri = await QRCode.toDataURL(verifyUrl, { margin: 1, width: 240 });

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

    // Deterministic filename keyed on motherId — enables /api/verify to locate the blob
    const filename = `Immunization-Passport-${t.motherId}.pdf`;

    const blobToken = process.env.BLOB_READ_WRITE_TOKEN || process.env.blob_READ_WRITE_TOKEN;
    if (!blobToken) {
      throw new Error(
        "No Blob token found in either BLOB_READ_WRITE_TOKEN or blob_READ_WRITE_TOKEN."
      );
    }

    const { put } = await import("@vercel/blob");
    const blob = await put(`immunization-passports/${filename}`, pdf, {
      access: "public",
      contentType: "application/pdf",
      addRandomSuffix: false,   // deterministic URL — verify endpoint depends on this
      token: blobToken,
    });

    return res.status(200).json({ url: blob.url, filename, bytes: pdf.length });
  } catch (err) {
    console.error("immunization-passport failed:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
};

module.exports.config = { maxDuration: 60 };
