/**
 * POST /api/moh711-report
 *
 * Renders a DRAFT MOH 711A pre-fill (ANC/PMTCT + Maternity sections only)
 * as a PDF and uploads it to Vercel Blob storage, returning a plain JSON URL.
 *
 * Deliberately a thin slice: HealthBridge only tracks ANC attendance and
 * deliveries. Family Planning, PMTCT/HIV, STI, TB, Blood Safety, ART, VCT,
 * CHANIS, delivery mode/outcomes/complications/deaths are NOT populated —
 * the PDF says so explicitly and is watermarked DRAFT — PENDING HRIO REVIEW.
 * The HRIO reconciles this against their own KHIS/DHIS2 screen before
 * submitting anything to a government system. Same transport pattern as
 * odpc-report.js and mch-report.js (Make cannot carry raw PDF bytes).
 *
 * Body:
 * {
 *   "secret": "<MOH711_REPORT_SECRET>",
 *   "facility": "Example Hospital",
 *   "month": "September 2026",
 *   "reportDate": "8 September 2026",
 *   "ancNew": 12, "ancRevisit": 34, "ancTotal": 46, "anc4thVisit": 9,
 *   "iptp1": "0", "iptp2": "0", "iptp3": "0",
 *   "totalDeliveries": 5,
 *   "format": "pdf" | "html"
 * }
 *
 * Returns: { "url": "...", "filename": "MOH711-DRAFT-...", "bytes": 54321 }
 *
 * Env vars: MOH711_REPORT_SECRET, BLOB_READ_WRITE_TOKEN (or blob_READ_WRITE_TOKEN)
 */

const fs = require("fs");
const path = require("path");

const num = (v) => Number(v || 0);

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function fillTemplate(tokens) {
  const tplPath = path.join(process.cwd(), "templates", "moh711-report-template.html");
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
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;

    if (!process.env.MOH711_REPORT_SECRET || body.secret !== process.env.MOH711_REPORT_SECRET) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const t = {
      facility: body.facility || "",
      month: body.month || "",
      reportDate: body.reportDate || "",
      ancNew: num(body.ancNew),
      ancRevisit: num(body.ancRevisit),
      ancTotal: num(body.ancTotal),
      anc4thVisit: num(body.anc4thVisit),
      iptp1: body.iptp1 || "0",
      iptp2: body.iptp2 || "0",
      iptp3: body.iptp3 || "0",
      totalDeliveries: num(body.totalDeliveries),
    };

    const iptpTracked = !/NOT TRACKED/i.test(String(t.iptp1));

    const tokens = {
      FACILITY: esc(t.facility),
      MONTH: esc(t.month),
      REPORT_DATE: esc(t.reportDate),
      ANC_NEW: t.ancNew,
      ANC_REVISIT: t.ancRevisit,
      ANC_TOTAL: t.ancTotal,
      ANC_4TH_VISIT: t.anc4thVisit,
      IPTP1: esc(t.iptp1),
      IPTP2: esc(t.iptp2),
      IPTP3: esc(t.iptp3),
      IPTP_ROW_CLASS: iptpTracked ? "ok" : "warn",
      TOTAL_DELIVERIES: t.totalDeliveries,
    };

    const html = fillTemplate(tokens);

    if (body.format === "html") {
      res.setHeader("content-type", "text/html; charset=utf-8");
      return res.status(200).send(html);
    }

    const pdf = await toPdf(html);
    const safeFacility = String(t.facility || "facility").replace(/\s+/g, "-");
    const safeMonth = String(t.month || "report").replace(/\s+/g, "-");
    const filename = `MOH711-DRAFT-${safeFacility}-${safeMonth}.pdf`;

    const blobToken = process.env.BLOB_READ_WRITE_TOKEN || process.env.blob_READ_WRITE_TOKEN;
    if (!blobToken) throw new Error("No Blob token found.");

    const { put } = await import("@vercel/blob");
    const blob = await put(`moh711-reports/${filename}`, pdf, {
      access: "public",
      contentType: "application/pdf",
      addRandomSuffix: true,
      token: blobToken,
    });

    return res.status(200).json({ url: blob.url, filename, bytes: pdf.length });
  } catch (err) {
    console.error("moh711-report failed:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
};

module.exports.config = { maxDuration: 60 };
