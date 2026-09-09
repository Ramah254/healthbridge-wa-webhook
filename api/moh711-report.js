/**
 * POST /api/moh711-report
 *
 * MOH 711A DRAFT pre-fill — ANC/PMTCT + Maternity sections only.
 * Watermarked DRAFT; HRIO reconciles against KHIS/DHIS2 before submission.
 *
 * Body:
 * {
 *   secret, facility, month, reportDate,
 *   ancNew, ancRevisit, ancTotal, anc4thVisit, anc8,
 *   iptp1, iptp2, iptp3,
 *   totalDeliveries,
 *   format: "pdf" | "html"
 * }
 * Returns: { url, filename, bytes }
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
      anc8: num(body.anc8),
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
      ANC_8TH_CONTACT: t.anc8,
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
