/**
 * POST /api/odpc-report
 *
 * Renders the HealthBridge ODPC Data Protection Readiness Report as a PDF
 * and uploads it to Vercel Blob storage, returning a plain JSON URL.
 *
 * Deliberately simpler than /api/mch-report.js: this report is a factual
 * compliance snapshot, not a narrative monthly summary, so there is no
 * Anthropic API call and no JSON-parsing failure class to debug. All text
 * is built deterministically from the numbers Make sends. If a narrative
 * layer is wanted later, follow mch-report.js's draftNarrative() pattern
 * exactly rather than inventing a new one.
 *
 * Transport: same as mch-report.js. Make cannot carry raw PDF bytes without
 * corruption (see that file's header comment for the three failed attempts).
 * This endpoint uploads to Blob and returns a URL; Make fetches it with
 * http:ActionGetFile and hands that to Google Drive.
 *
 * ---------------------------------------------------------------------------
 * Body:
 * {
 *   "secret": "<ODPC_REPORT_SECRET>",
 *   "facility": "Example Hospital",
 *   "reportDate": "6 September 2026",
 *   "dcRegNo": "...",
 *   "dpRegNo": "...",
 *   "consentCoveragePct": 100,
 *   "retentionDays": 580,
 *   "archiverState": "Active, weekly",
 *   "lastPurgeDate": "1 September 2026",
 *   "rowsPurged": 0,
 *   "confidentialCount": 5,
 *   "confidentialTotal": 6,
 *   "auditLogRowsMonth": 412,
 *   "optOutsMonth": 1,
 *   "archivedCount": 3,
 *   "format": "pdf" | "html"
 * }
 *
 * Returns (format "pdf"):
 * { "url": "...", "filename": "ODPC-Readiness-Example-Hospital-2026-09.pdf", "bytes": 98765 }
 *
 * Env vars required:
 *   ODPC_REPORT_SECRET     shared secret, must match what Make sends
 *   BLOB_READ_WRITE_TOKEN  (or blob_READ_WRITE_TOKEN) — same Blob store as mch-report
 *
 * Vercel project settings required: Node.js 22.x+ (same project as mch-report.js).
 */

const fs = require("fs");
const path = require("path");

const num = (v) => Number(v || 0);

function statusClass(pct, warnBelow, badBelow) {
  if (pct < badBelow) return { cls: "bad", label: "Attention needed" };
  if (pct < warnBelow) return { cls: "warn", label: "Review recommended" };
  return { cls: "ok", label: "Compliant" };
}

function buildHeadline(t) {
  const issues = [];
  if (t.consentCoveragePct < 100) issues.push(`consent coverage at ${t.consentCoveragePct}%`);
  if (t.confidentialCount < t.confidentialTotal) {
    issues.push(`${t.confidentialTotal - t.confidentialCount} scenario(s) without confidential mode enabled`);
  }
  if (!issues.length) {
    return "Patient data at your facility is being handled under Kenya's Data Protection Act, 2019, " +
      "with active consent controls, automated retention limits, and a full audit trail. No open items.";
  }
  return `Data protection controls are largely in place, with ${issues.join(" and ")} flagged for attention below.`;
}

function buildSummary(t) {
  const parts = [
    `<p>HealthBridge Solutions operates under registered Data Controller (${t.dcRegNo}) and Data ` +
    `Processor (${t.dpRegNo}) status with Kenya's Office of the Data Protection Commissioner. All ` +
    `patient data processed on behalf of ${t.facility} is subject to consent enforcement, automated ` +
    `field-level retention purging at ${t.retentionDays} days, and a complete audit trail of every ` +
    `data change, timestamped and attributable.</p>`,
  ];
  if (t.consentCoveragePct < 100) {
    parts.push(`<p>Consent coverage stands at ${t.consentCoveragePct}% of active mothers. Records without ` +
      `a confirmed ConsentGiven=YES are not processed by any automated messaging or reminder scenario.</p>`);
  }
  if (t.confidentialCount < t.confidentialTotal) {
    parts.push(`<p>${t.confidentialTotal - t.confidentialCount} of ${t.confidentialTotal} scenarios ` +
      `handling identifiable patient data do not yet have confidential mode enabled at the platform ` +
      `level. This is an internal configuration item, being addressed directly, not a data exposure.</p>`);
  }
  parts.push(`<p>${t.optOutsMonth} mother(s) exercised their right to opt out this month, honoured ` +
    `immediately. ${t.archivedCount} record(s) are currently archived under the retention policy.</p>`);
  return parts.join("\n");
}

function buildSignoff(facility) {
  return `This report reflects our ongoing commitment to data protection compliance at ${facility}. ` +
    `I'm available to walk your board or compliance officer through any item in this report, or to ` +
    `provide supporting documentation for your own ODPC obligations.`;
}

function fillTemplate(tokens) {
  const tplPath = path.join(process.cwd(), "templates", "odpc-readiness-template.html");
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

    if (!process.env.ODPC_REPORT_SECRET || body.secret !== process.env.ODPC_REPORT_SECRET) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const t = {
      facility: body.facility || "",
      reportDate: body.reportDate || "",
      dcRegNo: body.dcRegNo || "",
      dpRegNo: body.dpRegNo || "",
      consentCoveragePct: num(body.consentCoveragePct),
      retentionDays: num(body.retentionDays),
      archiverState: body.archiverState || "",
      lastPurgeDate: body.lastPurgeDate || "",
      rowsPurged: num(body.rowsPurged),
      confidentialCount: num(body.confidentialCount),
      confidentialTotal: num(body.confidentialTotal),
      auditLogRowsMonth: num(body.auditLogRowsMonth),
      optOutsMonth: num(body.optOutsMonth),
      archivedCount: num(body.archivedCount),
    };

    const consentStatus = statusClass(t.consentCoveragePct, 100, 90);
    const confidentialPct = t.confidentialTotal ? (100 * t.confidentialCount) / t.confidentialTotal : 100;
    const confidentialStatus = statusClass(confidentialPct, 100, 60);

    const tokens = {
      FACILITY: t.facility,
      REPORT_DATE: t.reportDate,
      DC_REG_NO: t.dcRegNo,
      DP_REG_NO: t.dpRegNo,
      CONSENT_COVERAGE_PCT: t.consentCoveragePct,
      CONSENT_STAT_CLASS: consentStatus.cls,
      CONSENT_STAT_LABEL: consentStatus.label,
      RETENTION_DAYS: t.retentionDays,
      ARCHIVER_STATE: t.archiverState,
      LAST_PURGE_DATE: t.lastPurgeDate,
      ROWS_PURGED: t.rowsPurged,
      PURGE_STAT_CLASS: "ok",
      CONFIDENTIAL_COUNT: t.confidentialCount,
      CONFIDENTIAL_TOTAL: t.confidentialTotal,
      CONFIDENTIAL_STAT_CLASS: confidentialStatus.cls,
      CONFIDENTIAL_STAT_LABEL: confidentialStatus.label,
      AUDITLOG_ROWS_MONTH: t.auditLogRowsMonth,
      OPT_OUTS_MONTH: t.optOutsMonth,
      ARCHIVED_COUNT: t.archivedCount,
      HEADLINE: buildHeadline(t),
      SUMMARY_BODY: buildSummary(t),
      SIGNOFF: buildSignoff(t.facility),
    };

    const html = fillTemplate(tokens);

    if (body.format === "html") {
      res.setHeader("content-type", "text/html; charset=utf-8");
      return res.status(200).send(html);
    }

    const pdf = await toPdf(html);

    const safeFacility = String(t.facility || "facility").replace(/\s+/g, "-");
    const safeDate = String(t.reportDate || "report").replace(/\s+/g, "-");
    const filename = `ODPC-Readiness-${safeFacility}-${safeDate}.pdf`;

    const blobToken = process.env.BLOB_READ_WRITE_TOKEN || process.env.blob_READ_WRITE_TOKEN;
    if (!blobToken) {
      throw new Error(
        "No Blob token found in either BLOB_READ_WRITE_TOKEN or blob_READ_WRITE_TOKEN. " +
        "Same store as mch-report.js (mchblob) — confirm it's linked to this project too."
      );
    }

    const { put } = await import("@vercel/blob");
    const blob = await put(`odpc-reports/${filename}`, pdf, {
      access: "public",
      contentType: "application/pdf",
      addRandomSuffix: true,
      token: blobToken,
    });

    return res.status(200).json({ url: blob.url, filename, bytes: pdf.length });
  } catch (err) {
    console.error("odpc-report failed:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
};

module.exports.config = { maxDuration: 60 };
