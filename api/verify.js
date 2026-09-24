/**
 * GET /api/verify?id=...&name=...&dob=...&facility=...&issued=...&sig=...
 *
 * Public verification page for the Digital Immunization Passport, reached by
 * scanning the QR code. Verification is by HMAC signature: the passport
 * endpoint signs the printed fields with PASSPORT_REPORT_SECRET and this page
 * recomputes it. A match means every field is exactly as issued by
 * HealthBridge. No stored PDF is looked up and no document link is exposed.
 */

const crypto = require("crypto");

function esc(s) {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function expectedSig(id, name, dob, facility, issued) {
  return crypto
    .createHmac("sha256", process.env.PASSPORT_REPORT_SECRET || "")
    .update([id, name, dob, facility, issued].map(v => String(v || "")).join("|"))
    .digest("hex")
    .slice(0, 32);
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

module.exports = async (req, res) => {
  if (req.method !== "GET") return res.status(405).send("GET only");
  const { id, name, dob, facility, issued, sig } = req.query;
  if (!id) return res.status(400).send("Missing record ID.");

  const verified = !!process.env.PASSPORT_REPORT_SECRET &&
    safeEqual(sig, expectedSig(id, name, dob, facility, issued));

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.setHeader("x-robots-tag", "noindex, nofollow");
  return res.status(200).send(renderPage({ id, name, dob, facility, issued, verified }));
};

function renderPage({ id, name, dob, facility, issued, verified }) {
  const c = verified
    ? { fg: "#16a34a", bg: "#f0fdf4", bd: "#bbf7d0", icon: "&#10003;", label: "Record Verified",
        note: "This passport was issued by the HealthBridge MCH follow-up system and its details have not been altered." }
    : { fg: "#dc2626", bg: "#fef2f2", bd: "#fecaca", icon: "&#10007;", label: "Not Verified",
        note: "The details on this document do not match a record issued by HealthBridge. It may have been altered. Please confirm with the issuing facility." };
  const row = (k, v) => `<div class="row"><span class="k">${k}</span><span class="v">${esc(v) || "&ndash;"}</span></div>`;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>HealthBridge &middot; Passport Verification</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8fafc;color:#1e293b;min-height:100vh;display:flex;justify-content:center;padding:32px 16px}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:480px;overflow:hidden;align-self:flex-start}
.header{background:#0f4c81;color:#fff;padding:20px 24px;font-weight:700;font-size:17px}
.header small{display:block;font-weight:400;opacity:.8;font-size:13px;margin-top:2px}
.status{margin:20px 24px;padding:16px;border-radius:10px;background:${c.bg};border:1px solid ${c.bd}}
.status b{color:${c.fg};font-size:17px}
.status p{margin-top:6px;font-size:14px;line-height:1.5}
.rows{padding:0 24px 20px}
.row{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid #e2e8f0;font-size:14px}
.k{color:#64748b}.v{font-weight:600;text-align:right}
.foot{padding:16px 24px;font-size:12px;color:#64748b;background:#f8fafc}
</style></head><body>
<div class="card">
  <div class="header">HealthBridge Solutions<small>Digital Immunization Passport verification</small></div>
  <div class="status"><b>${c.icon} ${c.label}</b><p>${c.note}</p></div>
  <div class="rows">
    ${row("Child", name)}${row("Date of birth", dob)}${row("Facility", facility)}${row("Record ID", id)}${row("Issued", issued)}
  </div>
  <div class="foot">This page confirms authenticity only. For the full immunisation record, ask the parent to present the passport shared with them on WhatsApp.</div>
</div></body></html>`;
}
