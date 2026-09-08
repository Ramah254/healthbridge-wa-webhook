/**
 * GET /api/verify?id=MCH-2026-xxx&name=Baby&dob=12/07/2026&facility=...&issued=...
 *
 * Public verification page for the Digital Immunization Passport.
 * Scanned by schools, daycares, and clinics to confirm a HealthBridge-generated
 * passport is authentic. Locates the stored PDF via Vercel Blob and renders a
 * clean HTML verification page with a direct link to the original document.
 *
 * No auth required — this page is meant to be publicly accessible.
 * Env vars: BLOB_READ_WRITE_TOKEN (or blob_READ_WRITE_TOKEN) for blob lookup.
 */

function esc(s) {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

module.exports = async (req, res) => {
  if (req.method !== "GET") return res.status(405).send("GET only");

  const { id, name, dob, facility, issued } = req.query;
  if (!id) {
    return res.status(400).send("Missing record ID.");
  }

  let pdfUrl = null;
  let verified = false;

  try {
    const { head } = await import("@vercel/blob");
    const blobToken = process.env.BLOB_READ_WRITE_TOKEN || process.env.blob_READ_WRITE_TOKEN;
    const blobPath = `immunization-passports/Immunization-Passport-${id}.pdf`;
    const result = await head(blobPath, { token: blobToken });
    pdfUrl = result.url;
    verified = true;
  } catch (_) {
    verified = false;
  }

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  return res.status(200).send(renderPage({ id, name, dob, facility, issued, pdfUrl, verified }));
};

function renderPage({ id, name, dob, facility, issued, pdfUrl, verified }) {
  const statusColor = verified ? "#16a34a" : "#dc2626";
  const statusBg = verified ? "#f0fdf4" : "#fef2f2";
  const statusBorder = verified ? "#bbf7d0" : "#fecaca";
  const statusIcon = verified ? "✓" : "✗";
  const statusLabel = verified ? "Record Verified" : "Record Not Found";
  const statusNote = verified
    ? "This passport was generated directly from the HealthBridge MCH follow-up system and is authentic."
    : "No matching record was found in the HealthBridge system for this ID. The document may have been altered or the ID is incorrect.";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HealthBridge · Passport Verification</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f8fafc;
    color: #1e293b;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 32px 16px;
  }
  .card {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    width: 100%;
    max-width: 480px;
    overflow: hidden;
  }
  .header {
    background: #0f4c81;
    padding: 24px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .header-logo {
    width: 40px; height: 40px;
    background: #fff;
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
  }
  .header-text h1 { color: #fff; font-size: 16px; font-weight: 700; }
  .header-text p { color: #93c5fd; font-size: 12px; margin-top: 2px; }
  .body { padding: 24px; }
  .status-box {
    border-radius: 10px;
    border: 1px solid ${statusBorder};
    background: ${statusBg};
    padding: 20px;
    display: flex;
    gap: 16px;
    align-items: flex-start;
    margin-bottom: 24px;
  }
  .status-icon {
    width: 36px; height: 36px;
    border-radius: 50%;
    background: ${statusColor};
    color: #fff;
    font-size: 18px;
    font-weight: 700;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }
  .status-label { font-size: 16px; font-weight: 700; color: ${statusColor}; }
  .status-note { font-size: 13px; color: #475569; margin-top: 4px; line-height: 1.5; }
  .section-title {
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.08em; color: #94a3b8; margin-bottom: 12px;
  }
  .field { margin-bottom: 14px; }
  .field-label { font-size: 11px; color: #94a3b8; margin-bottom: 2px; }
  .field-value { font-size: 15px; font-weight: 500; color: #0f172a; }
  .divider { height: 1px; background: #e2e8f0; margin: 20px 0; }
  .pdf-btn {
    display: block;
    background: #0f4c81;
    color: #fff;
    text-decoration: none;
    text-align: center;
    padding: 14px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    margin-top: 20px;
  }
  .pdf-btn:hover { background: #1e3a5f; }
  .footer {
    margin-top: 24px;
    font-size: 11px;
    color: #94a3b8;
    text-align: center;
    line-height: 1.6;
  }
  .record-id {
    font-family: monospace;
    font-size: 12px;
    background: #f1f5f9;
    padding: 4px 8px;
    border-radius: 4px;
    color: #475569;
  }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="header-logo">🏥</div>
    <div class="header-text">
      <h1>HealthBridge Solutions</h1>
      <p>Digital Immunization Passport · Verification</p>
    </div>
  </div>
  <div class="body">
    <div class="status-box">
      <div class="status-icon">${statusIcon}</div>
      <div>
        <div class="status-label">${statusLabel}</div>
        <div class="status-note">${statusNote}</div>
      </div>
    </div>

    <div class="section-title">Record Details</div>

    <div class="field">
      <div class="field-label">Record ID</div>
      <div class="field-value"><span class="record-id">${esc(id)}</span></div>
    </div>
    ${name ? `<div class="field">
      <div class="field-label">Child's Name</div>
      <div class="field-value">${esc(name)}</div>
    </div>` : ""}
    ${dob ? `<div class="field">
      <div class="field-label">Date of Birth</div>
      <div class="field-value">${esc(dob)}</div>
    </div>` : ""}
    ${facility ? `<div class="field">
      <div class="field-label">Issuing Facility</div>
      <div class="field-value">${esc(facility)}</div>
    </div>` : ""}
    ${issued ? `<div class="field">
      <div class="field-label">Passport Issued</div>
      <div class="field-value">${esc(issued)}</div>
    </div>` : ""}

    ${verified && pdfUrl ? `
    <div class="divider"></div>
    <div class="section-title">Original Document</div>
    <a class="pdf-btn" href="${esc(pdfUrl)}" target="_blank" rel="noopener">
      📄 View / Download Passport PDF
    </a>` : ""}
  </div>
</div>
<div class="footer">
  Verification powered by HealthBridge Solutions &nbsp;·&nbsp; Kenya KEPI Programme<br>
  For queries contact the issuing facility directly.
</div>
</body>
</html>`;
}
