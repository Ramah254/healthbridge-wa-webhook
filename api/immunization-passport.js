/**
 * POST /api/immunization-passport
 *
 * Digital Immunization Passport PDF — pdfkit (pure JS, no Chromium).
 * Handles Make.com's raw-body auto-stringification of array/collection
 * variables (doses may arrive as a JSON string, not a native array) and
 * its Aggregator "properties" wrapper on each bundled item.
 */

"use strict";

function esc(v) { return String(v == null ? "" : v); }

/** Make sometimes delivers `doses` as a JSON-encoded string (raw-body
 *  auto-stringification) instead of a real array. Normalize both shapes,
 *  and unwrap the Aggregator's `{properties:{...}}` bundle if present. */
function normalizeDoses(raw) {
  let arr = raw;
  if (typeof arr === "string") {
    try { arr = JSON.parse(arr); } catch (e) { arr = []; }
  }
  // Make's json:CreateJSON module always wraps its output under the field
  // name from its Data Structure (confirmed via live trace: {"array":[...]});
  // it cannot emit a bare array. Unwrap that specific, observed shape.
  if (arr && typeof arr === "object" && !Array.isArray(arr) && Array.isArray(arr.array)) {
    arr = arr.array;
  }
  if (!Array.isArray(arr)) return [];
  return arr.map((d) => {
    const src = d && typeof d === "object" && d.properties ? d.properties : d;
    return {
      label:  src && src.label  != null ? String(src.label)  : "",
      status: src && src.status != null ? String(src.status) : "",
      date:   src && src.date   != null ? String(src.date)   : "",
    };
  });
}

async function buildPdf(PDFDocument, QRCode, {
  motherId, motherName, babyName, dob, facility, generatedOn, doses, _debugRawDoses
}) {
  const verifyUrl =
    "https://healthbridge-wa-webhook.vercel.app/api/verify" +
    `?id=${encodeURIComponent(motherId)}` +
    `&name=${encodeURIComponent(babyName)}` +
    `&dob=${encodeURIComponent(dob)}` +
    `&facility=${encodeURIComponent(facility)}` +
    `&issued=${encodeURIComponent(generatedOn)}`;

  const qrBuf = await QRCode.toBuffer(verifyUrl, { type: "png", margin: 1, width: 180 });

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      margins: { top: 48, bottom: 48, left: 48, right: 48 },
      info: {
        Title:  `${babyName} Immunization Passport`,
        Author: "HealthBridge Solutions",
      },
    });

    const chunks = [];
    doc.on("data",  (c) => chunks.push(c));
    doc.on("end",   ()  => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    // ── Palette ──────────────────────────────────────────────────────
    const BRAND      = "#1A56DB";
    const BRAND_SOFT = "#EFF4FE";
    const DARK       = "#0F172A";
    const SLATE      = "#64748B";
    const LINE       = "#E2E8F0";
    const GIVEN_BG   = "#EDFBF3";
    const GIVEN_TXT  = "#0F7A3D";
    const PEND_TXT   = "#8A6D1F";

    const L = 48, R = 547, W = R - L;

    // ── Masthead ─────────────────────────────────────────────────────
    doc.font("Helvetica-Bold").fontSize(15).fillColor(BRAND)
       .text("HealthBridge Solutions", L, 48);
    doc.font("Helvetica").fontSize(8).fillColor(SLATE)
       .text("DIGITAL IMMUNIZATION PASSPORT", L, 51, { width: W, align: "right" });
    doc.moveTo(L, 74).lineTo(R, 74).strokeColor(DARK).lineWidth(1.3).stroke();

    // ── Title ────────────────────────────────────────────────────────
    doc.font("Helvetica-Bold").fontSize(21).fillColor(DARK)
       .text(`${babyName}'s Immunization Record`, L, 90, { width: W });

    // ── ID card ──────────────────────────────────────────────────────
    const CARD_T = 128, CARD_H = 108, QRW = 92;
    const QRL = R - QRW;

    doc.roundedRect(L, CARD_T, W, CARD_H, 4).fillColor("#F7F9FC").fill();
    doc.roundedRect(L, CARD_T, W, CARD_H, 4).strokeColor("#DCE6F8").lineWidth(0.6).stroke();
    doc.rect(L, CARD_T, 4, CARD_H).fillColor(BRAND).fill();

    const PAD  = 20;
    const CX   = L + PAD;
    const C2   = L + Math.round((W - QRW) / 2) + 6;
    const FLDW = C2 - CX - 16;

    function metaField(label, val, x, y, width) {
      doc.font("Helvetica").fontSize(7.5).fillColor(SLATE)
         .text(label, x, y, { width, characterSpacing: 0.3 });
      doc.font("Helvetica-Bold").fontSize(11).fillColor(DARK)
         .text(val || "\u2014", x, y + 12, { width, lineBreak: false });
    }

    metaField("CHILD'S NAME",      babyName,    CX, CARD_T + 18, FLDW);
    metaField("DATE OF BIRTH",     dob,         C2, CARD_T + 18, FLDW);
    metaField("MOTHER / GUARDIAN", motherName,  CX, CARD_T + 50, FLDW);
    metaField("FACILITY",          facility,    C2, CARD_T + 50, FLDW);
    metaField("RECORD ID",         motherId,    CX, CARD_T + 82, FLDW);
    metaField("GENERATED",         generatedOn, C2, CARD_T + 82, FLDW);

    doc.image(qrBuf, QRL + 8, CARD_T + 12, { width: QRW - 16, height: QRW - 16 });
    doc.font("Helvetica").fontSize(6.5).fillColor(SLATE)
       .text("Scan to verify record", QRL + 8, CARD_T + QRW - 2,
             { width: QRW - 16, align: "center" });

    // ── Headline box ─────────────────────────────────────────────────
    const hlText =
      `This document is an official digital record of ${babyName}'s immunizations under ` +
      `Kenya's KEPI schedule, generated directly from ${facility}'s HealthBridge follow-up ` +
      `system. It may be presented for school or daycare enrollment in place of, or ` +
      `alongside, the physical Mother & Child Health booklet.`;
    const HL_T = CARD_T + CARD_H + 16;
    const HL_H = doc.heightOfString(hlText, { font: "Helvetica", fontSize: 9.5, width: W - 28 }) + 34;

    doc.roundedRect(L, HL_T, W, HL_H, 3).fillColor(BRAND_SOFT).fill();
    doc.rect(L, HL_T, 4, HL_H).fillColor(BRAND).fill();
    doc.font("Helvetica-Bold").fontSize(7.5).fillColor(BRAND)
       .text("FOR SCHOOLS AND DAYCARES", L + 18, HL_T + 12, { width: W - 28, characterSpacing: 0.3 });
    doc.font("Helvetica").fontSize(9.5).fillColor(DARK)
       .text(hlText, L + 18, HL_T + 25, { width: W - 28, lineGap: 2 });

    // ── Section header ───────────────────────────────────────────────
    const SEC_T = HL_T + HL_H + 20;
    doc.font("Helvetica-Bold").fontSize(7.5).fillColor(BRAND)
       .text("IMMUNIZATION RECORD", L, SEC_T, { width: W, characterSpacing: 0.3 });
    doc.font("Helvetica-Bold").fontSize(13).fillColor(DARK)
       .text("KEPI schedule, birth through 18 months.", L, SEC_T + 12, { width: W });

    // ── Table ────────────────────────────────────────────────────────
    const TH_T = SEC_T + 36, TH_H = 24;
    doc.rect(L, TH_T, W, TH_H).fillColor(DARK).fill();
    doc.font("Helvetica-Bold").fontSize(7.5).fillColor("#FFFFFF");
    doc.text("VACCINE / DOSE", L + 14, TH_T + 8, { width: 290, lineBreak: false });
    doc.text("STATUS",         L + 300, TH_T + 8, { width: 90, align: "right", lineBreak: false });
    doc.text("DATE GIVEN",     L + 388, TH_T + 8, { width: W - 402, align: "right", lineBreak: false });

    let rowY = TH_T + TH_H;
    const RH = 26;
    const doseList = doses.length ? doses : [null];

    doseList.forEach((d, i) => {
      const bg = i % 2 === 0 ? "#FFFFFF" : "#F8FAFB";
      doc.rect(L, rowY, W, RH).fillColor(bg).fill();

      if (!d) {
        doc.font("Helvetica").fontSize(9).fillColor(SLATE)
           .text("No dose records available yet.", L + 14, rowY + 9, { width: 420 });
        if (_debugRawDoses) {
          doc.font("Helvetica").fontSize(6).fillColor("#C2410C")
             .text("[TEMP DEBUG] raw doses received: " + _debugRawDoses, L + 14, rowY + 18, { width: W - 28 });
        }
      } else {
        const given = d.status.toLowerCase() === "given";
        doc.font("Helvetica").fontSize(9.5).fillColor(DARK)
           .text(d.label || "\u2014", L + 14, rowY + 8, { width: 285, lineBreak: false });

        if (given) {
          doc.roundedRect(L + 300, rowY + 5, 76, 16, 8).fillColor(GIVEN_BG).fill();
          doc.font("Helvetica-Bold").fontSize(8).fillColor(GIVEN_TXT)
             .text("Given", L + 300, rowY + 9, { width: 76, align: "center", lineBreak: false });
        } else {
          doc.font("Helvetica-Bold").fontSize(8).fillColor(PEND_TXT)
             .text("Not yet given", L + 300, rowY + 9, { width: 90, align: "right", lineBreak: false });
        }

        doc.font("Helvetica-Bold").fontSize(9.5).fillColor(DARK)
           .text(given ? (d.date || "\u2014") : "\u2014", L + 388, rowY + 8,
                 { width: W - 402, align: "right", lineBreak: false });
      }
      doc.moveTo(L, rowY + RH).lineTo(R, rowY + RH).strokeColor(LINE).lineWidth(0.5).stroke();
      rowY += RH;
    });

    // ── Signoff ──────────────────────────────────────────────────────
    const SIG_T = rowY + 22;
    doc.moveTo(L, SIG_T).lineTo(R, SIG_T).strokeColor(LINE).lineWidth(0.6).stroke();
    doc.font("Helvetica").fontSize(9.5).fillColor(DARK)
       .text(
         `This record reflects doses logged through HealthBridge's WhatsApp-based follow-up ` +
         `system as of the generation date above. Please confirm any recent doses directly with ` +
         `${facility} if this document is more than a few weeks old.`,
         L, SIG_T + 14, { width: W, lineGap: 2 }
       );

    doc.moveDown(0.8);
    doc.font("Helvetica-Bold").fontSize(8.5).fillColor(SLATE)
       .text("HealthBridge Solutions", { continued: true })
       .font("Helvetica").fillColor(SLATE)
       .text("  \u00b7  Maternal & Child Health Follow-Up");

    doc.moveDown(1);
    doc.moveTo(L, doc.y).lineTo(R, doc.y).strokeColor(LINE).lineWidth(0.5).stroke();
    doc.moveDown(0.6);
    doc.font("Helvetica-Bold").fontSize(7.5).fillColor(SLATE)
       .text("About this document.  ", { continued: true });
    doc.font("Helvetica").fontSize(7.5).fillColor(SLATE)
       .text(
         `Doses are recorded when a caregiver confirms them via WhatsApp or a nurse updates ` +
         `the record directly. This is a convenience record, not a replacement for the official ` +
         `Ministry of Health Mother & Child Health booklet. ` +
         `Confidential to ${motherName} and ${facility}.`,
         { width: W, lineGap: 1.5 }
       );

    doc.end();
  });
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "POST only" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;

    if (
      !process.env.PASSPORT_REPORT_SECRET ||
      body.secret !== process.env.PASSPORT_REPORT_SECRET
    ) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { default: PDFDocument } = await import("pdfkit");
    const QRCodeMod = await import("qrcode");
    const QRCode = QRCodeMod.default || QRCodeMod;

    const data = {
      motherId:    esc(body.motherId),
      motherName:  esc(body.motherName),
      babyName:    esc(body.babyName) || "Baby",
      dob:         esc(body.dob),
      facility:    esc(body.facility),
      generatedOn: esc(body.generatedOn),
      doses:       normalizeDoses(body.doses),
      _debugRawDoses: (function () {
        try {
          return typeof body.doses + ": " + JSON.stringify(body.doses).slice(0, 400);
        } catch (e) {
          return typeof body.doses + " (stringify failed: " + e.message + ")";
        }
      })(),
    };

    const pdf = await buildPdf(PDFDocument, QRCode, data);

    if (body.format === "html") {
      res.setHeader("content-type", "text/plain; charset=utf-8");
      return res.status(200).send(`pdfkit OK, ${pdf.length} bytes, ${data.doses.length} doses`);
    }

    const blobToken =
      process.env.BLOB_READ_WRITE_TOKEN || process.env.blob_READ_WRITE_TOKEN;
    if (!blobToken) {
      throw new Error("No Blob token (BLOB_READ_WRITE_TOKEN / blob_READ_WRITE_TOKEN).");
    }

    const { put } = await import("@vercel/blob");
    const filename = `Immunization-Passport-${data.motherId}.pdf`;
    const blob = await put(`immunization-passports/${filename}`, pdf, {
      access:          "public",
      contentType:     "application/pdf",
      addRandomSuffix: false,
      token:           blobToken,
    });

    return res.status(200).json({ url: blob.url, filename, bytes: pdf.length, doses: data.doses.length });

  } catch (err) {
    console.error("immunization-passport failed:", err.stack || err);
    return res.status(500).json({ error: String(err.message || err) });
  }
};

module.exports.config = { maxDuration: 60 };
