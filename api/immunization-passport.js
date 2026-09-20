/**
 * POST /api/immunization-passport
 *
 * Digital Immunization Passport PDF — pdfkit (pure JS, no Chromium).
 * Uses dynamic import() for all packages to handle ESM-only modules.
 *
 * Body: { secret, motherId, motherName, babyName, dob, facility,
 *         generatedOn, doses:[{label,status,date}], format? }
 * Returns: { url, filename, bytes }
 */

"use strict";

function esc(v) { return String(v == null ? "" : v); }

async function buildPdf(PDFDocument, QRCode, {
  motherId, motherName, babyName, dob, facility, generatedOn, doses
}) {
  const verifyUrl =
    "https://healthbridge-wa-webhook.vercel.app/api/verify" +
    `?id=${encodeURIComponent(motherId)}` +
    `&name=${encodeURIComponent(babyName)}` +
    `&dob=${encodeURIComponent(dob)}` +
    `&facility=${encodeURIComponent(facility)}` +
    `&issued=${encodeURIComponent(generatedOn)}`;

  const qrBuf = await QRCode.toBuffer(verifyUrl, { type: "png", margin: 1, width: 150 });

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      margins: { top: 40, bottom: 40, left: 40, right: 40 },
      info: {
        Title:  `${babyName} Immunization Passport`,
        Author: "HealthBridge Solutions",
      },
    });

    const chunks = [];
    doc.on("data",  (c) => chunks.push(c));
    doc.on("end",   ()  => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const BRAND = "#1A56DB";
    const DARK  = "#0F172A";
    const SLATE = "#64748B";
    const L = 40, R = 555, W = R - L;

    // Masthead
    doc.font("Helvetica-Bold").fontSize(14).fillColor(BRAND)
       .text("HealthBridge Solutions", L, 40);
    doc.font("Helvetica").fontSize(8).fillColor(SLATE)
       .text("DIGITAL IMMUNIZATION PASSPORT", L, 40, { align: "right", width: W });
    doc.moveTo(L, 62).lineTo(R, 62).strokeColor(DARK).lineWidth(1.5).stroke();

    // Title
    doc.font("Helvetica-Bold").fontSize(19).fillColor(DARK)
       .text(`${babyName}'s Immunization Record`, L, 70, { width: W });

    // ID card background + border
    const CARD_T = 100, CARD_H = 92, QRW = 78;
    const QRL = R - QRW;
    doc.rect(L, CARD_T, W, CARD_H).fillColor("#F7F9FC").fill();
    doc.rect(L, CARD_T, W, CARD_H).strokeColor("#DCE6F8").lineWidth(0.5).stroke();
    doc.rect(L, CARD_T, 3, CARD_H).fillColor(BRAND).fill();

    const CX = L + 10;
    const C2 = L + Math.round(W / 2) - 10;

    function metaField(label, val, x, y) {
      doc.font("Helvetica").fontSize(7).fillColor(SLATE)
         .text(label, x, y, { width: C2 - CX - 4 });
      doc.font("Helvetica-Bold").fontSize(10).fillColor(DARK)
         .text(val || "\u2014", x, y + 9, { width: QRL - x - 8, lineBreak: false });
    }

    metaField("CHILD'S NAME",      babyName,    CX, CARD_T + 10);
    metaField("DATE OF BIRTH",     dob,         C2, CARD_T + 10);
    metaField("MOTHER / GUARDIAN", motherName,  CX, CARD_T + 36);
    metaField("FACILITY",          facility,    C2, CARD_T + 36);
    metaField("RECORD ID",         motherId,    CX, CARD_T + 62);
    metaField("GENERATED",         generatedOn, C2, CARD_T + 62);

    // QR code
    doc.image(qrBuf, QRL + 2, CARD_T + 6, { width: QRW - 6, height: QRW - 6 });
    doc.font("Helvetica").fontSize(6).fillColor(SLATE)
       .text("Scan to verify record", QRL + 2, CARD_T + CARD_H - 10,
             { width: QRW - 6, align: "center" });

    // Headline box
    const hlText =
      `This document is an official digital record of ${babyName}'s immunizations under ` +
      `Kenya's KEPI schedule, generated directly from ${facility}'s HealthBridge follow-up system. ` +
      `It may be presented for school or daycare enrollment in place of, or alongside, ` +
      `the physical Mother & Child Health booklet.`;
    const HL_T = CARD_T + CARD_H + 10;
    const HL_H = doc.heightOfString(hlText, {
      font: "Helvetica", fontSize: 9, width: W - 16,
    }) + 26;

    doc.rect(L, HL_T, W, HL_H).fillColor("#EFF4FE").fill();
    doc.rect(L, HL_T, 3, HL_H).fillColor(BRAND).fill();
    doc.font("Helvetica-Bold").fontSize(7).fillColor(BRAND)
       .text("FOR SCHOOLS AND DAYCARES", L + 10, HL_T + 8, { width: W - 16 });
    doc.font("Helvetica").fontSize(9).fillColor(DARK)
       .text(hlText, L + 10, HL_T + 19, { width: W - 16 });

    // Section header
    const SEC_T = HL_T + HL_H + 12;
    doc.font("Helvetica-Bold").fontSize(7).fillColor(BRAND)
       .text("IMMUNIZATION RECORD", L, SEC_T, { width: W });
    doc.font("Helvetica-Bold").fontSize(12).fillColor(DARK)
       .text("KEPI schedule, birth through 18 months.", L, SEC_T + 10, { width: W });

    // Table header row
    const TH_T = SEC_T + 28, TH_H = 18;
    doc.rect(L, TH_T, W, TH_H).fillColor(DARK).fill();
    doc.font("Helvetica-Bold").fontSize(7).fillColor("#FFFFFF")
       .text("VACCINE / DOSE", L + 8, TH_T + 5, { width: 285, lineBreak: false });
    doc.font("Helvetica-Bold").fontSize(7).fillColor("#FFFFFF")
       .text("STATUS", L + 298, TH_T + 5, { width: 80, align: "right", lineBreak: false });
    doc.font("Helvetica-Bold").fontSize(7).fillColor("#FFFFFF")
       .text("DATE GIVEN", L + 382, TH_T + 5, { width: W - 387, align: "right", lineBreak: false });

    // Dose rows
    let rowY = TH_T + TH_H;
    const RH = 16;
    const doseList = doses.length ? doses : [null];

    doseList.forEach((d, i) => {
      const bg = i % 2 === 0 ? "#FFFFFF" : "#F8FAFB";
      doc.rect(L, rowY, W, RH).fillColor(bg).fill();

      if (!d) {
        doc.font("Helvetica").fontSize(8).fillColor(SLATE)
           .text("No dose records available yet.", L + 8, rowY + 4,
                 { width: 400, lineBreak: false });
      } else {
        const given = String(d.status || "").toLowerCase() === "given";
        doc.font("Helvetica").fontSize(8).fillColor(DARK)
           .text(esc(d.label), L + 8, rowY + 4, { width: 285, lineBreak: false });
        doc.font("Helvetica-Bold").fontSize(8)
           .fillColor(given ? "#158035" : "#C2410C")
           .text(given ? "Given" : "Due", L + 298, rowY + 4,
                 { width: 80, align: "right", lineBreak: false });
        doc.font("Helvetica-Bold").fontSize(8).fillColor(DARK)
           .text(given ? (esc(d.date) || "\u2014") : "\u2014",
                 L + 382, rowY + 4,
                 { width: W - 387, align: "right", lineBreak: false });
      }
      doc.moveTo(L, rowY + RH).lineTo(R, rowY + RH)
         .strokeColor("#E8EEF7").lineWidth(0.4).stroke();
      rowY += RH;
    });

    // Signoff
    const SIG_T = rowY + 10;
    doc.moveTo(L, SIG_T).lineTo(R, SIG_T).strokeColor("#E2E8F0").lineWidth(0.5).stroke();
    doc.font("Helvetica").fontSize(8.8).fillColor(DARK)
       .text(
         `This record reflects doses logged through HealthBridge's WhatsApp-based follow-up ` +
         `system as of the generation date above. Please confirm any recent doses directly with ` +
         `${facility} if this document is more than a few weeks old.`,
         L, SIG_T + 8, { width: W }
       );
    doc.moveDown(0.4);
    doc.font("Helvetica").fontSize(7.8).fillColor(SLATE)
       .text("HealthBridge Solutions \u00b7 Maternal & Child Health Follow-Up", { width: W });

    doc.moveDown(0.8);
    doc.moveTo(L, doc.y).lineTo(R, doc.y).strokeColor("#E2E8F0").lineWidth(0.4).stroke();
    doc.moveDown(0.3);
    doc.font("Helvetica-Bold").fontSize(7).fillColor(SLATE)
       .text("About this document.  ", { continued: true });
    doc.font("Helvetica").fontSize(7).fillColor(SLATE)
       .text(
         `Doses are recorded when a caregiver confirms them via WhatsApp or a nurse updates ` +
         `the record directly. This is a convenience record, not a replacement for the official ` +
         `Ministry of Health Mother & Child Health booklet. ` +
         `Confidential to ${motherName} and ${facility}.`,
         { width: W }
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

    // Dynamic imports — works regardless of whether package is CJS or ESM
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
      doses:       Array.isArray(body.doses) ? body.doses : [],
    };

    const pdf = await buildPdf(PDFDocument, QRCode, data);

    if (body.format === "html") {
      res.setHeader("content-type", "text/plain; charset=utf-8");
      return res.status(200).send(`pdfkit OK, ${pdf.length} bytes`);
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

    return res.status(200).json({ url: blob.url, filename, bytes: pdf.length });

  } catch (err) {
    console.error("immunization-passport failed:", err.stack || err);
    return res.status(500).json({ error: String(err.message || err) });
  }
};

module.exports.config = { maxDuration: 60 };
