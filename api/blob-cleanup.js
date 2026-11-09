"use strict";

const crypto = require("crypto");
const { purgeOld } = require("../lib/blob-purge");

/**
 * Daily Vercel Cron: delete report and passport PDFs older than 24 hours.
 * Each report endpoint already purges on its own runs, but the passport
 * endpoint can go days without a run, which would leave old PDFs stored.
 *
 * Vercel sends `Authorization: Bearer <CRON_SECRET>` when the CRON_SECRET
 * env var is set. Requests without it are rejected.
 */
const PREFIXES = [
  "mch-reports/",
  "moh711-reports/",
  "odpc-reports/",
  "immunization-passports/",
];

function bearerOk(req) {
  const expected = process.env.CRON_SECRET;
  if (!expected) return false;
  const given = String((req.headers && req.headers.authorization) || "").replace(/^Bearer /, "");
  const h = (v) => crypto.createHash("sha256").update(String(v)).digest();
  return crypto.timingSafeEqual(h(given), h(expected));
}

module.exports = async (req, res) => {
  if (!bearerOk(req)) return res.status(401).json({ error: "unauthorized" });
  const token = process.env.BLOB_READ_WRITE_TOKEN || process.env.blob_READ_WRITE_TOKEN;
  if (!token) return res.status(500).json({ error: "no blob token" });
  for (const p of PREFIXES) await purgeOld(p, token);
  return res.status(200).json({ ok: true, prefixes: PREFIXES });
};
