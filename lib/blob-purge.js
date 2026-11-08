"use strict";

/**
 * Delete blobs under `prefix` older than `maxAgeMs` (default 24 hours).
 * Report and passport PDFs only need to exist long enough for Make.com or
 * WhatsApp to fetch them. Failures are logged and never block the response.
 */
async function purgeOld(prefix, token, maxAgeMs = 24 * 60 * 60 * 1000) {
  try {
    const { list, del } = await import("@vercel/blob");
    const cutoff = Date.now() - maxAgeMs;
    let cursor;
    do {
      const page = await list({ prefix, cursor, token });
      const stale = page.blobs
        .filter((b) => new Date(b.uploadedAt).getTime() < cutoff)
        .map((b) => b.url);
      if (stale.length) await del(stale, { token });
      cursor = page.hasMore ? page.cursor : undefined;
    } while (cursor);
  } catch (e) {
    console.error(`blob purge failed for ${prefix} (non-fatal):`, e.message || e);
  }
}

module.exports = { purgeOld };
