"use strict";
const crypto = require("crypto");

/**
 * Shared-secret check for the Make.com to Vercel report endpoints.
 *
 * Preferred: send the secret in the `x-hb-secret` request header (Make
 * keychain, API Key Auth module). Legacy: `secret` field in the JSON body.
 * The legacy body field is accepted until REQUIRE_HEADER_AUTH=1 is set in
 * Vercel, so Make and Vercel can be switched over in any order.
 *
 * Comparison is constant time (both sides hashed to equal length first).
 */
function secretOk(req, body, expected) {
  if (!expected) return false;
  const headerVal = req.headers && req.headers["x-hb-secret"];
  const bodyVal = body && typeof body === "object" ? body.secret : undefined;
  const allowBody = process.env.REQUIRE_HEADER_AUTH !== "1";
  const given = headerVal || (allowBody ? bodyVal : "") || "";
  const h = (v) => crypto.createHash("sha256").update(String(v)).digest();
  return crypto.timingSafeEqual(h(given), h(expected));
}

module.exports = { secretOk };
