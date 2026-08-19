const { parseAuthResults, isFail } = require("../utils/headerParser");

const CATEGORY_CAP = 30;

/**
 * Authentication category (cap: 30).
 *
 * SPF fail:   +10
 * DKIM fail:  +10
 * DMARC fail: +20
 *
 * Only hard "fail" is penalized.
 * softfail, neutral, temperror, permerror, none, missing → 0 points.
 * DKIM none/missing alone → 0 points.
 */
function scoreAuthentication({ authenticationResults }) {
  let score = 0;
  const findings = [];

  const auth = parseAuthResults(authenticationResults);

  if (isFail(auth.spf)) {
    score += 10;
    findings.push("SPF authentication failed");
  }

  if (isFail(auth.dkim)) {
    score += 10;
    findings.push("DKIM authentication failed");
  }

  if (isFail(auth.dmarc)) {
    score += 20;
    findings.push("DMARC authentication failed");
  }

  return {
    score: Math.min(score, CATEGORY_CAP),
    findings,
  };
}

module.exports = { scoreAuthentication };
