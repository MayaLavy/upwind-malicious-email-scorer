const { extractDomain, extractDisplayName, isLookalikeDomain } = require("../utils/domainHelpers");
const { BRANDS } = require("../utils/brandList");

const CATEGORY_CAP = 25;

/**
 * Impersonation category (cap: 25).
 *
 * Display name claims known brand but domain doesn't match: +15
 * Lookalike/typosquatting domain:                           +25
 */
function scoreImpersonation({ from }) {
  let score = 0;
  const findings = [];

  const senderDomain = extractDomain(from);
  const displayName = extractDisplayName(from);

  if (!senderDomain) {
    return { score: 0, findings };
  }

  for (const [brand, legitimateDomains] of Object.entries(BRANDS)) {
    const brandInDisplayName = displayName.includes(brand);

    const domainIsLegitimate = legitimateDomains.some(
      (d) => senderDomain === d || senderDomain.endsWith("." + d)
    );

    if (brandInDisplayName && !domainIsLegitimate) {
      score += 15;
      findings.push(
        `Display name claims to be ${brand} but sender domain is ${senderDomain}`
      );
    }

    for (const legitDomain of legitimateDomains) {
      if (isLookalikeDomain(senderDomain, legitDomain)) {
        score = 25;
        findings.push(
          `Sender domain ${senderDomain} is a lookalike of ${legitDomain}`
        );
        return { score: Math.min(score, CATEGORY_CAP), findings };
      }
    }
  }

  return {
    score: Math.min(score, CATEGORY_CAP),
    findings,
  };
}

module.exports = { scoreImpersonation };
