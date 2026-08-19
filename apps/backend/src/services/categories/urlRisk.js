const { findMismatchedLinks, domainFromUrl } = require("../utils/htmlLinkParser");
const { isLookalikeDomain } = require("../utils/domainHelpers");
const { BRANDS } = require("../utils/brandList");

const CATEGORY_CAP = 25;

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
  "is.gd", "buff.ly", "rebrand.ly", "bl.ink", "short.io",
  "cutt.ly", "rb.gy",
]);

/**
 * URL Risk category (cap: 25).
 *
 * 10+ unique URLs:                          +5
 * Known URL shortener:                      +5
 * URL uses IP address instead of domain:    +10
 * Suspicious/lookalike destination domain:  +15
 * Displayed URL differs from actual href:   +20
 */
function scoreUrlRisk({ urls, bodyHtml }) {
  let score = 0;
  const findings = [];

  const uniqueUrls = [...new Set((urls || []).map((u) => u.toLowerCase()))];

  if (uniqueUrls.length >= 10) {
    score += 5;
    findings.push(`Email contains ${uniqueUrls.length} unique URLs`);
  }

  let hasShortener = false;
  let hasIpUrl = false;
  let hasLookalike = false;

  for (const url of uniqueUrls) {
    const domain = domainFromUrl(url);
    if (!domain) continue;

    if (!hasShortener && SHORTENERS.has(domain)) {
      hasShortener = true;
      score += 5;
      findings.push(`Email contains a shortened URL (${domain})`);
    }

    if (!hasIpUrl && /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(domain)) {
      hasIpUrl = true;
      score += 10;
      findings.push(`URL uses an IP address instead of a domain: ${domain}`);
    }

    if (!hasLookalike) {
      for (const legitimateDomains of Object.values(BRANDS)) {
        for (const legit of legitimateDomains) {
          if (isLookalikeDomain(domain, legit)) {
            hasLookalike = true;
            score += 15;
            findings.push(
              `URL domain ${domain} is a lookalike of ${legit}`
            );
            break;
          }
        }
        if (hasLookalike) break;
      }
    }
  }

  const mismatched = findMismatchedLinks(bodyHtml);
  if (mismatched.length > 0) {
    score += 20;
    const first = mismatched[0];
    findings.push(
      `Link displays "${first.displayedText}" but actually points to ${first.hrefDomain}`
    );
  }

  return {
    score: Math.min(score, CATEGORY_CAP),
    findings,
  };
}

module.exports = { scoreUrlRisk };
