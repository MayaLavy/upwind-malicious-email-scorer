const {
  normalizeComparableDomain,
  isSameDomainFamily,
} = require("./domainHelpers");

/**
 * Minimal HTML <a> tag parser for detecting displayed-link vs href mismatches.
 *
 * LIMITATION: This uses simple regex and does NOT handle:
 * - URL-encoded or obfuscated hrefs
 * - Nested HTML elements within <a> tags
 * - CSS-hidden content or style-based tricks
 * - JavaScript-based URL redirects
 * - Complex multi-line attributes
 *
 * This is intentional for the MVP scope. A production system would use
 * a proper HTML parser (e.g. cheerio) and more sophisticated analysis.
 */

/**
 * Extracts domain from a URL string.
 */
function domainFromUrl(url) {
  if (!url) return "";
  try {
    const match = url.match(/^https?:\/\/([^/?#]+)/i);
    return match ? normalizeComparableDomain(match[1]) : "";
  } catch {
    return "";
  }
}

/**
 * Checks if text looks like a URL or domain.
 */
function looksLikeUrl(text) {
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(text.trim())) {
    return false;
  }
  return /^https?:\/\//i.test(text) || /^www\./i.test(text) || /\.[a-z]{2,}$/i.test(text);
}

/**
 * Extracts <a href="...">displayed text</a> pairs from HTML.
 * Returns an array of { href, displayedText, hrefDomain, displayedDomain }.
 */
function extractLinks(html) {
  if (!html || typeof html !== "string") return [];

  const links = [];
  const pattern = /<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;

  while ((match = pattern.exec(html)) !== null) {
    const href = match[1].trim();
    const displayedRaw = match[2].replace(/<[^>]+>/g, "").trim();

    if (!href || !displayedRaw) continue;

    links.push({
      href,
      displayedText: displayedRaw,
      hrefDomain: domainFromUrl(href),
      displayedDomain: looksLikeUrl(displayedRaw)
        ? domainFromUrl(
            displayedRaw.startsWith("http")
              ? displayedRaw
              : "http://" + displayedRaw
          )
        : "",
    });
  }

  return links;
}

/**
 * Finds links where displayed text looks like a URL/domain
 * but points to a different domain.
 */
function findMismatchedLinks(html) {
  const links = extractLinks(html);
  return links.filter(
    (link) =>
      link.displayedDomain &&
      link.hrefDomain &&
      !isSameDomainFamily(link.displayedDomain, link.hrefDomain)
  );
}

module.exports = { extractLinks, findMismatchedLinks, domainFromUrl, looksLikeUrl };
