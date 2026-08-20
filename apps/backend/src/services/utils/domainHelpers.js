/**
 * Extracts the domain from an email address string.
 * Handles formats like "Display Name <user@domain.com>" and "user@domain.com".
 */
function extractDomain(emailString) {
  if (!emailString || typeof emailString !== "string") return "";
  const match = emailString.match(/@([^\s>]+)/);
  return match ? match[1].toLowerCase().trim() : "";
}

/**
 * Normalizes a domain for conservative equality comparisons.
 * Used to avoid false mismatches from case, whitespace, or trailing punctuation.
 */
function normalizeComparableDomain(domain) {
  if (!domain || typeof domain !== "string") return "";
  return domain
    .toLowerCase()
    .trim()
    .replace(/[.,;:!?)\]\}]+$/g, "");
}

/**
 * Extracts the display name from an email "From" field.
 * e.g. "PayPal Security <attacker@evil.com>" → "paypal security"
 */
function extractDisplayName(fromField) {
  if (!fromField || typeof fromField !== "string") return "";
  const match = fromField.match(/^"?([^"<]+)"?\s*</);
  return match ? match[1].trim().toLowerCase() : "";
}

/**
 * Common character substitutions used in typosquatting.
 */
const TYPO_MAP = {
  "0": "o",
  "1": "l",
  "!": "i",
  "@": "a",
  "$": "s",
  "5": "s",
  "3": "e",
};

/**
 * Normalizes a domain by replacing common typosquatting characters.
 */
function normalizeDomain(domain) {
  let normalized = domain.toLowerCase();
  for (const [fake, real] of Object.entries(TYPO_MAP)) {
    normalized = normalized.split(fake).join(real);
  }
  normalized = normalized.replace(/rn/g, "m");
  return normalized;
}

/**
 * Checks if two domains are similar enough to be a typosquat.
 * Returns true if the normalized forms match but the originals don't.
 */
function isLookalikeDomain(suspectDomain, legitimateDomain) {
  const suspect = suspectDomain.toLowerCase();
  const legit = legitimateDomain.toLowerCase();
  if (suspect === legit) return false;

  if (normalizeDomain(suspect) === normalizeDomain(legit)) return true;

  const suspectBase = suspect.replace(/\.[^.]+$/, "");
  const legitBase = legit.replace(/\.[^.]+$/, "");
  if (
    suspectBase !== legitBase &&
    normalizeDomain(suspectBase) === normalizeDomain(legitBase)
  ) {
    return true;
  }

  return false;
}

/**
 * Treats an exact domain match or parent/subdomain relationship as the same family.
 * Examples:
 * - service.tiktok.com vs tiktok.com => true
 * - company.com vs support.company.com => true
 * - company.com vs gmail.com => false
 * - paypal.com vs attacker-paypal.com => false
 */
function isSameDomainFamily(firstDomain, secondDomain) {
  const first = normalizeComparableDomain(firstDomain);
  const second = normalizeComparableDomain(secondDomain);

  if (!first || !second) return false;
  if (first === second) return true;

  return first.endsWith("." + second) || second.endsWith("." + first);
}

module.exports = {
  extractDomain,
  extractDisplayName,
  normalizeComparableDomain,
  normalizeDomain,
  isLookalikeDomain,
  isSameDomainFamily,
};
