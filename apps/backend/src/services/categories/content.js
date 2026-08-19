const CATEGORY_CAP = 20;

/**
 * Patterns representing actual social engineering attempts,
 * not just individual keywords.
 */
const URGENCY_PATTERNS = [
  /act\s+(now|immediately|quickly)/i,
  /immediate\s+action\s+required/i,
  /within\s+\d+\s+(hours?|minutes?)/i,
  /within\s+[12]\s+days?/i,
  /expires?\s+(today|tonight|soon|in\s+\d+)/i,
  /don'?t\s+delay/i,
  /urgent\s*:?\s*(action|response|attention|notice|update)/i,
  /time[- ]sensitive/i,
  /last\s+(chance|warning|notice|reminder)/i,
];

const THREAT_PATTERNS = [
  /account\s+(will\s+be|has\s+been|is\s+being)\s*(suspended|closed|terminated|locked|disabled|restricted)/i,
  /failure\s+to\s+(respond|act|verify|confirm|comply)/i,
  /legal\s+action/i,
  /unauthorized\s+(access|activity|transaction)/i,
  /suspicious\s+(activity|login|sign[- ]?in)/i,
  /your\s+account\s+(is|was)\s+(compromised|hacked|breached)/i,
];

const CREDENTIAL_PATTERNS = [
  /verify\s+your\s+(identity|account|email|password|credentials)/i,
  /confirm\s+your\s+(identity|account|email|password|credentials)/i,
  /update\s+your\s+(password|credentials|payment|billing|security)/i,
  /enter\s+your\s+(password|credentials|ssn|social\s+security)/i,
  /(sign|log)\s*in\s+to\s+(verify|confirm|secure|restore|unlock)/i,
  /reset\s+your\s+password/i,
];

const FINANCIAL_PATTERNS = [
  /wire\s+transfer/i,
  /gift\s+card/i,
  /bitcoin|cryptocurrency/i,
  /bank\s+(account|details|transfer|routing)/i,
  /send\s+(money|funds|payment|code|pin)/i,
  /western\s+union/i,
  /moneygram/i,
  /itunes\s+card/i,
  /share\s+(your|the)\s+(code|pin|otp|token)/i,
];

function matchAny(text, patterns) {
  return patterns.some((p) => p.test(text));
}

/**
 * Content / Social Engineering category (cap: 20).
 *
 * Explicit urgency/time pressure:     +5
 * Explicit threat/consequence:        +5
 * Credential/sensitive-data request:  +15
 * Unusual financial request:          +15
 */
function scoreContent({ subject, bodyText }) {
  let score = 0;
  const findings = [];

  const text = ((subject || "") + " " + (bodyText || "")).substring(0, 50000);

  if (matchAny(text, URGENCY_PATTERNS)) {
    score += 5;
    findings.push("Email contains urgent language pressuring immediate action");
  }

  if (matchAny(text, THREAT_PATTERNS)) {
    score += 5;
    findings.push(
      "Email threatens negative consequences such as account suspension"
    );
  }

  if (matchAny(text, CREDENTIAL_PATTERNS)) {
    score += 15;
    findings.push("Email requests verification of credentials or sensitive data");
  }

  if (matchAny(text, FINANCIAL_PATTERNS)) {
    score += 15;
    findings.push(
      "Email contains an unusual financial request such as wire transfer or gift cards"
    );
  }

  return {
    score: Math.min(score, CATEGORY_CAP),
    findings,
  };
}

module.exports = { scoreContent };
