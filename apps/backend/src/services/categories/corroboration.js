const BONUS = 10;

const FINANCIAL_FINDING_PATTERN = /unusual financial request/i;

/**
 * Corroboration bonus (max: 10).
 *
 * Awarded only when:
 * - At least two different categories are active (score > 0), AND
 * - At least one of those categories is Authentication, Impersonation, or URL Risk.
 *
 * Examples:
 *   Impersonation + Credential Request      → bonus
 *   Suspicious URL + Urgency                → bonus
 *   Auth failure + Reply-To mismatch        → bonus
 *   Urgency + Credential Request            → NO bonus (both are Content)
 *   Urgency + Reply-To mismatch             → NO bonus (no strong category)
 */
function scoreCorroboration(categoryResults) {
  let score = 0;
  const findings = [];

  const strongCategories = ["authentication", "impersonation", "urlRisk"];
  const allCategories = [
    "authentication",
    "impersonation",
    "urlRisk",
    "replyTo",
    "content",
  ];

  const activeCategories = allCategories.filter(
    (cat) => categoryResults[cat] && categoryResults[cat].score > 0
  );

  if (activeCategories.length >= 2) {
    const hasStrongCategory = activeCategories.some((cat) =>
      strongCategories.includes(cat)
    );

    const hasOtherCategory = activeCategories.some(
      (cat) => !strongCategories.includes(cat)
    );

    const multipleStrongCategories =
      activeCategories.filter((cat) => strongCategories.includes(cat)).length >= 2;

    if (hasStrongCategory && (hasOtherCategory || multipleStrongCategories)) {
      score += BONUS;
      findings.push(
        "Multiple suspicious signals detected across different categories"
      );
    }
  }

  // BEC corroboration: financial request + Reply-To domain mismatch.
  // This is a narrowly scoped rule for business email compromise scenarios.
  // It does NOT apply to other Content + Reply-To combinations.
  const hasFinancialRequest =
    categoryResults.content &&
    categoryResults.content.findings.some((f) => FINANCIAL_FINDING_PATTERN.test(f));

  const hasReplyToMismatch =
    categoryResults.replyTo && categoryResults.replyTo.score > 0;

  if (hasFinancialRequest && hasReplyToMismatch && score === 0) {
    score += BONUS;
    findings.push(
      "Financial request combined with Reply-To domain mismatch (BEC pattern)"
    );
  }

  return { score, findings };
}

module.exports = { scoreCorroboration };
