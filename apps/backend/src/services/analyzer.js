const { scoreAuthentication } = require("./categories/authentication");
const { scoreImpersonation } = require("./categories/impersonation");
const { scoreUrlRisk } = require("./categories/urlRisk");
const { scoreReplyTo } = require("./categories/replyTo");
const { scoreContent } = require("./categories/content");
const { scoreCorroboration } = require("./categories/corroboration");

const VERDICT_THRESHOLDS = [
  { min: 60, label: "Likely Malicious" },
  { min: 30, label: "High Risk" },
  { min: 15, label: "Suspicious" },
  { min: 0, label: "Low Risk" },
];

function getVerdict(score) {
  for (const threshold of VERDICT_THRESHOLDS) {
    if (score >= threshold.min) return threshold.label;
  }
  return "Low Risk";
}

/**
 * Analyzes an email and returns a deterministic maliciousness score.
 *
 * @param {Object} emailData
 * @param {string} emailData.subject
 * @param {string} emailData.from
 * @param {string} emailData.bodyText
 * @param {string[]} emailData.urls
 * @param {string} [emailData.replyTo]
 * @param {string} [emailData.authenticationResults]
 * @param {string} [emailData.bodyHtml]
 *
 * @returns {{ score: number, verdict: string, reasons: string[], breakdown: Object }}
 */
function analyzeEmail(emailData) {
  const categoryResults = {
    authentication: scoreAuthentication(emailData),
    impersonation: scoreImpersonation(emailData),
    urlRisk: scoreUrlRisk(emailData),
    replyTo: scoreReplyTo(emailData),
    content: scoreContent(emailData),
  };

  const corroboration = scoreCorroboration(categoryResults);
  categoryResults.corroboration = corroboration;

  let rawScore = 0;
  const reasons = [];

  for (const result of Object.values(categoryResults)) {
    rawScore += result.score;
    reasons.push(...result.findings);
  }

  const finalScore = Math.min(100, rawScore);

  return {
    score: finalScore,
    verdict: getVerdict(finalScore),
    reasons,
    breakdown: Object.fromEntries(
      Object.entries(categoryResults).map(([key, val]) => [
        key,
        { score: val.score, findings: val.findings },
      ])
    ),
  };
}

module.exports = { analyzeEmail };
