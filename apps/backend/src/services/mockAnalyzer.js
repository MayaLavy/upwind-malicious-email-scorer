/**
 * Returns a hardcoded analysis result for MVP development.
 * Real detection logic will replace this later.
 */
function analyzeEmail() {
  return {
    score: 82,
    verdict: "Likely malicious",
    reasons: [
      "Sender domain looks suspicious",
      "Email contains urgent financial language",
      "Message includes a link with a mismatched destination",
    ],
  };
}

module.exports = { analyzeEmail };
