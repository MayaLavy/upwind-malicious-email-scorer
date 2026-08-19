const { extractDomain } = require("../utils/domainHelpers");

const MAX_SCORE = 5;

/**
 * Reply-To anomaly (max: 5).
 *
 * From domain and Reply-To domain differ: +5
 * No Reply-To, or same domain:            +0
 */
function scoreReplyTo({ from, replyTo }) {
  if (!replyTo || typeof replyTo !== "string" || replyTo.trim() === "") {
    return { score: 0, findings: [] };
  }

  const fromDomain = extractDomain(from);
  const replyToDomain = extractDomain(replyTo);

  if (!fromDomain || !replyToDomain) {
    return { score: 0, findings: [] };
  }

  if (fromDomain !== replyToDomain) {
    return {
      score: MAX_SCORE,
      findings: [
        `Reply-To domain (${replyToDomain}) differs from sender domain (${fromDomain})`,
      ],
    };
  }

  return { score: 0, findings: [] };
}

module.exports = { scoreReplyTo };
