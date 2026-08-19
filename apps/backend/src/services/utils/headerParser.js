/**
 * Parses an Authentication-Results header string and extracts
 * SPF, DKIM, and DMARC results.
 *
 * Only "fail" is treated as a penalizable result.
 * softfail, neutral, temperror, permerror, none, and missing
 * are all treated as non-penalizing.
 */
function parseAuthResults(headerValue) {
  const result = { spf: null, dkim: null, dmarc: null };

  if (!headerValue || typeof headerValue !== "string") {
    return result;
  }

  const lower = headerValue.toLowerCase();

  const spfMatch = lower.match(/spf\s*=\s*(\w+)/);
  if (spfMatch) result.spf = spfMatch[1];

  const dkimMatch = lower.match(/dkim\s*=\s*(\w+)/);
  if (dkimMatch) result.dkim = dkimMatch[1];

  const dmarcMatch = lower.match(/dmarc\s*=\s*(\w+)/);
  if (dmarcMatch) result.dmarc = dmarcMatch[1];

  return result;
}

/**
 * Returns true only for a hard "fail" result.
 * softfail, neutral, temperror, permerror, none → false.
 */
function isFail(value) {
  return value === "fail";
}

module.exports = { parseAuthResults, isFail };
