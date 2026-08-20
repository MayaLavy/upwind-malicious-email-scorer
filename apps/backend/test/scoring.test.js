const { analyzeEmail, getVerdict } = require("../src/services/analyzer");

const tests = [
  {
    name: "Test 1: Clean legitimate email",
    input: {
      subject: "Meeting notes from Monday",
      from: "alice@company.com",
      bodyText: "Hi, here are the meeting notes.",
      urls: [],
      replyTo: "",
      authenticationResults: "spf=pass dkim=pass dmarc=pass",
      bodyHtml: "",
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
  },
  {
    name: "Test 2: Auth failures",
    input: {
      subject: "Invoice attached",
      from: "billing@company.com",
      bodyText: "Please see attached invoice.",
      urls: [],
      replyTo: "",
      authenticationResults: "spf=fail dkim=fail dmarc=fail",
      bodyHtml: "",
    },
    expectedScore: 30,
    expectedVerdict: "High Risk",
    expectedReasonsContains: [
      "SPF authentication failed",
      "DKIM authentication failed",
      "DMARC authentication failed",
    ],
  },
  {
    name: "Test 3: Brand impersonation",
    input: {
      subject: "Your account has been compromised",
      from: "Microsoft Support <security@m1crosoft-support.com>",
      bodyText: "Your account was compromised. Click here to verify.",
      urls: ["https://m1crosoft-support.com/verify"],
      replyTo: "",
      authenticationResults: "",
      bodyHtml: "",
    },
    expectedScore: 30,
    expectedVerdict: "High Risk",
    expectedReasonsContains: [
      "Display name claims to be microsoft but sender domain is m1crosoft-support.com",
    ],
  },
  {
    name: "Test 4: URL risk",
    input: {
      subject: "Check this out",
      from: "friend@gmail.com",
      bodyText: "Click here: https://bit.ly/abc123",
      urls: ["https://bit.ly/abc123"],
      replyTo: "",
      authenticationResults: "",
      bodyHtml: '<a href="https://evil.com/steal">https://paypal.com/login</a>',
    },
    expectedScore: 25,
    expectedVerdict: "Suspicious",
    expectedReasonsContains: [
      "Email contains a shortened URL (bit.ly)",
      'Link displays "https://paypal.com/login" but actually points to evil.com',
    ],
  },
  {
    name: "Test 5: Full phishing",
    input: {
      subject: "Urgent: Your account will be suspended",
      from: "PayPal Security <security@paypa1.com>",
      bodyText:
        "Your account will be suspended within 24 hours. Verify your credentials immediately at the link below.",
      urls: ["https://paypa1.com/verify"],
      replyTo: "",
      authenticationResults: "spf=fail dkim=fail dmarc=fail",
      bodyHtml: "",
    },
    expectedScore: 100,
    expectedVerdict: "Likely Malicious",
  },
  {
    name: "Test 6: BEC financial scam",
    input: {
      subject: "Urgent wire transfer needed",
      from: "ceo@company.com",
      bodyText:
        "Please process this wire transfer immediately. The payment must go out today.",
      urls: [],
      replyTo: "ceo@gmail.com",
      authenticationResults: "",
      bodyHtml: "",
    },
    expectedScore: 30,
    expectedVerdict: "High Risk",
    expectedReasonsContains: [
      "Email contains an unusual financial request such as wire transfer or gift cards",
      "Financial request combined with Reply-To domain mismatch (BEC pattern)",
    ],
  },
  {
    name: "Test 7: Reply-To mismatch only",
    input: {
      subject: "Newsletter signup",
      from: "news@company.com",
      bodyText: "Thanks for signing up for our newsletter.",
      urls: [],
      replyTo: "replies@mailchimp.com",
      authenticationResults: "",
      bodyHtml: "",
    },
    expectedScore: 5,
    expectedVerdict: "Low Risk",
  },
  {
    name: "Regression 1: Displayed domain punctuation should not mismatch",
    input: {
      subject: "Order update",
      from: "orders@marketplace.com",
      bodyText: "View your order details.",
      urls: [],
      replyTo: "",
      authenticationResults: "",
      bodyHtml:
        '<a href="https://www.aliexpress.com/item/123">www.AliExpress.com.</a>',
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { urlRisk: 0 },
  },
  {
    name: "Regression 2: Reply-To subdomain family should not mismatch",
    input: {
      subject: "Service notification",
      from: "updates@service.tiktok.com",
      bodyText: "Here is your account update.",
      urls: [],
      replyTo: "reply@tiktok.com",
      authenticationResults: "",
      bodyHtml: "",
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { replyTo: 0 },
  },
  {
    name: "Regression 3: Truly different Reply-To domain should still mismatch",
    input: {
      subject: "Service notification",
      from: "updates@company.com",
      bodyText: "Here is your account update.",
      urls: [],
      replyTo: "reply@gmail.com",
      authenticationResults: "",
      bodyHtml: "",
    },
    expectedScore: 5,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { replyTo: 5 },
  },
  {
    name: "Regression 4: Displayed email address should not trigger link mismatch",
    input: {
      subject: "Weekly offers",
      from: "newsletter@superpharm.co.il",
      bodyText: "Browse this week's offers.",
      urls: [
        "https://links.email.superpharm.co.il/1",
        "https://links.email.superpharm.co.il/2",
        "https://links.email.superpharm.co.il/3",
        "https://links.email.superpharm.co.il/4",
        "https://links.email.superpharm.co.il/5",
        "https://links.email.superpharm.co.il/6",
        "https://links.email.superpharm.co.il/7",
        "https://links.email.superpharm.co.il/8",
        "https://links.email.superpharm.co.il/9",
        "https://links.email.superpharm.co.il/10",
        "https://links.email.superpharm.co.il/11",
        "https://links.email.superpharm.co.il/12",
        "https://links.email.superpharm.co.il/13",
        "https://links.email.superpharm.co.il/14",
        "https://links.email.superpharm.co.il/15",
        "https://links.email.superpharm.co.il/16",
        "https://links.email.superpharm.co.il/17",
        "https://links.email.superpharm.co.il/18",
      ],
      replyTo: "",
      authenticationResults: "",
      bodyHtml:
        '<a href="https://links.email.superpharm.co.il/click?id=123">NLcustomers@SuperPharm.co.il</a>',
    },
    expectedScore: 5,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { urlRisk: 5 },
  },
  {
    name: "Regression 5: Quoted Reply-To domain should not mismatch",
    input: {
      subject: "Weekly offers",
      from: "newsletter@super-pharm.co.il",
      bodyText: "Browse this week's offers.",
      urls: [],
      replyTo: "\"Super-Pharm\" <offers@super-pharm.co.il\">",
      authenticationResults: "",
      bodyHtml: "",
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { replyTo: 0 },
  },
  {
    name: "Regression 6: Same-family displayed link and href should not mismatch",
    input: {
      subject: "Order update",
      from: "orders@aldoshoes.com",
      bodyText: "Track your order.",
      urls: [],
      replyTo: "",
      authenticationResults: "",
      bodyHtml:
        '<a href="https://trk.send.aldoshoes.com/click/123">aldoshoes.com</a>',
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { urlRisk: 0 },
  },
  {
    name: "Auth non-fail: SPF softfail should not add auth points",
    input: {
      subject: "Account update",
      from: "noreply@company.com",
      bodyText: "Your settings were updated.",
      urls: [],
      replyTo: "",
      authenticationResults: "spf=softfail dkim=pass dmarc=pass",
      bodyHtml: "",
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { authentication: 0 },
  },
  {
    name: "Auth non-fail: SPF/DKIM/DMARC neutral should not add auth points",
    input: {
      subject: "Account update",
      from: "noreply@company.com",
      bodyText: "Your settings were updated.",
      urls: [],
      replyTo: "",
      authenticationResults: "spf=neutral dkim=neutral dmarc=neutral",
      bodyHtml: "",
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { authentication: 0 },
  },
  {
    name: "Auth non-fail: DKIM none / SPF none should not add auth points",
    input: {
      subject: "Account update",
      from: "noreply@company.com",
      bodyText: "Your settings were updated.",
      urls: [],
      replyTo: "",
      authenticationResults: "spf=none dkim=none dmarc=pass",
      bodyHtml: "",
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { authentication: 0 },
  },
  {
    name: "Auth non-fail: missing Authentication-Results should not add auth points",
    input: {
      subject: "Account update",
      from: "noreply@company.com",
      bodyText: "Your settings were updated.",
      urls: [],
      replyTo: "",
      authenticationResults: "",
      bodyHtml: "",
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { authentication: 0 },
  },
  {
    name: "Auth non-fail: temperror/permerror should not add auth points",
    input: {
      subject: "Account update",
      from: "noreply@company.com",
      bodyText: "Your settings were updated.",
      urls: [],
      replyTo: "",
      authenticationResults: "spf=temperror dkim=permerror dmarc=pass",
      bodyHtml: "",
    },
    expectedScore: 0,
    expectedVerdict: "Low Risk",
    expectedBreakdown: { authentication: 0 },
  },
  {
    name: "Global score cap: raw category total exceeds 100",
    input: {
      subject: "Urgent: Your account will be suspended",
      from: "PayPal Security <security@paypa1.com>",
      bodyText:
        "Your account will be suspended within 24 hours. Verify your credentials immediately at the link below.",
      urls: ["https://paypa1.com/verify"],
      replyTo: "attacker@gmail.com",
      authenticationResults: "spf=fail dkim=fail dmarc=fail",
      bodyHtml: "",
    },
    expectedScore: 100,
    expectedVerdict: "Likely Malicious",
    expectCategorySumAboveFinal: true,
  },
];

const verdictBoundaryCases = [
  { score: 14, expected: "Low Risk" },
  { score: 15, expected: "Suspicious" },
  { score: 29, expected: "Suspicious" },
  { score: 30, expected: "High Risk" },
  { score: 59, expected: "High Risk" },
  { score: 60, expected: "Likely Malicious" },
];

let failed = false;

function assert(condition, message) {
  if (!condition) {
    console.log(`  FAIL: ${message}`);
    failed = true;
    return false;
  }
  return true;
}

console.log("\n=== Verdict threshold boundaries (via getVerdict) ===");
console.log(
  "Note: boundaries are tested through exported getVerdict() so exact scores do not require artificial email fixtures."
);
for (const boundary of verdictBoundaryCases) {
  const actual = getVerdict(boundary.score);
  const passed = actual === boundary.expected;
  console.log(
    `\nVerdict boundary ${boundary.score}: expected="${boundary.expected}", actual="${actual}"`
  );
  console.log(`  Result:   ${passed ? "PASS" : "FAIL"}`);
  if (!passed) failed = true;
}

for (const test of tests) {
  const result = analyzeEmail(test.input);
  let passed = true;

  console.log(`\n${test.name}`);
  console.log(
    `  Expected: score=${test.expectedScore}, verdict="${test.expectedVerdict}"`
  );
  console.log(
    `  Actual:   score=${result.score}, verdict="${result.verdict}"`
  );

  passed =
    assert(result.score === test.expectedScore, "score mismatch") && passed;
  passed =
    assert(result.verdict === test.expectedVerdict, "verdict mismatch") &&
    passed;

  if (test.expectedBreakdown) {
    for (const [category, expectedScore] of Object.entries(
      test.expectedBreakdown
    )) {
      const actualScore = result.breakdown[category]
        ? result.breakdown[category].score
        : undefined;
      console.log(
        `  Breakdown ${category}: expected=${expectedScore}, actual=${actualScore}`
      );
      passed =
        assert(
          actualScore === expectedScore,
          `breakdown ${category} score mismatch`
        ) && passed;
    }
  }

  if (test.expectedReasonsContains) {
    for (const reason of test.expectedReasonsContains) {
      passed =
        assert(
          result.reasons.includes(reason),
          `missing expected reason: ${reason}`
        ) && passed;
      console.log(`  Reason check: "${reason}" -> ${result.reasons.includes(reason) ? "found" : "MISSING"}`);
    }
  }

  if (test.expectCategorySumAboveFinal) {
    const categorySum = Object.values(result.breakdown).reduce(
      (sum, cat) => sum + cat.score,
      0
    );
    console.log(
      `  Category sum=${categorySum}, final score=${result.score}`
    );
    passed =
      assert(
        categorySum > 100,
        `expected uncapped category sum > 100, got ${categorySum}`
      ) && passed;
    passed =
      assert(result.score === 100, "final score should be capped at 100") &&
      passed;
  }

  console.log(`  Result:   ${passed ? "PASS" : "FAIL"}`);
  if (!passed) failed = true;
}

if (failed) {
  process.exit(1);
}
