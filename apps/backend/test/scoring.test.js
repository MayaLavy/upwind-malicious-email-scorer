const { analyzeEmail } = require("../src/services/analyzer");

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
    expectedVerdict: "Suspicious",
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
    expectedVerdict: "Suspicious",
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
    expectedVerdict: "Low Risk",
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
    expectedVerdict: "Suspicious",
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
];

let failed = false;

for (const test of tests) {
  const result = analyzeEmail(test.input);
  const scoreMatches = result.score === test.expectedScore;
  const verdictMatches = result.verdict === test.expectedVerdict;

  let breakdownMatches = true;
  if (test.expectedBreakdown) {
    for (const [category, expectedScore] of Object.entries(test.expectedBreakdown)) {
      if (!result.breakdown[category] || result.breakdown[category].score !== expectedScore) {
        breakdownMatches = false;
        break;
      }
    }
  }

  const passed = scoreMatches && verdictMatches && breakdownMatches;

  console.log(`\n${test.name}`);
  console.log(
    `  Expected: score=${test.expectedScore}, verdict="${test.expectedVerdict}"`
  );
  console.log(
    `  Actual:   score=${result.score}, verdict="${result.verdict}"`
  );

  if (test.expectedBreakdown) {
    for (const [category, expectedScore] of Object.entries(test.expectedBreakdown)) {
      console.log(
        `  Breakdown ${category}: expected=${expectedScore}, actual=${result.breakdown[category].score}`
      );
    }
  }

  console.log(`  Result:   ${passed ? "PASS" : "FAIL"}`);

  if (!passed) {
    failed = true;
  }
}

if (failed) {
  process.exit(1);
}
