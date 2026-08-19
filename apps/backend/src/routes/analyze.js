const express = require("express");
const { analyzeEmail } = require("../services/analyzer");

const router = express.Router();

const REQUIRED_FIELDS = ["subject", "from", "bodyText", "urls"];

function validatePayload(body) {
  const missing = REQUIRED_FIELDS.filter((field) => !(field in body));

  if (missing.length > 0) {
    return `Missing required fields: ${missing.join(", ")}`;
  }

  if (typeof body.subject !== "string") {
    return "Field 'subject' must be a string";
  }

  if (typeof body.from !== "string") {
    return "Field 'from' must be a string";
  }

  if (typeof body.bodyText !== "string") {
    return "Field 'bodyText' must be a string";
  }

  if (!Array.isArray(body.urls) || !body.urls.every((url) => typeof url === "string")) {
    return "Field 'urls' must be an array of strings";
  }

  if (body.replyTo !== undefined && typeof body.replyTo !== "string") {
    return "Field 'replyTo' must be a string";
  }

  if (body.authenticationResults !== undefined && typeof body.authenticationResults !== "string") {
    return "Field 'authenticationResults' must be a string";
  }

  if (body.bodyHtml !== undefined && typeof body.bodyHtml !== "string") {
    return "Field 'bodyHtml' must be a string";
  }

  return null;
}

router.post("/", (req, res) => {
  const validationError = validatePayload(req.body);

  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const emailData = {
    subject: req.body.subject,
    from: req.body.from,
    bodyText: req.body.bodyText,
    urls: req.body.urls,
    replyTo: req.body.replyTo || "",
    authenticationResults: req.body.authenticationResults || "",
    bodyHtml: req.body.bodyHtml || "",
  };

  const result = analyzeEmail(emailData);

  return res.json(result);
});

module.exports = router;
