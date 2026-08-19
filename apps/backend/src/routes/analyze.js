const express = require("express");
const { analyzeEmail } = require("../services/mockAnalyzer");

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

  return null;
}

router.post("/", (req, res) => {
  const validationError = validatePayload(req.body);

  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const result = analyzeEmail();

  return res.json(result);
});

module.exports = router;
