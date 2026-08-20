/**
 * Contextual trigger — called automatically when the user opens an email.
 * Reads subject and sender, then builds a card UI.
 */
function onGmailMessageOpen(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);

  var subject = message.getSubject();
  var sender = message.getFrom();

  return buildEmailCard(subject, sender);
}

/**
 * Builds the main card showing email info and an Analyze button.
 * Passes the messageId so the click handler can access the email.
 */
function buildEmailCard(subject, sender) {
  var header = CardService.newCardHeader()
    .setTitle("Malicious Email Scorer")
    .setImageUrl("https://www.gstatic.com/images/icons/material/system/1x/security_black_24dp.png");

  var subjectWidget = CardService.newKeyValue()
    .setTopLabel("Subject")
    .setContent(subject);

  var senderWidget = CardService.newKeyValue()
    .setTopLabel("From")
    .setContent(sender);

  var analyzeButton = CardService.newTextButton()
    .setText("Analyze Email")
    .setOnClickAction(
      CardService.newAction().setFunctionName("onAnalyzeClick")
    );

  var section = CardService.newCardSection()
    .addWidget(subjectWidget)
    .addWidget(senderWidget)
    .addWidget(analyzeButton);

  var card = CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();

  return [card];
}

/**
 * Extracts URLs from a text string.
 */
function extractUrls(text) {
  if (!text) return [];
  var urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  var matches = text.match(urlPattern);
  return matches ? matches : [];
}

/**
 * Extracts the raw Authentication-Results header from the message.
 */
function getAuthenticationResults(message) {
  try {
    return message.getHeader("Authentication-Results") || "";
  } catch (e) {
    return "";
  }
}

/**
 * Sends email data to the backend and returns the analysis result.
 * Throws on network or HTTP errors.
 */
function callBackend(subject, sender, bodyText, urls, replyTo, authenticationResults, bodyHtml) {
  var payload = {
    subject: subject,
    from: sender,
    bodyText: bodyText,
    urls: urls,
    replyTo: replyTo || "",
    authenticationResults: authenticationResults || "",
    bodyHtml: bodyHtml || ""
  };

  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  var response = UrlFetchApp.fetch(CONFIG.BACKEND_URL + "/analyze", options);
  var statusCode = response.getResponseCode();

  if (statusCode !== 200) {
    throw new Error("Backend returned status " + statusCode);
  }

  var json = JSON.parse(response.getContentText());

  if (typeof json.score === "undefined" || !json.verdict || !json.reasons) {
    throw new Error("Unexpected response format from backend");
  }

  return json;
}

/**
 * Forces English analysis text to render LTR inside an RTL Gmail host UI.
 * CardService has no text-direction API, so we wrap with Unicode LTR embedding.
 */
function asLtr(text) {
  if (text === null || text === undefined) {
    return "";
  }
  return "\u202A" + String(text) + "\u202C";
}

/**
 * Builds a card displaying the analysis result.
 * Uses one widget per reason so long findings wrap cleanly in the narrow sidebar.
 */
function buildResultCard(result) {
  var header = CardService.newCardHeader()
    .setTitle("Analysis Result");

  var summarySection = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel(asLtr("Score"))
        .setText(asLtr(result.score + " / 100"))
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel(asLtr("Verdict"))
        .setText(asLtr(result.verdict))
        .setWrapText(true)
    );

  var reasonsSection = CardService.newCardSection()
    .setHeader(asLtr("Reasons"));

  var reasons = result.reasons || [];
  if (reasons.length === 0) {
    reasonsSection.addWidget(
      CardService.newTextParagraph()
        .setText(asLtr("No suspicious signals detected"))
    );
  } else {
    for (var i = 0; i < reasons.length; i++) {
      reasonsSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(asLtr(String(i + 1)))
          .setText(asLtr(reasons[i]))
          .setWrapText(true)
      );
    }
  }

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(summarySection)
    .addSection(reasonsSection)
    .build();
}

/**
 * Builds a card displaying an error message.
 */
function buildErrorCard(errorMessage) {
  var header = CardService.newCardHeader()
    .setTitle("Analysis Error");

  var errorWidget = CardService.newTextParagraph()
    .setText(asLtr("Could not analyze this email:\n\n" + errorMessage));

  var section = CardService.newCardSection()
    .addWidget(errorWidget);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

/**
 * Click handler for the Analyze button.
 * Reads the email, calls the backend, and shows the result.
 */
function onAnalyzeClick(e) {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    var message = GmailApp.getMessageById(e.gmail.messageId);

    var subject = message.getSubject();
    var sender = message.getFrom();
    var bodyText = message.getPlainBody();
    var urls = extractUrls(bodyText);
    var replyTo = message.getReplyTo();
    var authenticationResults = getAuthenticationResults(message);
    var bodyHtml = message.getBody();

    var result = callBackend(subject, sender, bodyText, urls, replyTo, authenticationResults, bodyHtml);
    var card = buildResultCard(result);
  } catch (err) {
    var card = buildErrorCard(err.message);
  }

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}
