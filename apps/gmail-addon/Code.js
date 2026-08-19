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
 * Placeholder handler for the Analyze button.
 * Shows a temporary result card (no backend call yet).
 */
function onAnalyzeClick(e) {
  var header = CardService.newCardHeader()
    .setTitle("Analysis Result");

  var scoreWidget = CardService.newKeyValue()
    .setTopLabel("Score")
    .setContent("—");

  var verdictWidget = CardService.newKeyValue()
    .setTopLabel("Verdict")
    .setContent("Not connected to backend yet");

  var reasonsWidget = CardService.newTextParagraph()
    .setText("Backend integration coming soon.");

  var section = CardService.newCardSection()
    .addWidget(scoreWidget)
    .addWidget(verdictWidget)
    .addWidget(reasonsWidget);

  var card = CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}
