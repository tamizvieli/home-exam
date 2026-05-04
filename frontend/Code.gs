/**
 * Malicious Email Scorer - Gmail Add-on Frontend
 * Backend: FastAPI (Python)
 * Frontend: Google Apps Script + Card Service
 */


const API_BASE_URL = 'https://home-exam-1.onrender.com';

// ===== CARD BUILDERS =====

/**
 * Creates the initial homepage card with "Analyze Email" button
 */
function buildHomepage(e) {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Malicious Email Scorer')
      .setSubtitle('Security Analysis')
      .setImageUrl('https://www.gstatic.com/images/icons/material/system/1x/security_googblue_48dp.png')
    )
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText('Click below to analyze this email for potential security threats.')
      )
      .addWidget(CardService.newTextButton()
        .setText('🔍 Analyze Email')
        .setOnClickAction(CardService.newAction()
          .setFunctionName('analyzeEmail')
        )
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      )
    )
    .build();

  return [card];
}

/**
 * Main entry point for Gmail contextual trigger
 */
function onGmailMessageOpen(e) {
  return buildHomepage(e);
}

// ===== EMAIL ANALYSIS =====

/**
 * Analyzes the current email when button is clicked
 */
function analyzeEmail(e) {
  try {
    // Get the current message
    const messageId = e.gmail.messageId;
    const accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);
    const message = GmailApp.getMessageById(messageId);

    // Extract email data
    const emailData = extractEmailData(message);

    // Call backend API
    const result = callBackendAPI(emailData);

    // Build result card
    return buildResultCard(result);

  } catch (error) {
    Logger.log('Analysis error: ' + error);
    return buildErrorCard(error.toString());
  }
}

/**
 * Extracts required data from Gmail message
 */
function extractEmailData(message) {
  // Sender
  const sender = message.getFrom();

  // Subject
  const subject = message.getSubject();

  // Body (HTML and plain text)
  const bodyHtml = message.getBody();
  const bodyText = message.getPlainBody();

  // Attachment extensions
  const attachments = message.getAttachments();
  const attachmentExtensions = attachments.map(att => {
    const name = att.getName();
    const lastDot = name.lastIndexOf('.');
    return lastDot !== -1 ? name.substring(lastDot) : '';
  }).filter(ext => ext !== '');

  // Headers - try to get authentication_results
  let authResults = '';
  try {
    const rawContent = message.getRawContent();
    const authMatch = rawContent.match(/Authentication-Results: ([^\n]+)/i);
    if (authMatch && authMatch[1]) {
      authResults = authMatch[1].trim();
    }
  } catch (e) {
    Logger.log('Could not extract authentication header: ' + e);
    authResults = '';
  }

  return {
    sender: sender,
    subject: subject,
    body_html: bodyHtml,
    body_text: bodyText,
    attachment_extensions: attachmentExtensions,
    headers: {
      authentication_results: authResults
    }
  };
}

/**
 * Calls the backend API with email data
 */
function callBackendAPI(emailData) {
  const url = API_BASE_URL + '/analyze';

  const options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(emailData),
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(url, options);
    const statusCode = response.getResponseCode();

    if (statusCode !== 200) {
      throw new Error('Backend returned status ' + statusCode + ': ' + response.getContentText());
    }

    const result = JSON.parse(response.getContentText());
    return result;

  } catch (error) {
    throw new Error('API call failed: ' + error.toString());
  }
}

// ===== UI BUILDERS =====

/**
 * Builds the result card displaying analysis results
 */
function buildResultCard(result) {
  const score = result.score;
  const riskLevel = result.risk_level;
  const verdict = result.verdict;
  const explanations = result.explanations || [];

  // Determine color and icon based on risk level
  let scoreColor = '#00AA00';  // Green
  let iconUrl = 'https://www.gstatic.com/images/icons/material/system/1x/check_circle_googgreen_48dp.png';
  let riskText = '✅ בטוח';

  if (riskLevel === 'suspicious') {
    scoreColor = '#FF8800';  // Orange
    iconUrl = 'https://www.gstatic.com/images/icons/material/system/1x/warning_googyellow_48dp.png';
    riskText = '⚠️ חשוד';
  } else if (riskLevel === 'dangerous') {
    scoreColor = '#DD0000';  // Red
    iconUrl = 'https://www.gstatic.com/images/icons/material/system/1x/error_googred_48dp.png';
    riskText = '🚨 מסוכן';
  }

  // Build card
  const cardBuilder = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('תוצאות ניתוח אבטחה')
      .setImageUrl(iconUrl)
    );

  // Score section
  const scoreSection = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('ציון סיכון (Risk Score)')
      .setText('<b><font color="' + scoreColor + '">' + score + '/100</font></b>')
      .setWrapText(true)
    )
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('רמת סיכון (Risk Level)')
      .setText('<b>' + riskText + '</b>')
      .setWrapText(true)
    );

  cardBuilder.addSection(scoreSection);

  // Verdict section
  if (verdict) {
    const verdictSection = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText('<b>פסק דין:</b><br>' + verdict)
      );
    cardBuilder.addSection(verdictSection);
  }

  // Explanations section
  if (explanations.length > 0) {
    const explanationsSection = CardService.newCardSection()
      .setHeader('הסברים מפורטים');

    explanations.forEach((explanation, index) => {
      explanationsSection.addWidget(CardService.newTextParagraph()
        .setText('• ' + explanation)
      );
    });

    cardBuilder.addSection(explanationsSection);
  }

  // Re-analyze button
  const actionsSection = CardService.newCardSection()
    .addWidget(CardService.newTextButton()
      .setText('🔄 נתח מחדש')
      .setOnClickAction(CardService.newAction()
        .setFunctionName('analyzeEmail')
      )
    );

  cardBuilder.addSection(actionsSection);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation()
      .updateCard(cardBuilder.build())
    )
    .build();
}

/**
 * Builds an error card when something goes wrong
 */
function buildErrorCard(errorMessage) {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('שגיאה בניתוח')
      .setImageUrl('https://www.gstatic.com/images/icons/material/system/1x/error_googred_48dp.png')
    )
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText('<b>לא ניתן לנתח את האימייל</b><br><br>אנא ודא שהשרת פועל וכתובת ה-API מוגדרת נכון.')
      )
      .addWidget(CardService.newDecoratedText()
        .setTopLabel('פרטי שגיאה טכניים')
        .setText('<font color="#666666"><i>' + errorMessage + '</i></font>')
        .setWrapText(true)
      )
      .addWidget(CardService.newTextButton()
        .setText('🔄 נסה שוב')
        .setOnClickAction(CardService.newAction()
          .setFunctionName('analyzeEmail')
        )
      )
    )
    .build();

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation()
      .updateCard(card)
    )
    .build();
}


