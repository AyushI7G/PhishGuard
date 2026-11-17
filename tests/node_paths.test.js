const assert = require('assert');
const { computeUnifiedThreatScore, riskLevelFromScore } = require('../backend/engine/classifier');
const { blendScores } = require('../backend/engine/mlClient');
const { analyzeAttachment } = require('../backend/engine/attachmentAnalyzer');
const { parseEmailHeaders } = require('../backend/features/extractors');

const reported = `From: "PayPal Security" <security-alert@paypa1-account-update.xyz>
Received-SPF: fail
Subject: URGENT: Your PayPal Account Has Been Suspended! Verify Identity
You must verify your password and banking details within 24 hours to prevent permanent account termination.
Click here immediately: http://verify-paypal-user.security-update.xyz/login`;

const result = computeUnifiedThreatScore(reported, 'PayPal Security <security-alert@paypa1-account-update.xyz>');
assert.strictEqual(result.classification, 'Phishing');
assert.ok(result.finalScore >= 0.6);
assert.ok(Object.keys(result.shapFeatures).length > 0);

const gmailLike = computeUnifiedThreatScore(
  'Authentication-Results: spf=pass dkim=pass dmarc=pass\nRoutine project update and meeting notes.',
  'Sarah Miller <sarah.miller@acme-corp.com>'
);
assert.notStrictEqual(gmailLike.classification, 'Phishing');
assert.strictEqual(riskLevelFromScore(0.61), 'Medium');
assert.strictEqual(riskLevelFromScore(0.70), 'High');
assert.strictEqual(riskLevelFromScore(0.27), 'Low');
assert.strictEqual(riskLevelFromScore(0.28), 'Medium');

// This reproduces the reported integration shape: no sender/header metadata
// and a moderate ML probability, so the content evidence must carry the blend.
const bodyOnly = `URGENT: Your PayPal Account Has Been Suspended! Verify Identity
Dear Valued Customer,
We detected multiple unauthorized sign-in attempts to your PayPal account from unknown IP 194.26.29.11.
For your safety, YOUR ACCOUNT HAS BEEN TEMPORARILY SUSPENDED.
You must verify your password and banking details within 24 hours to prevent permanent account termination.
Click here immediately!`;
const bodyOnlyResult = computeUnifiedThreatScore(bodyOnly, '');
assert.strictEqual(bodyOnlyResult.classification, 'Phishing');
assert.strictEqual(blendScores(bodyOnlyResult.finalScore, 0.6816), 0.78);

const forgedAuthentication = `Routine project update.

Authentication-Results: spf=pass dkim=pass dmarc=pass
Please review the attached document.`;
const parsedForgedAuthentication = parseEmailHeaders(forgedAuthentication);
assert.strictEqual(parsedForgedAuthentication.hasAuthenticationResults, false);
assert.strictEqual(parsedForgedAuthentication.spf, null);

const macroAttachment = analyzeAttachment(Buffer.from(''), 'invoice.docm');
assert.strictEqual(macroAttachment.classification, 'Suspicious');
assert.ok(macroAttachment.detected_signals.some(signal => signal.includes('Macro-enabled Office attachment')));
assert.ok(Math.abs(Object.values(macroAttachment.probabilities).reduce((sum, probability) => sum + probability, 0) - 1) < 1e-9);

for (const attachment of [
  macroAttachment,
  analyzeAttachment(Buffer.from(''), 'invoice.pdf'),
  analyzeAttachment(Buffer.from('MZ'), 'invoice.pdf.exe')
]) {
  assert.ok(Math.abs(Object.values(attachment.probabilities).reduce((sum, probability) => sum + probability, 0) - 1) < 1e-9);
  const predictedClass = Object.entries(attachment.probabilities).sort((a, b) => b[1] - a[1])[0][0];
  assert.strictEqual(predictedClass, attachment.classification.toLowerCase());
}

const suspiciousUrl = computeUnifiedThreatScore('Please visit http://account-check.example.xyz/login', '');
assert.ok(suspiciousUrl.urlAnalysisList[0].diagnostics.classification !== 'Legitimate');

console.log('Node manual/Gmail-style classifier paths passed');
