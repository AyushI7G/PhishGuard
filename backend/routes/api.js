// backend/routes/api.js
// Express API Router for PhishGuard - Robust Multi-Signal Phishing Detection Platform

const express = require('express');
const router = express.Router();
const { google } = require('googleapis');

const {
  extractSenderFeatures
} = require('../features/extractors');

const {
  computeUnifiedThreatScore,
  analyzeUrlThreat
} = require('../engine/classifier');

// Default sample inbox emails with multi-signal evidence
const DEFAULT_INBOX_EMAILS = [
  {
    id: 'msg-101',
    from: 'security-alert@paypa1-account-update.xyz',
    senderName: 'PayPal Security',
    subject: 'URGENT: Your PayPal Account Has Been Suspended! Verify Identity',
    date: '10:42 AM',
    snippet: 'We detected multiple unauthorized sign-in attempts to your account. Click here immediately to verify your identity before termination.',
    body: `From: "PayPal Security" <security-alert@paypa1-account-update.xyz>\nReceived-SPF: fail\nSubject: URGENT: Your PayPal Account Has Been Suspended! Verify Identity\n\nDear Valued Customer,\n\nWe detected multiple unauthorized sign-in attempts to your PayPal account from unknown IP 194.26.29.11.\n\nFor your safety, YOUR ACCOUNT HAS BEEN TEMPORARILY SUSPENDED.\n\nYou must verify your password and banking details within 24 hours to prevent permanent account termination.\n\nClick here immediately: http://verify-paypal-user.security-update.xyz/login\n\nUrgent action required!\n\nSecurity Team\nPayPal Inc.`,
    isStarred: true,
    isUnread: true
  },
  {
    id: 'msg-102',
    from: 'executive-office@wire-transfer-ceo.link',
    senderName: 'Chief Executive Officer',
    subject: 'CONFIDENTIAL: Urgent Wire Transfer Request for Vendor Acquisition',
    date: '09:15 AM',
    snippet: 'Are you at your desk right now? We need an immediate wire transfer of $48,500 processed for vendor escrow. Do not call my cell.',
    body: `From: "Chief Executive Officer" <executive-office@wire-transfer-ceo.link>\nReply-To: secret-offshore-escrow@yopmail.com\nSubject: CONFIDENTIAL: Urgent Wire Transfer Request for Vendor Acquisition\n\nAre you at your desk right now?\n\nI am currently in an urgent confidential meeting with acquisition attorneys. We need an immediate wire transfer of $48,500 processed for vendor escrow.\n\nDo not call my cell phone as I cannot talk. Confirm when you are ready and I will email you the account numbers to wire right away.\n\nRegards,\nChief Executive Officer`,
    isStarred: false,
    isUnread: true
  },
  {
    id: 'msg-103',
    from: 'sarah.miller@acme-corp.com',
    senderName: 'Sarah Miller',
    subject: 'Project Kickoff Q3: Slides & Agenda for Monday 10:00 AM',
    date: 'Yesterday',
    snippet: 'Hi everyone, I have finalized the agenda and quarterly targets for our Q3 strategy rollout. Please review the shared Google Doc.',
    body: `From: "Sarah Miller" <sarah.miller@acme-corp.com>\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: Project Kickoff Q3: Slides & Agenda for Monday 10:00 AM\n\nHi everyone,\n\nI have finalized the agenda and quarterly targets for our Q3 strategy rollout. Please review the shared Google Doc before our kickoff meeting on Monday at 10:00 AM PST.\n\nMeeting link: https://meet.google.com/abc-defg-hij\n\nBest regards,\nSarah Miller\nLead Product Architect`,
    isStarred: false,
    isUnread: false
  },
  {
    id: 'msg-104',
    from: 'cloud-noreply@google.com',
    senderName: 'Google Cloud Platform',
    subject: 'Monthly Cloud Billing Statement - Project ID: app-prod-412',
    date: 'Aug 28',
    snippet: 'Your monthly Google Cloud billing statement is now available in the Cloud Console.',
    body: `From: "Google Cloud Platform" <cloud-noreply@google.com>\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: Monthly Cloud Billing Statement - Project ID: app-prod-412\n\nHello Google Cloud Developer,\n\nYour billing statement for the previous billing period is now available. Your total usage charges were $14.20.\n\nYou can review your invoice and breakdowns directly in the Google Cloud Console: https://console.cloud.google.com/billing\n\nThank you for choosing Google Cloud.`,
    isStarred: true,
    isUnread: false
  }
];

let dynamicInbox = [...DEFAULT_INBOX_EMAILS];

// 1. Analyze email text, sender, headers, & URLs
router.post(['/predict', '/api/predict'], (req, res) => {
  const { email_text, sender_email, urls } = req.body;
  if (!email_text && !sender_email) {
    return res.status(400).json({ error: 'Please provide email_text or sender_email.' });
  }

  const text = email_text || '';
  const result = computeUnifiedThreatScore(text, sender_email, urls || []);

  const topEmailShap = {};
  Object.entries(result.shapFeatures).forEach(([k, v]) => {
    topEmailShap[k] = Math.round(v * 100) / 100;
  });

  let confidenceVal = 0.95;
  if (result.classification === 'Phishing') {
    confidenceVal = result.finalScore;
  } else if (result.classification === 'Legitimate') {
    confidenceVal = 1 - result.finalScore;
  } else {
    confidenceVal = 0.55 + Math.abs(result.finalScore - 0.45);
  }
  const confidenceScore = Math.max(50, Math.min(99, Math.round(confidenceVal * 100)));

  return res.json({
    threat_probability: result.finalScore,
    probability: result.finalScore,
    risk_score: result.risk_score,
    classification: result.classification,
    confidence_score: confidenceScore,
    confidence_label: `${confidenceScore}%`,
    detected_signals: result.detectedSignals,
    reasoning: generateReasoningSummary(result),
    top_email_text_features: topEmailShap,
    sender_analysis: {
      sender_email: result.senderFeats.parsed.raw || sender_email,
      domain: result.senderFeats.domain,
      classification: result.senderFeats.brandImpersonationFound || result.senderFeats.hasLookalike ? 'Phishing' : result.senderFeats.isTrusted ? 'Safe' : 'Suspicious',
      risk_score: result.senderFeats.brandImpersonationFound || result.senderFeats.hasLookalike ? 95 : result.senderFeats.isTrusted ? 5 : 45,
      features: result.senderFeats
    },
    header_analysis: result.headerFeats,
    url_analysis: result.urlAnalysisList,
    ml_features: {
      text_length: result.textFeats.num_chars,
      word_count: result.textFeats.num_words,
      entropy: result.textFeats.entropy,
      uppercase_ratio: result.textFeats.uppercase_ratio,
      psychological_pressure: result.textFeats.linguistic?.overallPsychologicalPressure || 0
    }
  });
});

// 2. Sender threat verification
router.post(['/predict_sender', '/api/predict_sender'], (req, res) => {
  const { sender_email } = req.body;
  if (!sender_email) {
    return res.status(400).json({ error: 'sender_email is required' });
  }

  const senderFeats = extractSenderFeatures(sender_email);
  const isPhish = senderFeats.brandImpersonationFound || senderFeats.hasLookalike || senderFeats.isDisposable;
  const isSuspicious = senderFeats.isSuspiciousTld || senderFeats.displayNameMismatch || (!senderFeats.isTrusted && senderFeats.domainEntropy > 3.8);

  let classification = 'Safe';
  let riskScore = 4;

  if (isPhish) {
    classification = 'Phishing';
    riskScore = 96;
  } else if (isSuspicious) {
    classification = 'Suspicious';
    riskScore = 65;
  } else if (senderFeats.isTrusted) {
    classification = 'Safe';
    riskScore = 2;
  }

  const detectedSignals = [];
  if (senderFeats.brandImpersonationFound) {
    detectedSignals.push(`Target Brand Impersonation: "${senderFeats.brandImpersonationFound}" used on unauthorized domain "${senderFeats.domain}"`);
  }
  if (senderFeats.hasLookalike) {
    const target = senderFeats.lookalikeDetails?.targetBrand || 'legitimate service';
    detectedSignals.push(`Typosquatting Lookalike: Domain "${senderFeats.domain}" mimics "${target}"`);
  }
  if (senderFeats.displayNameMismatch) {
    detectedSignals.push(senderFeats.displayNameSpoofingDetails || `Display Name Misalignment with originating email address`);
  }
  if (senderFeats.isSuspiciousTld) {
    detectedSignals.push(`High-Risk TLD (.${senderFeats.parsed.tld}) frequently leveraged in mass phishing campaigns`);
  }
  if (senderFeats.isDisposable) {
    detectedSignals.push(`Disposable / Temporary Email Service Provider (${senderFeats.domain})`);
  }
  if (senderFeats.isTrusted) {
    detectedSignals.push(`Verified Organization Domain (${senderFeats.domain}) with established sender reputation`);
  }
  if (!detectedSignals.length) {
    detectedSignals.push('Standard email address structure with no high-risk impersonation or spoofing markers.');
  }

  return res.json({
    sender_email,
    classification,
    risk_score: riskScore,
    detected_signals: detectedSignals,
    parsed_structure: senderFeats.parsed,
    heuristic_flags: {
      brand_impersonation: !!senderFeats.brandImpersonationFound,
      homoglyph_or_typo: !!senderFeats.hasLookalike,
      is_suspicious_tld: !!senderFeats.isSuspiciousTld,
      is_disposable_domain: !!senderFeats.isDisposable,
      is_trusted_enterprise: !!senderFeats.isTrusted,
      display_name_mismatch: !!senderFeats.displayNameMismatch
    },
    reasoning: isPhish 
      ? `This sender address exhibits active brand spoofing or deceptive lookalike characteristics (${senderFeats.brandImpersonationFound ? `Impersonating ${senderFeats.brandImpersonationFound}` : 'Typosquatting'}). High risk of credential theft.`
      : isSuspicious 
        ? `This sender domain has elevated anomaly indicators (uncommon TLD or role misalignment). Verify identity before trusting.`
        : `Sender domain belongs to established, legitimate infrastructure with clean reputation.`
  });
});

// 3. Scan URL route
router.post(['/predict_url', '/api/predict_url'], (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  const analysis = analyzeUrlThreat(url);
  return res.json({
    url,
    threat_probability: analysis.threat_probability,
    risk_score: Math.round(analysis.threat_probability * 100),
    classification: analysis.classification,
    flags: analysis.flags,
    features: analysis.features,
    reasoning: analysis.reasoning
  });
});

// 4. Gmail Inbox endpoints
router.get(['/inbox', '/api/inbox'], async (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const accessToken = authHeader.split(' ')[1].trim();
    if (accessToken) {
      try {
        const auth = new google.auth.OAuth2();
        auth.setCredentials({ access_token: accessToken });
        const gmail = google.gmail({ version: 'v1', auth });

        // Retrieve user profile / email
        let userEmail = '';
        try {
          const profile = await gmail.users.getProfile({ userId: 'me' });
          userEmail = profile.data.emailAddress || '';
        } catch (pErr) {
          console.warn('Profile fetch warning:', pErr.message);
        }

        // Fetch up to 25 latest inbox messages
        const listRes = await gmail.users.messages.list({
          userId: 'me',
          q: 'in:inbox',
          maxResults: 25
        });

        const messages = listRes.data.messages || [];
        
        const detailedEmails = await Promise.all(
          messages.map(async (m) => {
            try {
              const msg = await gmail.users.messages.get({
                userId: 'me',
                id: m.id,
                format: 'full'
              });

              const headers = msg.data.payload?.headers || [];
              const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || '(No Subject)';
              const from = headers.find(h => h.name.toLowerCase() === 'from')?.value || 'Unknown Sender';
              const dateRaw = headers.find(h => h.name.toLowerCase() === 'date')?.value || '';
              const spfHeader = headers.find(h => h.name.toLowerCase() === 'received-spf')?.value || '';
              const authResults = headers.find(h => h.name.toLowerCase() === 'authentication-results')?.value || '';
              
              const senderName = from.includes('<')
                ? from.split('<')[0].replace(/["']/g, '').trim()
                : from.split('@')[0];

              // Body extraction
              function decodePart(part) {
                if (!part) return '';
                if (part.body && part.body.data) {
                  return Buffer.from(part.body.data, 'base64').toString('utf-8');
                }
                if (part.parts && part.parts.length) {
                  for (const sub of part.parts) {
                    if (sub.mimeType === 'text/plain' && sub.body?.data) {
                      return Buffer.from(sub.body.data, 'base64').toString('utf-8');
                    }
                  }
                  for (const sub of part.parts) {
                    const found = decodePart(sub);
                    if (found) return found;
                  }
                }
                return '';
              }

              let body = decodePart(msg.data.payload) || msg.data.snippet || '';
              if (spfHeader || authResults) {
                body = `Authentication-Results: ${authResults || spfHeader}\n\n${body}`;
              }

              // Threat evaluation
              const analysis = computeUnifiedThreatScore(body, from);

              return {
                id: msg.data.id,
                threadId: msg.data.threadId,
                from,
                senderName,
                subject,
                date: dateRaw ? new Date(dateRaw).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Recent',
                snippet: msg.data.snippet || body.substring(0, 140),
                body,
                threat_probability: analysis.finalScore,
                classification: analysis.classification,
                detected_signals: analysis.detectedSignals,
                detected_features: analysis.detectedSignals,
                risk_score: analysis.risk_score,
                isStarred: msg.data.labelIds?.includes('STARRED') || false,
                isUnread: msg.data.labelIds?.includes('UNREAD') || false,
                isLiveGmail: true
              };
            } catch (err) {
              console.error('Error fetching message details for ' + m.id, err);
              return null;
            }
          })
        );

        const liveEmails = detailedEmails.filter(Boolean);

        const stats = {
          total: liveEmails.length,
          phishing: liveEmails.filter(e => e.classification === 'Phishing').length,
          suspicious: liveEmails.filter(e => e.classification === 'Suspicious').length,
          legitimate: liveEmails.filter(e => e.classification === 'Legitimate').length
        };

        return res.json({
          isLiveGmail: true,
          userEmail,
          emails: liveEmails,
          stats
        });
      } catch (oauthErr) {
        console.error('Gmail OAuth API Error:', oauthErr.message);
        return res.status(401).json({
          error: 'Gmail authorization expired or failed. Please reconnect your account.',
          details: oauthErr.message,
          isAuthError: true
        });
      }
    }
  }

  // Fallback to local mailbox if no token provided
  const analyzedInbox = dynamicInbox.map(email => {
    const analysis = computeUnifiedThreatScore(email.body, email.from);
    return {
      ...email,
      threat_probability: analysis.finalScore,
      classification: analysis.classification,
      detected_signals: analysis.detectedSignals,
      detected_features: analysis.detectedSignals,
      risk_score: analysis.risk_score
    };
  });

  const stats = {
    total: analyzedInbox.length,
    phishing: analyzedInbox.filter(e => e.classification === 'Phishing').length,
    suspicious: analyzedInbox.filter(e => e.classification === 'Suspicious').length,
    legitimate: analyzedInbox.filter(e => e.classification === 'Legitimate').length
  };

  return res.json({
    isLiveGmail: false,
    emails: analyzedInbox,
    stats
  });
});

router.post(['/inbox/add', '/api/inbox/add'], (req, res) => {
  const { from, subject, body } = req.body;
  if (!body || !from) return res.status(400).json({ error: 'from and body required' });
  
  const analysis = computeUnifiedThreatScore(body, from);
  
  const newEmail = {
    id: 'msg-' + Date.now(),
    from,
    senderName: from.includes('<') ? from.split('<')[0].replace(/["']/g, '').trim() : from.split('@')[0],
    subject: subject || '(No Subject)',
    date: 'Just now',
    snippet: body.substring(0, 120) + '...',
    body,
    threat_probability: analysis.finalScore,
    classification: analysis.classification,
    detected_signals: analysis.detectedSignals,
    detected_features: analysis.detectedSignals,
    risk_score: analysis.risk_score,
    isStarred: false,
    isUnread: true
  };

  dynamicInbox.unshift(newEmail);
  return res.json({ success: true, email: newEmail });
});

function generateReasoningSummary(result) {
  if (result.classification === 'Phishing') {
    const primaryReason = result.detectedSignals[0] || 'Multiple malicious vectors identified';
    return `Phishing threat confirmed with high probability (${result.risk_score}% risk). Evidence: ${primaryReason}. Do not interact, click links, or input credentials.`;
  } else if (result.classification === 'Suspicious') {
    return `Elevated risk indicators detected (${result.risk_score}% risk). The message exhibits anomalies in sender structure, destination URLs, or language pressure. Verify through an independent verified channel.`;
  } else {
    return `Legitimate communication profile (${result.risk_score}% risk). Verified authentication, standard syntax, and clean domain reputation confirmed with no deceptive markers.`;
  }
}

module.exports = router;
