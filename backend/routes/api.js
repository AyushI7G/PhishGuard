// backend/routes/api.js
// Express API Router for PhishGuard - Robust Multi-Signal Phishing Detection Platform

const express = require('express');
const router = express.Router();
const multer = require('multer');
const { google } = require('googleapis');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});
const MAX_GMAIL_ATTACHMENT_BYTES = 35 * 1024 * 1024;
const parseAttachmentUpload = (req, res, next) => {
  upload.single('file')(req, res, err => {
    if (!err) return next();
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ error: status === 413 ? 'Attachment exceeds the 50 MB upload limit.' : err.message });
  });
};

const {
  extractSenderFeatures
} = require('../features/extractors');

const {
  computeUnifiedThreatScore,
  analyzeUrlThreat,
  riskLevelFromScore
} = require('../engine/classifier');

const {
  analyzeAttachment
} = require('../engine/attachmentAnalyzer');

const {
  blendScores,
  classifyFromScore,
  getAttachmentMetrics,
  mergeShap,
  mlHealth,
  predictAttachment,
  predictEmail,
  predictEmailBatch,
  predictUrl
} = require('../engine/mlClient');

// Default sample inbox emails with multi-signal evidence and attachments
const DEFAULT_INBOX_EMAILS = [
  {
    id: 'msg-101',
    from: 'security-alert@paypa1-account-update.xyz',
    senderName: 'PayPal Security',
    subject: 'URGENT: Your PayPal Account Has Been Suspended! Verify Identity',
    date: '10:42 AM',
    snippet: 'We detected multiple unauthorized sign-in attempts to your account. Click here immediately to verify your identity before termination.',
    body: `From: "PayPal Security" <security-alert@paypa1-account-update.xyz>\nReceived-SPF: fail\nSubject: URGENT: Your PayPal Account Has Been Suspended! Verify Identity\n\nDear Valued Customer,\n\nWe detected multiple unauthorized sign-in attempts to your PayPal account from unknown IP 194.26.29.11.\n\nFor your safety, YOUR ACCOUNT HAS BEEN TEMPORARILY SUSPENDED.\n\nYou must verify your password and banking details within 24 hours to prevent permanent account termination.\n\nClick here immediately: http://verify-paypal-user.security-update.xyz/login\n\nPlease find the attached dispute form for review.\n\nUrgent action required!\n\nSecurity Team\nPayPal Inc.`,
    isStarred: true,
    isUnread: true,
    attachments: [
      {
        filename: 'Dispute_Resolution_Form.pdf.exe',
        file_size: 148200,
        formatted_size: '144.7 KB',
        classification: 'Malicious',
        risk_score: 98,
        detected_signals: [
          'Deceptive double extension: "Dispute_Resolution_Form.pdf.exe" hides executable payload ".exe" behind ".pdf"',
          'Windows PE executable binary disguised as PDF document'
        ]
      }
    ]
  },
  {
    id: 'msg-102',
    from: 'executive-office@wire-transfer-ceo.link',
    senderName: 'Chief Executive Officer',
    subject: 'CONFIDENTIAL: Urgent Wire Transfer Request for Vendor Acquisition',
    date: '09:15 AM',
    snippet: 'Are you at your desk right now? We need an immediate wire transfer of $48,500 processed for vendor escrow. Do not call my cell.',
    body: `From: "Chief Executive Officer" <executive-office@wire-transfer-ceo.link>\nReply-To: secret-offshore-escrow@yopmail.com\nSubject: CONFIDENTIAL: Urgent Wire Transfer Request for Vendor Acquisition\n\nAre you at your desk right now?\n\nI am currently in an urgent confidential meeting with acquisition attorneys. We need an immediate wire transfer of $48,500 processed for vendor escrow.\n\nDo not call my cell phone as I cannot talk. Open the attached authorization macro document and fill in escrow details right away.\n\nRegards,\nChief Executive Officer`,
    isStarred: false,
    isUnread: true,
    attachments: [
      {
        filename: 'Escrow_Transfer_Mandate.docm',
        file_size: 92400,
        formatted_size: '90.2 KB',
        classification: 'Malicious',
        risk_score: 94,
        detected_signals: [
          'Weaponized Office document: VBA macro with Auto-Execution hook (Document_Open)',
          'Suspicious VBA execution APIs detected (Shell, PowerShell, CreateObject)'
        ]
      }
    ]
  },
  {
    id: 'msg-103',
    from: 'sarah.miller@acme-corp.com',
    senderName: 'Sarah Miller',
    subject: 'Project Kickoff Q3: Slides & Agenda for Monday 10:00 AM',
    date: 'Yesterday',
    snippet: 'Hi everyone, I have finalized the agenda and quarterly targets for our Q3 strategy rollout. Please review the shared Google Doc.',
    body: `From: "Sarah Miller" <sarah.miller@acme-corp.com>\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: Project Kickoff Q3: Slides & Agenda for Monday 10:00 AM\n\nHi everyone,\n\nI have finalized the agenda and quarterly targets for our Q3 strategy rollout. Please review the attached presentation slides before our kickoff meeting on Monday at 10:00 AM PST.\n\nMeeting link: https://meet.google.com/abc-defg-hij\n\nBest regards,\nSarah Miller\nLead Product Architect`,
    isStarred: false,
    isUnread: false,
    attachments: [
      {
        filename: 'Project_Kickoff_Q3_Strategy.pdf',
        file_size: 1540000,
        formatted_size: '1.5 MB',
        classification: 'Safe',
        risk_score: 2,
        detected_signals: [
          'Verified Adobe PDF document structure with zero active scripts or launch directives'
        ]
      }
    ]
  },
  {
    id: 'msg-104',
    from: 'cloud-noreply@google.com',
    senderName: 'Google Cloud Platform',
    subject: 'Monthly Cloud Billing Statement - Project ID: app-prod-412',
    date: 'Aug 28',
    snippet: 'Your monthly Google Cloud billing statement is now available in the Cloud Console.',
    body: `From: "Google Cloud Platform" <cloud-noreply@google.com>\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: Monthly Cloud Billing Statement - Project ID: app-prod-412\n\nHello Google Cloud Developer,\n\nYour billing statement for the previous billing period is now available. Your total usage charges were $14.20.\n\nYou can review your invoice and breakdowns directly in the Google Cloud Console: https://console.cloud.google.com/billing\n\nAttached is your monthly PDF tax receipt.\n\nThank you for choosing Google Cloud.`,
    isStarred: true,
    isUnread: false,
    attachments: [
      {
        filename: 'GCP_Tax_Invoice_AUG2026.pdf',
        file_size: 384000,
        formatted_size: '375.0 KB',
        classification: 'Safe',
        risk_score: 1,
        detected_signals: [
          'Standard clean PDF financial invoice layout from verified enterprise infrastructure'
        ]
      }
    ]
  }
];

let dynamicInbox = [...DEFAULT_INBOX_EMAILS];

function decodeGmailData(data) {
  return Buffer.from(String(data || '').replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function normalizeBase64Content(value) {
  const dataUrlMarker = value.lastIndexOf(';base64,');
  const content = dataUrlMarker === -1 ? value : value.slice(dataUrlMarker + 8);
  let padding = 0;
  let paddingStarted = false;

  for (let i = 0; i < content.length; i += 1) {
    const code = content.charCodeAt(i);
    if (code === 61) {
      paddingStarted = true;
      padding += 1;
      if (padding > 2) return null;
      continue;
    }
    if (paddingStarted) return null;
    const isBase64Character =
      (code >= 65 && code <= 90)
      || (code >= 97 && code <= 122)
      || (code >= 48 && code <= 57)
      || code === 43
      || code === 47
      || code === 45
      || code === 95;
    if (!isBase64Character) return null;
  }

  const remainder = (content.length - padding) % 4;
  if (remainder === 1) return null;
  if (padding > 0 && (content.length % 4 !== 0 || padding !== (4 - remainder) % 4)) {
    return null;
  }

  const normalized = content.replace(/-/g, '+').replace(/_/g, '/');
  return normalized + (padding === 0 ? '='.repeat((4 - remainder) % 4) : '');
}

function collectGmailAttachments(payload, found = []) {
  if (!payload) return found;
  if (payload.filename && (payload.body?.attachmentId || payload.body?.data)) {
    found.push({
      filename: payload.filename,
      mime_type: payload.mimeType || '',
      attachment_id: payload.body.attachmentId,
      inline_data: payload.body.data,
      size: Number(payload.body.size) || 0
    });
  }
  for (const part of payload.parts || []) collectGmailAttachments(part, found);
  return found;
}

function unscannableAttachment(filename, reason, size = 0) {
  const details = {
    filename,
    classification: 'Suspicious',
    risk_score: 50,
    threat_probability: 0.5,
    detected_signals: [reason],
    diagnostics: true,
    formatted_size: size ? `${(size / 1024).toFixed(1)} KB` : 'Size unavailable'
  };
  return details;
}

async function scanGmailAttachments(gmail, messageId, payload) {
  const parts = collectGmailAttachments(payload);
  const emailAttachments = [];
  const modelInputs = [];
  const displayedResults = [];
  let scannedBytes = 0;

  for (const part of parts) {
    if (part.size > MAX_GMAIL_ATTACHMENT_BYTES || scannedBytes + part.size > MAX_GMAIL_ATTACHMENT_BYTES) {
      const result = unscannableAttachment(
        part.filename,
        'Attachment exceeds the 35 MB per-email scanning limit and was not downloaded.',
        part.size
      );
      emailAttachments.push(result);
      displayedResults.push(result);
      continue;
    }

    try {
      let encodedData = part.inline_data;
      if (!encodedData) {
        const response = await gmail.users.messages.attachments.get({
          userId: 'me',
          messageId,
          id: part.attachment_id
        });
        encodedData = response.data.data;
      }
      const bytes = decodeGmailData(encodedData);
      if (bytes.length > MAX_GMAIL_ATTACHMENT_BYTES || scannedBytes + bytes.length > MAX_GMAIL_ATTACHMENT_BYTES) {
        const result = unscannableAttachment(
          part.filename,
          'Attachment exceeds the 35 MB per-email scanning limit and was not scanned.',
          bytes.length
        );
        emailAttachments.push(result);
        displayedResults.push(result);
        continue;
      }
      scannedBytes += bytes.length;

      const input = {
        filename: part.filename,
        mime_type: part.mime_type,
        content_base64: bytes.toString('base64')
      };
      const result = analyzeAttachment(bytes, part.filename, part.mime_type);
      emailAttachments.push({ ...result, diagnostics: true });
      displayedResults.push(result);
      modelInputs.push(input);
    } catch (err) {
      const result = unscannableAttachment(
        part.filename,
        `Attachment could not be retrieved or scanned: ${err.message}`,
        part.size
      );
      emailAttachments.push(result);
      displayedResults.push(result);
    }
  }

  return { emailAttachments, modelInputs, displayedResults };
}

function attachMlToHeuristic(result, ml) {
  const mlProb = typeof ml?.probability === 'number' ? ml.probability : null;
  const finalScore = blendScores(result.finalScore, mlProb);
  const classification = classifyFromScore(finalScore);
  const detectedSignals = [...result.detectedSignals];

  if (mlProb != null) {
    detectedSignals.unshift(
      `ML model score ${Math.round(mlProb * 100)}% (XGBoost trained on CEAS + URL/PhishTank features)`
    );
  } else {
    detectedSignals.unshift('Machine-learning inference unavailable; this verdict uses static heuristics only.');
  }

  const shapFeatures = mergeShap(
    result.shapFeatures,
    ml?.top_email_text_features || null
  );

  return {
    ...result,
    heuristicScore: result.finalScore,
    finalScore,
    classification,
    risk_score: Math.round(finalScore * 100),
    detectedSignals,
    shapFeatures,
    ml
  };
}

function buildEmailResponse(result, senderEmail) {
  let confidenceVal = 0.95;
  if (result.classification === 'Phishing') {
    confidenceVal = result.finalScore;
  } else if (result.classification === 'Legitimate') {
    confidenceVal = 1 - result.finalScore;
  } else {
    confidenceVal = 0.55 + Math.abs(result.finalScore - 0.45);
  }
  const confidenceScore = Math.max(50, Math.min(99, Math.round(confidenceVal * 100)));
  const attachmentAnalysis = result.ml?.attachments?.length
    ? result.ml.attachments
    : result.attachmentAnalysisList || [];

  return {
    threat_probability: result.finalScore,
    probability: result.finalScore,
    risk_score: result.risk_score,
    risk_level: riskLevelFromScore(result.finalScore),
    classification: result.classification,
    confidence_score: confidenceScore,
    confidence_label: `${confidenceScore}%`,
    detected_signals: result.detectedSignals,
    reasoning: generateReasoningSummary(result),
    top_email_text_features: result.shapFeatures,
    top_url_features: result.ml?.top_url_features || {},
    sender_analysis: {
      sender_email: result.senderFeats.parsed.raw || senderEmail,
      domain: result.senderFeats.domain,
      classification: result.senderFeats.brandImpersonationFound || result.senderFeats.hasLookalike ? 'Phishing' : result.senderFeats.isTrusted ? 'Safe' : 'Suspicious',
      risk_score: result.senderFeats.brandImpersonationFound || result.senderFeats.hasLookalike ? 95 : result.senderFeats.isTrusted ? 5 : 45,
      features: result.senderFeats
    },
    header_analysis: result.headerFeats,
    url_analysis: result.urlAnalysisList,
    attachment_analysis: attachmentAnalysis,
    has_attachments: attachmentAnalysis.length > 0,
    ml_features: {
      text_length: result.textFeats.num_chars,
      word_count: result.textFeats.num_words,
      entropy: result.textFeats.entropy,
      uppercase_ratio: result.textFeats.uppercase_ratio,
      psychological_pressure: result.textFeats.linguistic?.overallPsychologicalPressure || 0,
      ml_probability: result.ml?.probability ?? null,
      model_version: result.ml?.model_version || 'heuristic-only'
    },
    ensemble_breakdown: {
      Heuristics: Math.round((result.heuristicScore ?? result.finalScore) * 1000) / 1000,
      XGBoost: result.ml?.probability != null ? Math.round(result.ml.probability * 1000) / 1000 : null,
      Blended: Math.round(result.finalScore * 1000) / 1000
    }
  };
}

// 1. Analyze email text, sender, headers, URLs, & attachments
router.post(['/predict', '/api/predict'], async (req, res) => {
  const { email_text, sender_email, urls, attachments } = req.body || {};
  if (email_text != null && typeof email_text !== 'string') {
    return res.status(400).json({ error: 'email_text must be a string' });
  }
  if (sender_email != null && typeof sender_email !== 'string') {
    return res.status(400).json({ error: 'sender_email must be a string' });
  }
  if (urls != null && (!Array.isArray(urls) || !urls.every(url => typeof url === 'string'))) {
    return res.status(400).json({ error: 'urls must be a list of strings' });
  }
  if (attachments != null && (
    !Array.isArray(attachments)
    || attachments.length > 20
    || !attachments.every(item => item && typeof item === 'object' && !Array.isArray(item))
  )) {
    return res.status(400).json({ error: 'attachments must be a list of at most 20 objects' });
  }
  if (!email_text && !sender_email && (!attachments || attachments.length === 0)) {
    return res.status(400).json({ error: 'Please provide email_text, sender_email, or attachments.' });
  }

  const text = email_text || '';
  let normalizedAttachments = attachments || [];
  let totalAttachmentBytes = 0;
  normalizedAttachments = normalizedAttachments.map(attachment => {
    for (const key of ['filename', 'mime_type', 'mime', 'content_base64', 'data', 'content']) {
      if (attachment[key] != null && typeof attachment[key] !== 'string') {
        return null;
      }
    }
    const encodedContent = attachment.content_base64 || attachment.data || attachment.content;
    if (encodedContent == null) return attachment;
    const canonicalBase64 = normalizeBase64Content(encodedContent);
    if (canonicalBase64 == null) return null;
    totalAttachmentBytes += Math.floor(canonicalBase64.length * 3 / 4);
    return { ...attachment, content_base64: canonicalBase64 };
  });
  if (normalizedAttachments.some(attachment => attachment == null)) {
    return res.status(400).json({ error: 'Attachment fields must be strings and content must be valid base64.' });
  }
  if (totalAttachmentBytes > MAX_GMAIL_ATTACHMENT_BYTES) {
    return res.status(413).json({ error: 'Attachments exceed the 35 MB total scan limit.' });
  }

  const heuristic = computeUnifiedThreatScore(text, sender_email, urls || [], normalizedAttachments);
  const ml = await predictEmail(text, sender_email, urls, normalizedAttachments);
  const result = attachMlToHeuristic(heuristic, ml);
  return res.json(buildEmailResponse(result, sender_email));
});

// 1b. Dedicated Attachment Threat Scanner endpoint
router.post(['/predict_attachment', '/api/predict_attachment'], parseAttachmentUpload, async (req, res) => {
  try {
    let filename = '';
    let mimeType = '';
    let buffer = null;

    if (req.file) {
      filename = req.file.originalname || 'attachment';
      mimeType = req.file.mimetype || '';
      buffer = req.file.buffer;
    } else {
      filename = String(req.body.filename || req.body.name || 'uploaded_attachment').trim();
      mimeType = String(req.body.mime_type || req.body.mime || '').trim();
      const contentB64 = req.body.content_base64 || req.body.data || req.body.content || '';
      if (contentB64) {
        if (typeof contentB64 !== 'string') {
          return res.status(400).json({ error: 'Invalid base64 attachment content' });
        }
        const normalizedBase64 = normalizeBase64Content(contentB64);
        if (normalizedBase64 == null) return res.status(400).json({ error: 'Invalid base64 attachment content' });
        buffer = Buffer.from(normalizedBase64, 'base64');
      } else {
        buffer = Buffer.from('');
      }
    }

    const base64Payload = buffer.toString('base64');

    // 1. Query Python XGBoost service
    let mlResult = await predictAttachment({
      filename,
      content_base64: base64Payload,
      mime_type: mimeType
    });

    // 2. Fallback to Node.js static heuristics if ML microservice is starting or unavailable
    if (!mlResult || !mlResult.classification) {
      mlResult = analyzeAttachment(buffer, filename, mimeType);
    }

    return res.json(mlResult);
  } catch (err) {
    console.error('[Attachment Scan Error]', err);
    return res.status(500).json({ error: 'Attachment analysis failed: ' + err.message });
  }
});

// 1c. Attachment Model Performance Metrics
router.get(['/attachment_metrics', '/api/attachment_metrics'], async (_req, res) => {
  const metrics = await getAttachmentMetrics();
  if (metrics) return res.json(metrics);
  return res.status(503).json({
    error: 'Attachment model metrics are unavailable because the ML service is offline.'
  });
});

// 2. Sender threat verification
router.post(['/predict_sender', '/api/predict_sender'], (req, res) => {
  const sender_email = req.body?.sender_email;
  if (typeof sender_email !== 'string' || !sender_email.trim()) {
    return res.status(400).json({ error: 'sender_email is required as a string' });
  }

  const senderFeats = extractSenderFeatures(sender_email);
  if (!/^[^\s@<>]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(senderFeats.parsed.email)) {
    return res.status(400).json({ error: 'sender_email must contain a valid email address' });
  }
  const isPhish = senderFeats.brandImpersonationFound || senderFeats.hasLookalike || senderFeats.isDisposable;
  const isSuspicious = senderFeats.isSuspiciousTld || senderFeats.displayNameMismatch || (!senderFeats.isTrusted && senderFeats.domainEntropy > 3.8);

  let classification = 'Suspicious';
  let riskScore = 35;

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
        : senderFeats.isTrusted
          ? `Sender domain belongs to the local trusted-domain list. This is not a guarantee that the message is safe.`
          : `No known impersonation markers were detected, but this sender domain is not in the local trusted-domain list. Verify it independently.`
  });
});

// 3. Scan URL route
router.post(['/predict_url', '/api/predict_url'], async (req, res) => {
  const url = req.body?.url;
  if (typeof url !== 'string' || !url.trim()) return res.status(400).json({ error: 'url parameter required as a string' });
  if (url.length > 8192) return res.status(400).json({ error: 'url must be no longer than 8192 characters' });
  const analysis = analyzeUrlThreat(url);
  const ml = await predictUrl(url);

  let score = analysis.threat_probability;
  if (analysis.features?.is_trusted) {
    score = Math.min(score, 0.05);
  } else {
    score = blendScores(score, ml?.probability);
  }
  const classification = classifyFromScore(score);

  return res.json({
    url,
    threat_probability: score,
    probability: score,
    risk_score: Math.round(score * 100),
    classification,
    flags: analysis.flags,
    features: analysis.features,
    reasoning: analysis.reasoning,
    top_url_features: ml?.top_url_features || {},
    ml_probability: ml?.probability ?? null,
    model_version: ml?.model_version || 'heuristic-only'
  });
});

router.get(['/ml/health', '/api/ml/health'], async (_req, res) => {
  const health = await mlHealth();
  return res.json(health);
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

              function findBodyPart(part, mimeType) {
                if (!part) return '';
                if (part.mimeType === mimeType && part.body?.data) {
                  return decodeGmailData(part.body.data).toString('utf-8');
                }
                for (const sub of part.parts || []) {
                  const found = findBodyPart(sub, mimeType);
                  if (found) return found;
                }
                return '';
              }

              const messagePayload = msg.data.payload;
              const messageBody = findBodyPart(messagePayload, 'text/plain')
                || findBodyPart(messagePayload, 'text/html')
                || msg.data.snippet
                || '';
              const headerLines = [`From: ${from}`, `Subject: ${subject}`];
              if (authResults) headerLines.push(`Authentication-Results: ${authResults}`);
              if (spfHeader) headerLines.push(`Received-SPF: ${spfHeader}`);
              const body = `${headerLines.join('\n')}\n\n${messageBody}`;
              const scannedAttachments = await scanGmailAttachments(gmail, msg.data.id, messagePayload);

              // Threat evaluation (heuristics + trained XGBoost)
              const heuristic = computeUnifiedThreatScore(body, from, [], scannedAttachments.emailAttachments);
              const ml = await predictEmail(body, from, [], scannedAttachments.modelInputs);
              const analysis = attachMlToHeuristic(heuristic, ml);

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
                attachments: scannedAttachments.displayedResults,
                attachment_analysis: ml?.attachments || heuristic.attachmentAnalysisList,
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
  const mlBatch = await predictEmailBatch(
    dynamicInbox.map(email => ({
      id: email.id,
      email_text: email.body,
      sender_email: email.from
    }))
  );
  const mlById = new Map((mlBatch?.results || []).map(item => [item.id, item]));

  const analyzedInbox = dynamicInbox.map(email => {
    const heuristic = computeUnifiedThreatScore(email.body, email.from, [], email.attachments || []);
    const analysis = attachMlToHeuristic(heuristic, mlById.get(email.id) || null);
    return {
      ...email,
      threat_probability: analysis.finalScore,
      classification: analysis.classification,
      detected_signals: analysis.detectedSignals,
      detected_features: analysis.detectedSignals,
      risk_score: analysis.risk_score,
      attachments: email.attachments || [],
      attachment_analysis: heuristic.attachmentAnalysisList || []
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

router.post(['/inbox/add', '/api/inbox/add'], async (req, res) => {
  const { from, subject, body, attachments } = req.body || {};
  if (typeof body !== 'string' || !body.trim() || typeof from !== 'string' || !from.trim()) {
    return res.status(400).json({ error: 'from and body are required as non-empty strings' });
  }
  if (subject != null && typeof subject !== 'string') {
    return res.status(400).json({ error: 'subject must be a string' });
  }
  if (attachments != null && (
    !Array.isArray(attachments)
    || attachments.length > 20
    || !attachments.every(item => item && typeof item === 'object' && !Array.isArray(item))
  )) {
    return res.status(400).json({ error: 'attachments must be a list of at most 20 objects' });
  }
  
  let totalAttachmentBytes = 0;
  const emailAttachments = (attachments || []).map(attachment => {
    for (const key of ['filename', 'mime_type', 'mime', 'content_base64', 'data', 'content']) {
      if (attachment[key] != null && typeof attachment[key] !== 'string') return null;
    }
    const encodedContent = attachment.content_base64 || attachment.data || attachment.content;
    if (encodedContent == null) return attachment;
    const canonicalBase64 = normalizeBase64Content(encodedContent);
    if (canonicalBase64 == null) return null;
    totalAttachmentBytes += Math.floor(canonicalBase64.length * 3 / 4);
    return { ...attachment, content_base64: canonicalBase64 };
  });
  if (emailAttachments.some(attachment => attachment == null)) {
    return res.status(400).json({ error: 'Attachment fields must be strings and content must be valid base64.' });
  }
  if (totalAttachmentBytes > MAX_GMAIL_ATTACHMENT_BYTES) {
    return res.status(413).json({ error: 'Attachments exceed the 35 MB total scan limit.' });
  }

  const heuristic = computeUnifiedThreatScore(body, from, [], emailAttachments);
  const ml = await predictEmail(body, from, [], emailAttachments);
  const analysis = attachMlToHeuristic(heuristic, ml);
  const displayAttachments = emailAttachments.map(({ content_base64, data, content, ...metadata }) => metadata);
  
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
    attachments: displayAttachments,
    attachment_analysis: heuristic.attachmentAnalysisList || [],
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
    return `No high-risk indicators were identified in the supplied content (${result.risk_score}% risk). This does not verify the sender or guarantee that links and attachments are safe.`;
  }
}

module.exports = router;
