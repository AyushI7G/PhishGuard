// backend/engine/classifier.js
// Robust Multi-Signal Phishing Engine: Sender, URLs, Cryptographic Headers, and ML Signals

const {
  extractEmailTextFeatures,
  extractSenderFeatures,
  extractUrlFeatures,
  extractUrls,
  parseEmailHeaders,
  HIGH_PROFILE_BRANDS,
  levenshteinDistance
} = require('../features/extractors');

// Deep URL threat analyzer
function analyzeUrlThreat(urlStr, senderDomain = '') {
  const feats = extractUrlFeatures(urlStr);
  let risk = 0.05;
  const flags = [];

  // Safe domain bypass
  if (feats.is_trusted) {
    return {
      threat_probability: 0.02,
      classification: 'Legitimate',
      flags: ['Verified enterprise domain reputation.'],
      features: feats,
      reasoning: `Domain (${feats.domain}) is an established, trusted enterprise infrastructure.`
    };
  }

  // 1. Direct IP Address in URL
  if (feats.has_ip) {
    risk += 0.50;
    flags.push('Direct IP Address Host (Evades domain reputation filters)');
  }

  // 2. Transport Protocol
  if (!feats.is_https) {
    risk += 0.15;
    flags.push('Insecure HTTP Connection (Unencrypted plaintext transmission)');
  }

  // 3. Subdomain Nesting
  if (feats.num_subdomains >= 3) {
    risk += 0.25;
    flags.push(`Excessive Subdomain Nesting (${feats.num_subdomains} levels detected)`);
  }

  // 4. Entropy Obfuscation
  if (feats.entropy > 4.2) {
    risk += 0.20;
    flags.push(`High String Entropy (${feats.entropy}) indicating randomized or obfuscated URL`);
  }

  // 5. Embedded @ Symbol (RFC delimiter manipulation)
  if (feats.has_at) {
    risk += 0.45;
    flags.push('Embedded "@" character in URL (Common browser credential/destination obfuscation trick)');
  }

  // 6. Credential Harvesting Paths
  if (feats.has_login || feats.has_update) {
    risk += 0.25;
    flags.push('Sensitive authentication or account verification path pattern');
  }

  // 7. Suspicious Top-Level Domain
  if (feats.is_suspicious_tld) {
    risk += 0.30;
    flags.push(`High-Risk TLD (.${feats.tld}) frequently leveraged in malicious campaigns`);
  }

  // 8. Lookalike Brand Check in URL Domain
  const domainWithoutTld = (feats.domain || '').split('.')[0];
  for (const brandObj of HIGH_PROFILE_BRANDS) {
    const dist = levenshteinDistance(domainWithoutTld, brandObj.name);
    if (dist > 0 && dist <= 2 && domainWithoutTld.length >= 4) {
      risk += 0.45;
      flags.push(`Typosquatting in destination URL: "${feats.domain}" mimics "${brandObj.name}"`);
      break;
    }
  }

  // 9. URL Domain vs Sender Domain Discrepancy (if sender claims a corporate identity)
  if (senderDomain && feats.domain) {
    const cleanSender = senderDomain.toLowerCase();
    const cleanUrl = feats.domain.toLowerCase();
    const isBrandSender = HIGH_PROFILE_BRANDS.some(b => cleanSender.includes(b.name));
    if (isBrandSender && !cleanUrl.includes(cleanSender) && !cleanSender.includes(cleanUrl)) {
      risk += 0.35;
      flags.push(`Domain Disconnect: Email claims "${senderDomain}" but destination link points to "${feats.domain}"`);
    }
  }

  const score = Math.max(0.01, Math.min(0.99, risk));
  let classification = 'Legitimate';
  if (score >= 0.60) classification = 'Phishing';
  else if (score >= 0.30) classification = 'Suspicious';

  return {
    threat_probability: score,
    classification,
    flags: flags.length ? flags : ['Standard URL parameters and domain reputation.'],
    features: feats,
    reasoning: classification === 'Phishing'
      ? `High-risk indicators identified in URL structure and destination endpoint (${feats.domain}).`
      : classification === 'Suspicious'
        ? `Elevated anomaly markers detected in URL composition. Verify destination before entering credentials.`
        : `URL exhibits standard structure with no high-risk markers.`
  };
}

// Unified Multi-Modal Threat Scoring Engine
function computeUnifiedThreatScore(emailText, senderInput = '', extractedUrls = []) {
  const textFeats = extractEmailTextFeatures(emailText);
  const senderFeats = extractSenderFeatures(senderInput, emailText);
  const headerFeats = parseEmailHeaders(emailText);

  // Extract URLs
  const urls = extractedUrls.length ? extractedUrls : extractUrls(emailText);
  const urlAnalysisList = urls.map(u => ({
    url: u,
    feats: extractUrlFeatures(u),
    diagnostics: analyzeUrlThreat(u, senderFeats.domain)
  }));

  const detectedSignals = [];
  const shapFeatures = {};
  
  // Base prior
  let threatScore = 0.05;

  // ============================================================
  // SIGNAL 1: CRYPTOGRAPHIC EMAIL HEADERS & AUTHENTICATION
  // ============================================================
  if (headerFeats.hasAuthenticationResults) {
    // SPF
    if (headerFeats.spf === 'fail' || headerFeats.spf === 'softfail') {
      const weight = headerFeats.spf === 'fail' ? 0.35 : 0.20;
      threatScore += weight;
      detectedSignals.push(`SPF Authentication Failed (${headerFeats.spf.toUpperCase()}): Originating IP address is not authorized for domain "${senderFeats.domain || 'sender'}"`);
      shapFeatures['SPF Policy Failure'] = 2.40;
    } else if (headerFeats.spf === 'pass') {
      threatScore -= 0.15;
      detectedSignals.push(`SPF Authentication Verified: Sender IP is authorized by domain SPF records`);
      shapFeatures['SPF Signature Verified'] = -1.50;
    }

    // DKIM
    if (headerFeats.dkim === 'fail') {
      threatScore += 0.35;
      detectedSignals.push('DKIM Cryptographic Signature Invalid: Message headers or body failed integrity checks');
      shapFeatures['DKIM Signature Broken'] = 2.20;
    } else if (headerFeats.dkim === 'pass') {
      threatScore -= 0.15;
      detectedSignals.push('DKIM Cryptographic Signature Valid: Message content verified untampered');
      shapFeatures['DKIM Signature Verified'] = -1.60;
    }

    // DMARC
    if (headerFeats.dmarc === 'fail') {
      threatScore += 0.40;
      detectedSignals.push('DMARC Alignment Policy Failed: Sender domain alignment rejected by policy');
      shapFeatures['DMARC Alignment Failure'] = 2.80;
    } else if (headerFeats.dmarc === 'pass') {
      threatScore -= 0.20;
      detectedSignals.push('DMARC Alignment Passed: SPF and DKIM identity alignment confirmed');
      shapFeatures['DMARC Alignment Passed'] = -1.90;
    }
  }

  // Header Anomalies: Reply-To Redirection
  if (headerFeats.headerAnomalies && headerFeats.headerAnomalies.length > 0) {
    headerFeats.headerAnomalies.forEach(anomaly => {
      threatScore += 0.30;
      detectedSignals.push(`Header Inconsistency: ${anomaly}`);
      shapFeatures['Reply-To Redirection Mismatch'] = 1.95;
    });
  }

  // ============================================================
  // SIGNAL 2: SENDER DOMAIN IDENTITY & SPOOFING ANALYSIS
  // ============================================================
  if (senderFeats.brandImpersonationFound) {
    threatScore += 0.50;
    detectedSignals.push(`Brand Impersonation Detected: Unauthorized domain "${senderFeats.domain}" claims identity of "${senderFeats.brandImpersonationFound}"`);
    shapFeatures[`Brand Spoofing (${senderFeats.brandImpersonationFound})`] = 3.20;
  }

  if (senderFeats.hasLookalike) {
    threatScore += 0.45;
    const target = senderFeats.lookalikeDetails?.targetBrand || 'legitimate service';
    detectedSignals.push(`Typosquatting/Homoglyph Domain: "${senderFeats.domain}" is a deceptive lookalike of "${target}"`);
    shapFeatures['Lookalike Domain Typosquatting'] = 2.75;
  }

  if (senderFeats.displayNameMismatch) {
    threatScore += 0.30;
    detectedSignals.push(senderFeats.displayNameSpoofingDetails || 'Display Name Spoofing: Corporate display name mismatch with mailbox domain');
    shapFeatures['Display Name Role Spoofing'] = 1.85;
  }

  if (senderFeats.isDisposable) {
    threatScore += 0.40;
    detectedSignals.push(`Burner / Disposable Inbox Domain (${senderFeats.domain})`);
    shapFeatures['Disposable Inbox Provider'] = 2.10;
  }

  if (senderFeats.isSuspiciousTld) {
    threatScore += 0.25;
    detectedSignals.push(`High-Risk Top-Level Domain (.${senderFeats.parsed.tld})`);
    shapFeatures['High-Risk TLD'] = 1.40;
  }

  if (senderFeats.isTrusted && !senderFeats.brandImpersonationFound) {
    threatScore -= 0.35;
    detectedSignals.push(`Reputable Enterprise Sender Domain (${senderFeats.domain})`);
    shapFeatures['Trusted Domain Reputation'] = -2.50;
  }

  // ============================================================
  // SIGNAL 3: EMBEDDED URL & DESTINATION THREAT ANALYSIS
  // ============================================================
  let maxUrlThreat = 0;
  let phishUrls = [];
  let suspUrls = [];

  urlAnalysisList.forEach(item => {
    const uRisk = item.diagnostics.threat_probability;
    if (uRisk > maxUrlThreat) maxUrlThreat = uRisk;

    if (item.diagnostics.classification === 'Phishing') {
      phishUrls.push(item.url);
      item.diagnostics.flags.forEach(f => {
        if (!detectedSignals.includes(f)) detectedSignals.push(`URL Risk: ${f} [${item.url}]`);
      });
    } else if (item.diagnostics.classification === 'Suspicious') {
      suspUrls.push(item.url);
      item.diagnostics.flags.forEach(f => {
        if (!detectedSignals.includes(f)) detectedSignals.push(`URL Caution: ${f} [${item.url}]`);
      });
    }
  });

  if (phishUrls.length > 0) {
    threatScore = Math.max(threatScore + 0.35, maxUrlThreat * 0.95);
    shapFeatures['Malicious Embedded URL'] = 2.90;
  } else if (suspUrls.length > 0) {
    threatScore += 0.20;
    shapFeatures['Suspicious Link Properties'] = 1.30;
  } else if (urlAnalysisList.length > 0 && maxUrlThreat < 0.10) {
    threatScore -= 0.10;
    shapFeatures['Safe Hyperlinks Verified'] = -1.10;
  }

  // ============================================================
  // SIGNAL 4: ML LINGUISTIC & STRUCTURAL SIGNALS
  // ============================================================
  const ling = textFeats.linguistic || {};

  // Psychological coercion signals
  if (ling.urgencyScore > 0.4 && !senderFeats.isTrusted) {
    threatScore += 0.15;
    detectedSignals.push('Coercive Psychological Urgency (Imminent account suspension / tight deadline pressure)');
    shapFeatures['Psychological Urgency Trigger'] = 1.20;
  }

  if (ling.financialPressureScore > 0.4 && (!senderFeats.isTrusted || senderFeats.displayNameMismatch)) {
    threatScore += 0.20;
    detectedSignals.push('High-Risk Financial / Transactional Transfer Lure');
    shapFeatures['Financial Transfer Lure'] = 1.45;
  }

  if (ling.credentialLureScore > 0.4 && (phishUrls.length > 0 || !senderFeats.isTrusted)) {
    threatScore += 0.20;
    detectedSignals.push('Credential Harvesting Directives (Requests password or identity verification)');
    shapFeatures['Credential Harvesting Lure'] = 1.50;
  }

  if (ling.authorityPressureScore > 0.5) {
    threatScore += 0.20;
    detectedSignals.push('Business Email Compromise (BEC) Signature: Out-of-band communication suppression & urgency');
    shapFeatures['BEC Authority Pressure'] = 1.60;
  }

  // Structural casing & punctuation
  if (textFeats.uppercase_ratio > 0.35 && textFeats.num_words > 12) {
    threatScore += 0.08;
    detectedSignals.push('Aggressive Capitalization Ratio (Psychological urgency amplifier)');
    shapFeatures['Aggressive Uppercase Syntax'] = 0.60;
  }

  if (textFeats.num_exclamations >= 3 && !senderFeats.isTrusted) {
    threatScore += 0.06;
    shapFeatures['Excessive Exclamation Punctuation'] = 0.45;
  }

  // Contextual balancing: When an email is from a verified sender with valid headers,
  // ensure benign conversational words do not cause false alarms
  if (senderFeats.isTrusted && (headerFeats.spf === 'pass' || headerFeats.dmarc === 'pass') && phishUrls.length === 0) {
    threatScore = Math.min(threatScore, 0.12);
  }

  // ============================================================
  // FINAL CALIBRATION & EVIDENCE SYNTHESIS
  // ============================================================
  const finalScore = Math.max(0.01, Math.min(0.99, threatScore));
  
  let classification = 'Legitimate';
  if (finalScore >= 0.60) {
    classification = 'Phishing';
  } else if (finalScore >= 0.30) {
    classification = 'Suspicious';
  }

  // Ensure SHAP features strictly match the classification without contradictory signals
  if (classification === 'Legitimate') {
    // Filter out residual positive micro-features so explanation is logically sound
    Object.keys(shapFeatures).forEach(k => {
      if (shapFeatures[k] > 0 && !detectedSignals.some(s => s.includes(k))) {
        delete shapFeatures[k];
      }
    });
    if (!shapFeatures['Trusted Domain Reputation'] && senderFeats.isTrusted) {
      shapFeatures['Trusted Domain Reputation'] = -2.50;
    }
    if (Object.keys(shapFeatures).length === 0) {
      shapFeatures['Normal Message Syntax'] = -1.20;
      shapFeatures['Standard Domain Reputation'] = -0.80;
    }
  }

  if (detectedSignals.length === 0) {
    detectedSignals.push('Standard communication syntax with no high-risk spoofing or credential harvesting markers.');
  }

  return {
    finalScore,
    risk_score: Math.round(finalScore * 100),
    classification,
    detectedSignals,
    shapFeatures,
    textFeats,
    senderFeats,
    headerFeats,
    urlAnalysisList
  };
}

module.exports = {
  analyzeUrlThreat,
  computeUnifiedThreatScore
};
