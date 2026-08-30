// backend/features/extractors.js
// Advanced Multi-Signal Feature Extraction for Email Text, Senders, URLs, and Headers

const SUSPICIOUS_WORDS = [
  'urgent', 'immediate', 'immediately', 'action required', 'suspended', 'suspension',
  'verify', 'verification', 'unauthorized', 'security alert', 'compromised', 'password',
  'banking', 'wire transfer', 'invoice', 'payment', 'overdue', 'gift card', 'bitcoin',
  'crypto', 'wallet', 'payroll', 'direct deposit', 'irs', 'tax refund', 'lottery',
  'winner', 'click here', 'login', 'log in', 'update account', 're-activate', 'locked',
  'violation', 'terminated', 'deactivated', 'reset password', 'confidential', 'ssn',
  'social security', 'credit card', 'cvv', 'pin', 'routing number', 'bank account'
];

const SUSPICIOUS_TLDS = [
  'xyz', 'top', 'club', 'work', 'link', 'click', 'loan', 'gq', 'cf', 'tk', 'ml', 'ga',
  'surf', 'icu', 'fit', 'rest', 'buzz', 'live', 'cam', 'agency', 'support', 'help', 'center',
  'monster', 'quest', 'fun', 'win', 'bid', 'country', 'stream', 'download', 'racing', 'account'
];

const HIGH_PROFILE_BRANDS = [
  { name: 'paypal', domain: 'paypal.com', aliases: ['paypa1', 'pay-pal', 'paypal-security', 'paypal-service'] },
  { name: 'google', domain: 'google.com', aliases: ['goog1e', 'g00gle', 'google-security', 'google-verify'] },
  { name: 'microsoft', domain: 'microsoft.com', aliases: ['micros0ft', 'msft', 'office365', 'outlook', 'micro-soft'] },
  { name: 'apple', domain: 'apple.com', aliases: ['app1e', 'appleid', 'apple-support', 'icloud-security'] },
  { name: 'amazon', domain: 'amazon.com', aliases: ['amaz0n', 'amazon-order', 'amazon-pay'] },
  { name: 'netflix', domain: 'netflix.com', aliases: ['netf1ix', 'netflix-billing'] },
  { name: 'chase', domain: 'chase.com', aliases: ['chasebank', 'chase-online'] },
  { name: 'wellsfargo', domain: 'wellsfargo.com', aliases: ['wells-fargo', 'wellsfargo-bank'] },
  { name: 'bankofamerica', domain: 'bankofamerica.com', aliases: ['bofa', 'bank-of-america'] },
  { name: 'citibank', domain: 'citi.com', aliases: ['citi-bank', 'citigroup'] },
  { name: 'facebook', domain: 'facebook.com', aliases: ['meta', 'fb-security'] },
  { name: 'instagram', domain: 'instagram.com', aliases: ['insta-verify'] },
  { name: 'linkedin', domain: 'linkedin.com', aliases: ['linked-in'] },
  { name: 'dhl', domain: 'dhl.com', aliases: ['dhl-express', 'dhl-delivery'] },
  { name: 'fedex', domain: 'fedex.com', aliases: ['fed-ex', 'fedex-tracking'] },
  { name: 'ups', domain: 'ups.com', aliases: ['ups-delivery', 'ups-tracking'] },
  { name: 'usps', domain: 'usps.com', aliases: ['usps-track', 'post-office'] },
  { name: 'dropbox', domain: 'dropbox.com', aliases: ['drop-box'] },
  { name: 'docusign', domain: 'docusign.com', aliases: ['docu-sign'] },
  { name: 'adobe', domain: 'adobe.com', aliases: ['adobe-cloud'] },
  { name: 'coinbase', domain: 'coinbase.com', aliases: ['coin-base', 'coinbase-verify'] },
  { name: 'binance', domain: 'binance.com', aliases: ['binance-auth'] },
  { name: 'zoom', domain: 'zoom.us', aliases: ['zoom-meeting'] },
  { name: 'slack', domain: 'slack.com', aliases: ['slack-team'] }
];

const DISPOSABLE_EMAIL_DOMAINS = [
  'mailinator.com', 'tempmail.com', '10minutemail.com', 'guerrillamail.com',
  'sharklasers.com', 'getnada.com', 'throwawaymail.com', 'yopmail.com',
  'dispostable.com', 'fakemailgenerator.com', 'trashmail.com', 'temp-mail.org',
  'tempmail.net', 'mytemp.email', 'crazymailing.com', 'dropmail.me'
];

const FREE_WEBMAIL_PROVIDERS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com',
  'zoho.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com', 'yandex.com'
];

const TRUSTED_DOMAINS = [
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com',
  'paypal.com', 'linkedin.com', 'netflix.com', 'chase.com', 'bankofamerica.com',
  'acme-corp.com', 'youtube.com', 'meet.google.com', 'zoom.us', 'slack.com',
  'console.cloud.google.com', 'docs.google.com', 'drive.google.com'
];

// Shannon Entropy Calculation
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const frequencies = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    frequencies[ch] = (frequencies[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in frequencies) {
    const p = frequencies[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

// Levenshtein distance for typosquatting detection
function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// Check homoglyphs / lookalikes (e.g. paypa1 -> paypal, micros0ft -> microsoft)
function normalizeHomoglyphs(str) {
  if (!str) return '';
  return str
    .toLowerCase()
    .replace(/[0]/g, 'o')
    .replace(/[1l|!]/g, 'l')
    .replace(/[3]/g, 'e')
    .replace(/[4@]/g, 'a')
    .replace(/[5$]/g, 's')
    .replace(/[8]/g, 'b')
    .replace(/[vv]/g, 'w')
    .replace(/[-_.]/g, '');
}

// URL Extractor supporting Plain Text, HTML links, and Markdown
function extractUrls(text) {
  if (!text) return [];
  const urls = new Set();

  // 1. Standard http/https URLs
  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+)/gi;
  let match;
  while ((match = urlRegex.exec(text)) !== null) {
    // Clean trailing punctuation
    let clean = match[1].replace(/[.,;:)>\]]+$/, '');
    urls.add(clean);
  }

  // 2. Markdown links: [text](url)
  const mdRegex = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi;
  while ((match = mdRegex.exec(text)) !== null) {
    urls.add(match[2]);
  }

  // 3. HTML hrefs: <a href="...">
  const hrefRegex = /href=["'](https?:\/\/[^"']+)["']/gi;
  while ((match = hrefRegex.exec(text)) !== null) {
    urls.add(match[1]);
  }

  return Array.from(urls);
}

// Email Headers Parser
function parseEmailHeaders(emailText = '') {
  const headers = {
    spf: null, // 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror'
    dkim: null, // 'pass' | 'fail' | 'none'
    dmarc: null, // 'pass' | 'fail' | 'none'
    replyTo: null,
    returnPath: null,
    fromHeader: null,
    receivedCount: 0,
    hasAuthenticationResults: false,
    headerAnomalies: []
  };

  if (!emailText) return headers;

  const authMatch = emailText.match(/Authentication-Results:\s*([^\r\n]+(?:\r?\n\s+[^\r\n]+)*)/i);
  const spfMatch = emailText.match(/Received-SPF:\s*([a-zA-Z]+)/i);
  const dkimMatch = emailText.match(/dkim=([a-zA-Z]+)/i);
  const dmarcMatch = emailText.match(/dmarc=([a-zA-Z]+)/i);
  const fromMatch = emailText.match(/^From:\s*(.+)$/im);
  const replyToMatch = emailText.match(/^Reply-To:\s*(.+)$/im);
  const returnPathMatch = emailText.match(/^Return-Path:\s*(.+)$/im);
  const receivedMatches = emailText.match(/^Received:/gim);

  if (receivedMatches) {
    headers.receivedCount = receivedMatches.length;
  }

  if (fromMatch) headers.fromHeader = fromMatch[1].trim();

  // SPF resolution
  if (spfMatch) {
    headers.spf = spfMatch[1].toLowerCase();
    headers.hasAuthenticationResults = true;
  } else if (authMatch) {
    const authLine = authMatch[1].toLowerCase();
    headers.hasAuthenticationResults = true;
    if (authLine.includes('spf=pass')) headers.spf = 'pass';
    else if (authLine.includes('spf=fail')) headers.spf = 'fail';
    else if (authLine.includes('spf=softfail')) headers.spf = 'softfail';
    else if (authLine.includes('spf=neutral')) headers.spf = 'neutral';
    else if (authLine.includes('spf=none')) headers.spf = 'none';
  }

  // DKIM resolution
  if (dkimMatch) {
    headers.dkim = dkimMatch[1].toLowerCase();
    headers.hasAuthenticationResults = true;
  } else if (authMatch) {
    const authLine = authMatch[1].toLowerCase();
    if (authLine.includes('dkim=pass')) headers.dkim = 'pass';
    else if (authLine.includes('dkim=fail')) headers.dkim = 'fail';
    else if (authLine.includes('dkim=none')) headers.dkim = 'none';
  }

  // DMARC resolution
  if (dmarcMatch) {
    headers.dmarc = dmarcMatch[1].toLowerCase();
    headers.hasAuthenticationResults = true;
  } else if (authMatch) {
    const authLine = authMatch[1].toLowerCase();
    if (authLine.includes('dmarc=pass')) headers.dmarc = 'pass';
    else if (authLine.includes('dmarc=fail')) headers.dmarc = 'fail';
    else if (authLine.includes('dmarc=none')) headers.dmarc = 'none';
  }

  if (replyToMatch) headers.replyTo = replyToMatch[1].trim();
  if (returnPathMatch) headers.returnPath = returnPathMatch[1].trim();

  // Header anomaly: Reply-To domain vs From domain mismatch
  if (headers.replyTo && headers.fromHeader) {
    const parsedFrom = parseSender(headers.fromHeader);
    const parsedReply = parseSender(headers.replyTo);
    if (parsedFrom.domain && parsedReply.domain && parsedFrom.domain !== parsedReply.domain) {
      // Check if not standard mailing list or known relay
      headers.headerAnomalies.push(`Reply-To address (${parsedReply.email}) redirects replies away from sender domain (${parsedFrom.domain})`);
    }
  }

  return headers;
}

// Canonical Sender String Parser
function parseSender(senderStr, emailText = '') {
  let raw = (senderStr || '').trim();
  if (!raw && emailText) {
    const matchFrom = emailText.match(/^From:\s*(.+)$/im);
    if (matchFrom) raw = matchFrom[1].trim();
  }
  if (!raw) return { raw: '', displayName: '', email: '', localPart: '', domain: '', tld: '' };

  let displayName = '';
  let email = '';

  const emailMatch = raw.match(/<([^>]+)>/);
  if (emailMatch) {
    email = emailMatch[1].trim().toLowerCase();
    displayName = raw.replace(/<[^>]+>/, '').replace(/["']/g, '').trim();
  } else {
    const pureEmail = raw.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (pureEmail) {
      email = pureEmail[1].toLowerCase();
      displayName = raw.replace(pureEmail[1], '').replace(/["']/g, '').trim();
    } else {
      email = raw.toLowerCase();
    }
  }

  let localPart = '';
  let domain = '';
  let tld = '';
  if (email.includes('@')) {
    const parts = email.split('@');
    localPart = parts[0];
    domain = parts[1] || '';
    const dParts = domain.split('.');
    if (dParts.length > 1) {
      tld = dParts[dParts.length - 1];
    }
  }

  return { raw, displayName, email, localPart, domain, tld };
}

// Comprehensive Sender Intelligence & Spoofing Extractor
function extractSenderFeatures(senderInput, emailText = '') {
  const parsed = parseSender(senderInput, emailText);
  const domain = parsed.domain.toLowerCase();
  const displayName = parsed.displayName.toLowerCase();
  const localPart = parsed.localPart.toLowerCase();
  const domainEntropy = calculateEntropy(domain);

  let brandImpersonationFound = null;
  let brandOfficialDomain = null;
  let hasLookalike = false;
  let lookalikeDetails = null;

  const normalizedDomain = normalizeHomoglyphs(domain);
  const normalizedDisplayName = normalizeHomoglyphs(displayName);
  const normalizedLocal = normalizeHomoglyphs(localPart);

  for (const brandObj of HIGH_PROFILE_BRANDS) {
    const brand = brandObj.name;
    const isOfficial = domain === brandObj.domain || domain.endsWith(`.${brandObj.domain}`);

    // Check if brand is targeted
    const brandInDisplay = displayName.includes(brand) || normalizedDisplayName.includes(brand);
    const brandInLocal = localPart.includes(brand) || normalizedLocal.includes(brand);
    const brandInDomain = domain.includes(brand) || normalizedDomain.includes(brand);
    const aliasInDomain = brandObj.aliases.some(alias => domain.includes(alias) || normalizedDomain.includes(alias));

    if ((brandInDisplay || brandInLocal || brandInDomain || aliasInDomain) && !isOfficial) {
      brandImpersonationFound = brand;
      brandOfficialDomain = brandObj.domain;
      break;
    }
  }

  // Lookalike distance check against top domains
  if (!brandImpersonationFound) {
    const domainWithoutTld = domain.split('.')[0] || '';
    for (const brandObj of HIGH_PROFILE_BRANDS) {
      const brand = brandObj.name;
      const isOfficial = domain === brandObj.domain || domain.endsWith(`.${brandObj.domain}`);
      if (isOfficial) continue;

      const dist = levenshteinDistance(domainWithoutTld, brand);
      if (dist > 0 && dist <= 2 && domainWithoutTld.length >= 4) {
        hasLookalike = true;
        lookalikeDetails = { targetBrand: brand, simulatedDomain: domainWithoutTld };
        break;
      }
    }
  }

  const isSuspiciousTld = SUSPICIOUS_TLDS.includes(parsed.tld.toLowerCase());
  const isDisposable = DISPOSABLE_EMAIL_DOMAINS.includes(domain);
  const isFreeWebmail = FREE_WEBMAIL_PROVIDERS.includes(domain);
  const isTrusted = TRUSTED_DOMAINS.some(td => domain === td || domain.endsWith(`.${td}`));

  // Display Name Spoofing vs External Sender (e.g. Display Name says "CEO Office" / "IT Support" but sent from free mail / random domain)
  let displayNameMismatch = false;
  let displayNameSpoofingDetails = null;

  if (displayName && domain && !isTrusted) {
    const cleanName = displayName.replace(/[^a-z0-9]/g, '');
    const cleanDomain = domain.split('.')[0].replace(/[^a-z0-9]/g, '');
    
    // Check if display name claims an institutional role
    const institutionalTerms = ['security', 'support', 'executive', 'officer', 'ceo', 'admin', 'billing', 'payroll', 'bank', 'verification', 'helpdesk'];
    const claimsAuthority = institutionalTerms.some(term => displayName.includes(term));

    if (claimsAuthority && (isFreeWebmail || isSuspiciousTld || (!cleanDomain.includes(cleanName) && cleanName.length > 5))) {
      displayNameMismatch = true;
      displayNameSpoofingDetails = `Display name "${parsed.displayName}" claims administrative or organizational authority from non-corporate domain "${domain}"`;
    }
  }

  return {
    parsed,
    domain,
    domainEntropy,
    brandImpersonationFound,
    brandOfficialDomain,
    hasLookalike,
    lookalikeDetails,
    isSuspiciousTld,
    isDisposable,
    isFreeWebmail,
    isTrusted,
    displayNameMismatch,
    displayNameSpoofingDetails
  };
}

// Psychological & Linguistic ML Signals
function extractLinguisticFeatures(text) {
  if (!text) {
    return {
      urgencyScore: 0,
      financialPressureScore: 0,
      credentialLureScore: 0,
      authorityPressureScore: 0,
      overallPsychologicalPressure: 0
    };
  }

  const lower = text.toLowerCase();

  // 1. Urgency / Fear pressure
  const urgencyTerms = ['immediate', 'immediately', 'urgent', 'within 24 hours', 'within 12 hours', 'expires', 'suspended', 'termination', 'deactivated', 'locked out', 'action required'];
  let urgencyMatches = 0;
  urgencyTerms.forEach(term => {
    if (lower.includes(term)) urgencyMatches++;
  });
  const urgencyScore = Math.min(1.0, urgencyMatches * 0.25);

  // 2. Financial / Transactional lures
  const financialTerms = ['wire transfer', 'escrow', 'direct deposit', 'gift card', 'bitcoin', 'crypto', 'invoice overdue', 'payroll update', 'bank account', 'tax refund', '$48,', '$50,', 'routing number'];
  let financialMatches = 0;
  financialTerms.forEach(term => {
    if (lower.includes(term)) financialMatches++;
  });
  const financialPressureScore = Math.min(1.0, financialMatches * 0.30);

  // 3. Credential Harvesting lures
  const credTerms = ['verify password', 'reset password', 'confirm identity', 'verify account', 'log in here', 'login here', 'click here to verify', 'security alert', 'unauthorized sign-in', 'unauthorized login'];
  let credMatches = 0;
  credTerms.forEach(term => {
    if (lower.includes(term)) credMatches++;
  });
  const credentialLureScore = Math.min(1.0, credMatches * 0.30);

  // 4. Authority / Secrecy Pressure (BEC)
  const authorityTerms = ['do not call', 'confidential meeting', 'acquisition', 'wire right away', 'cannot talk', 'are you at your desk'];
  let authorityMatches = 0;
  authorityTerms.forEach(term => {
    if (lower.includes(term)) authorityMatches++;
  });
  const authorityPressureScore = Math.min(1.0, authorityMatches * 0.35);

  const overallPsychologicalPressure = Math.min(1.0, (urgencyScore + financialPressureScore + credentialLureScore + authorityPressureScore) / 2.0);

  return {
    urgencyScore,
    financialPressureScore,
    credentialLureScore,
    authorityPressureScore,
    overallPsychologicalPressure
  };
}

// Text Structural & Statistical Feature Extractor
function extractEmailTextFeatures(text) {
  if (!text) {
    return {
      num_chars: 0,
      num_words: 0,
      num_lines: 0,
      num_exclamations: 0,
      num_question_marks: 0,
      num_dollar_signs: 0,
      num_uppercase: 0,
      uppercase_ratio: 0,
      suspicious_word_count: 0,
      suspicious_words_found: [],
      entropy: 0,
      linguistic: extractLinguisticFeatures('')
    };
  }

  const num_chars = text.length;
  const words = text.trim().split(/\s+/).filter(Boolean);
  const num_words = words.length;
  const num_lines = text.split('\n').length;

  const num_exclamations = (text.match(/!/g) || []).length;
  const num_question_marks = (text.match(/\?/g) || []).length;
  const num_dollar_signs = (text.match(/\$/g) || []).length;
  const num_uppercase = (text.match(/[A-Z]/g) || []).length;
  const uppercase_ratio = num_chars > 0 ? parseFloat((num_uppercase / num_chars).toFixed(3)) : 0;

  const suspicious_words_found = [];
  for (const word of SUSPICIOUS_WORDS) {
    const regex = new RegExp(`\\b${word}\\b`, 'gi');
    const matches = text.match(regex);
    if (matches) {
      suspicious_words_found.push({ word, count: matches.length });
    }
  }
  const suspicious_word_count = suspicious_words_found.reduce((acc, curr) => acc + curr.count, 0);
  const entropy = calculateEntropy(text);
  const linguistic = extractLinguisticFeatures(text);

  return {
    num_chars,
    num_words,
    num_lines,
    num_exclamations,
    num_question_marks,
    num_dollar_signs,
    num_uppercase,
    uppercase_ratio,
    suspicious_word_count,
    suspicious_words_found,
    entropy,
    linguistic
  };
}

// Deep URL Feature Extractor
function extractUrlFeatures(urlStr) {
  if (!urlStr) {
    return {
      url: '',
      domain: '',
      tld: '',
      length: 0,
      num_dots: 0,
      num_hyphens: 0,
      num_subdomains: 0,
      has_ip: false,
      is_https: false,
      has_at: false,
      entropy: 0,
      has_login: false,
      has_update: false,
      is_suspicious_tld: false,
      is_trusted: false
    };
  }

  const length = urlStr.length;
  const num_dots = (urlStr.match(/\./g) || []).length;
  const num_hyphens = (urlStr.match(/-/g) || []).length;
  const is_https = urlStr.toLowerCase().startsWith('https://');
  const has_at = urlStr.includes('@');
  const has_ip = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(urlStr);

  let num_subdomains = 0;
  let domain = '';
  let tld = '';

  try {
    const parsedUrl = new URL(urlStr.startsWith('http') ? urlStr : `http://${urlStr}`);
    domain = parsedUrl.hostname.toLowerCase();
    const parts = domain.split('.');
    if (parts.length > 1) {
      tld = parts[parts.length - 1];
    }
    if (parts.length > 2) {
      num_subdomains = parts.length - 2;
    }
  } catch {
    domain = urlStr.split('/')[0] || '';
  }

  const entropy = calculateEntropy(urlStr);
  const is_suspicious_tld = SUSPICIOUS_TLDS.includes(tld.toLowerCase());
  const is_trusted = TRUSTED_DOMAINS.some(td => domain === td || domain.endsWith(`.${td}`));

  return {
    url: urlStr,
    domain,
    tld,
    length,
    num_dots,
    num_hyphens,
    num_subdomains,
    has_ip,
    is_https,
    has_at,
    entropy,
    has_login: /login|signin|verify|account|banking|password|auth|security/i.test(urlStr),
    has_update: /update|confirm|secure|restore|recover|unlock/i.test(urlStr),
    is_suspicious_tld,
    is_trusted
  };
}

module.exports = {
  SUSPICIOUS_WORDS,
  SUSPICIOUS_TLDS,
  HIGH_PROFILE_BRANDS,
  DISPOSABLE_EMAIL_DOMAINS,
  FREE_WEBMAIL_PROVIDERS,
  TRUSTED_DOMAINS,
  calculateEntropy,
  levenshteinDistance,
  normalizeHomoglyphs,
  extractUrls,
  parseEmailHeaders,
  parseSender,
  extractSenderFeatures,
  extractLinguisticFeatures,
  extractEmailTextFeatures,
  extractUrlFeatures
};
