// backend/engine/attachmentAnalyzer.js
// Node.js Static Attachment Threat Analyzer & Resilient Fallback Engine

const crypto = require('crypto');

const EXECUTABLE_EXTS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.cpl', '.msi',
  '.msp', '.hta', '.jar', '.gadget', '.msc', '.application'
]);

const SCRIPT_EXTS = new Set([
  '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1',
  '.sh', '.py', '.pyw', '.pl', '.php', '.rb', '.reg', '.inf'
]);

const MACRO_EXTS = new Set([
  '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.xlam', '.ppam', '.potm'
]);

const ARCHIVE_EXTS = new Set([
  '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.img',
  '.cab', '.ace', '.arj', '.lzh'
]);

const OFFICE_EXTS = new Set([
  '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf'
]);

const PDF_EXTS = new Set(['.pdf']);
const IMAGE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.bmp', '.webp', '.ico']);

function computeEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  const frequencies = new Map();
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    frequencies.set(byte, (frequencies.get(byte) || 0) + 1);
  }
  let entropy = 0;
  const len = buffer.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1000) / 1000;
}

function detectMagicBytes(buffer) {
  if (!buffer || buffer.length < 2) return { mime: 'application/octet-stream', desc: 'Empty or Unknown Data' };

  if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
    return { mime: 'application/x-dosexec', desc: 'Portable Executable / MS-DOS (EXE/DLL/SCR)', isPe: true };
  }
  if (buffer.length >= 4 && buffer.slice(0, 4).toString('ascii') === '%PDF') {
    return { mime: 'application/pdf', desc: 'Adobe Portable Document Format (PDF)', isPdf: true };
  }
  if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
    return { mime: 'application/zip', desc: 'ZIP Archive / Modern Office Document', isZip: true };
  }
  if (buffer.length >= 8 && buffer[0] === 0xD0 && buffer[1] === 0xCF && buffer[2] === 0x11 && buffer[3] === 0xE0) {
    return { mime: 'application/x-ole-storage', desc: 'Microsoft OLE Composite Document (.doc, .xls)', isOle: true };
  }
  if (buffer.length >= 4 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return { mime: 'image/png', desc: 'PNG Image', isImage: true };
  }
  if (buffer.length >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return { mime: 'image/jpeg', desc: 'JPEG Image', isImage: true };
  }
  if (buffer.length >= 4 && buffer.slice(0, 4).toString('ascii').startsWith('GIF')) {
    return { mime: 'image/gif', desc: 'GIF Image', isImage: true };
  }
  if (buffer.length >= 4 && buffer.slice(0, 4).toString('ascii') === 'Rar!') {
    return { mime: 'application/x-rar', desc: 'RAR Archive', isArchive: true };
  }
  if (buffer.length >= 6 && buffer[0] === 0x37 && buffer[1] === 0x7A && buffer[2] === 0xBC && buffer[3] === 0xAF) {
    return { mime: 'application/x-7z-compressed', desc: '7-Zip Archive', isArchive: true };
  }

  return { mime: 'application/octet-stream', desc: 'Binary Data' };
}

function analyzeAttachment(fileBuffer, originalFilename = '', declaredMime = '') {
  const filename = (originalFilename || 'attachment').trim();
  const lowerName = filename.toLowerCase();
  const hasRtlo = filename.includes('\u202e');
  const cleanName = filename.replace(/\u202e/g, '');

  const extMatch = cleanName.match(/\.([a-z0-9]+)$/i);
  const ext = extMatch ? `.${extMatch[1].toLowerCase()}` : '';

  // Double extension inspection
  const parts = cleanName.split('.');
  let hasDoubleExt = false;
  let innerExt = '';
  let outerExt = '';

  if (parts.length >= 3) {
    const inner = `.${parts[parts.length - 2].toLowerCase().trim()}`;
    const outer = `.${parts[parts.length - 1].toLowerCase().trim()}`;
    const benignInner = OFFICE_EXTS.has(inner) || PDF_EXTS.has(inner) || IMAGE_EXTS.has(inner) || inner === '.txt';
    const riskyOuter = EXECUTABLE_EXTS.has(outer) || SCRIPT_EXTS.has(outer) || MACRO_EXTS.has(outer);
    if (benignInner && riskyOuter) {
      hasDoubleExt = true;
      innerExt = inner;
      outerExt = outer;
    }
  }

  const hasHiddenSpaces = /\.[a-z0-9]+\s{2,}\.[a-z0-9]+/i.test(cleanName);

  const buffer = Buffer.isBuffer(fileBuffer) ? fileBuffer : Buffer.from(fileBuffer || '');
  const size = buffer.length;
  const entropy = computeEntropy(buffer);
  const magic = detectMagicBytes(buffer);

  // Magic mismatch check
  let magicMismatch = false;
  if (magic.isPe && (OFFICE_EXTS.has(ext) || PDF_EXTS.has(ext) || IMAGE_EXTS.has(ext) || ext === '.txt')) {
    magicMismatch = true;
  } else if (PDF_EXTS.has(ext) && !magic.isPdf && size > 128) {
    magicMismatch = true;
  } else if (IMAGE_EXTS.has(ext) && !magic.isImage && size > 128) {
    magicMismatch = true;
  }

  // Text string heuristics
  const sampleText = buffer.slice(0, 300000).toString('latin1').toLowerCase();

  // Macro check
  const hasVba = sampleText.includes('vbaproject.bin') || sampleText.includes('_vba_project') || sampleText.includes('attribut vb_name');
  const hasAutoExec = /(autoopen|workbook_open|document_open|autoexec|auto_open)/i.test(sampleText);
  const hasMacroApis = /(wscript\.shell|createobject|powershell|urldownloadtofile|virtualalloc|callbyname)/i.test(sampleText);

  // Script triggers
  const hasScriptTriggers = /(downloadstring|frombase64string|iex\b|certutil\s+-urlcache|activexobject|wscript\.createobject|executionpolicy\s+bypass)/i.test(sampleText);

  // PDF JS & Launch
  const pdfHasJs = PDF_EXTS.has(ext) && /\/(javascript|js)\b/i.test(sampleText);
  const pdfHasLaunch = PDF_EXTS.has(ext) && /\/(launch|openaction|aa)\b/i.test(sampleText);
  const pdfHasEmbedded = PDF_EXTS.has(ext) && /\/embeddedfiles\b/i.test(sampleText);

  // Flags & signals
  const detectedSignals = [];
  let threatScore = 0.05;

  if (hasDoubleExt) {
    threatScore += 0.85;
    detectedSignals.push(`Deceptive double extension: "${filename}" hides executable extension "${outerExt}" behind "${innerExt}"`);
  }
  if (hasRtlo) {
    threatScore += 0.85;
    detectedSignals.push(`Unicode Right-to-Left Override spoofing detected in attachment filename`);
  }
  if (hasHiddenSpaces) {
    threatScore += 0.40;
    detectedSignals.push(`Hidden whitespace spacing detected in filename to disguise real extension`);
  }
  if (magicMismatch) {
    threatScore += 0.90;
    detectedSignals.push(`MIME / Header Mismatch: Declared as "${ext}" but raw content is a ${magic.desc}`);
  }
  if (magic.isPe && !EXECUTABLE_EXTS.has(ext)) {
    threatScore += 0.90;
    detectedSignals.push(`Windows PE executable disguised as non-executable file`);
  } else if (EXECUTABLE_EXTS.has(ext)) {
    threatScore += 0.75;
    detectedSignals.push(`Executable binary attachment (${ext}) frequently leveraged for direct malware execution`);
  }
  if (hasAutoExec && hasMacroApis) {
    threatScore += 0.85;
    detectedSignals.push(`Weaponized Office document: VBA macro with Auto-Execution trigger and dangerous system APIs`);
  } else if (hasAutoExec) {
    threatScore += 0.60;
    detectedSignals.push(`Office document contains Auto-Execution macro trigger (runs on file open)`);
  } else if (hasVba) {
    threatScore += 0.35;
    detectedSignals.push(`Embedded VBA macro code detected in Office attachment`);
  }
  if (MACRO_EXTS.has(ext) && !hasVba) {
    threatScore += 0.35;
    detectedSignals.push(`Macro-enabled Office attachment (${ext}); verify its source before opening`);
  }
  if (SCRIPT_EXTS.has(ext) && hasScriptTriggers) {
    threatScore += 0.80;
    detectedSignals.push(`Malicious script commands detected (DownloadString, Base64 payload, or PowerShell evasion)`);
  } else if (SCRIPT_EXTS.has(ext)) {
    threatScore += 0.45;
    detectedSignals.push(`Script file attachment (${ext}) capable of executing arbitrary commands`);
  }
  if (pdfHasLaunch) {
    threatScore += 0.75;
    detectedSignals.push(`PDF document contains external executable launch command (/Launch)`);
  }
  if (pdfHasJs) {
    threatScore += 0.50;
    detectedSignals.push(`PDF document contains active JavaScript streams (/JavaScript)`);
  }
  if (ARCHIVE_EXTS.has(ext) && /(exe|scr|bat|cmd|vbs|ps1)\b/i.test(sampleText)) {
    threatScore += 0.70;
    detectedSignals.push(`Archive file contains concealed executable or script payload`);
  }
  if (entropy > 7.45 && !ARCHIVE_EXTS.has(ext) && !IMAGE_EXTS.has(ext)) {
    threatScore += 0.35;
    detectedSignals.push(`Abnormally high Shannon entropy (${entropy}): indicator of packed or encrypted payload`);
  }

  // Safe indicator balance
  if (PDF_EXTS.has(ext) && magic.isPdf && !pdfHasJs && !pdfHasLaunch && !hasDoubleExt) {
    threatScore -= 0.15;
  }
  if (IMAGE_EXTS.has(ext) && magic.isImage && !hasDoubleExt) {
    threatScore -= 0.20;
  }
  if (OFFICE_EXTS.has(ext) && magic.isZip && !hasVba && !hasDoubleExt) {
    threatScore -= 0.15;
  }

  const finalScore = Math.max(0.01, Math.min(0.99, threatScore));
  let classification = 'Safe';
  if (finalScore >= 0.65) {
    classification = 'Malicious';
  } else if (finalScore >= 0.28) {
    classification = 'Suspicious';
  }

  if (detectedSignals.length === 0) {
    detectedSignals.push('Static file headers, extension, and content structure align with clean standards.');
  }

  const riskScore = Math.round(finalScore * 100);
  const probabilities = classification === 'Malicious'
    ? { safe: (1 - finalScore) / 2, suspicious: (1 - finalScore) / 2, malicious: finalScore }
    : classification === 'Suspicious'
      ? { safe: (1 - finalScore) / 4, suspicious: 0.5 + finalScore / 2, malicious: (1 - finalScore) / 4 }
      : { safe: 1 - finalScore, suspicious: finalScore, malicious: 0 };

  return {
    filename,
    extension: ext,
    file_size: size,
    formatted_size: size >= 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B`,
    entropy,
    declared_mime: declaredMime || 'application/octet-stream',
    detected_mime: magic.mime,
    magic_description: magic.desc,
    magic_mismatch: magicMismatch,
    is_pe_binary: !!magic.isPe,
    classification,
    risk_score: riskScore,
    threat_probability: finalScore,
    probabilities,
    diagnostics: {
      filename,
      extension: ext,
      file_size: size,
      entropy,
      declared_mime: declaredMime,
      detected_mime: magic.mime,
      magic_description: magic.desc,
      magic_mismatch: magicMismatch,
      is_pe_binary: !!magic.isPe,
      double_extension: { has_double_extension: hasDoubleExt, inner_extension: innerExt, outer_extension: outerExt, has_rtlo: hasRtlo, has_hidden_spaces: hasHiddenSpaces },
      macro_analysis: { has_macros: hasVba, has_autoexec: hasAutoExec, has_macro_apis: hasMacroApis },
      script_analysis: { has_scripts: SCRIPT_EXTS.has(ext), has_triggers: hasScriptTriggers },
      pdf_analysis: { has_javascript: pdfHasJs, has_launch_action: pdfHasLaunch, has_embedded_files: pdfHasEmbedded }
    },
    detected_signals: detectedSignals,
    top_attachment_features: {
      [hasDoubleExt ? 'Double Extension Cloaking' : magicMismatch ? 'MIME / Header Mismatch' : hasVba ? 'VBA Macro Stream' : isExecutable(ext) ? 'Executable Binary Type' : 'Document Format Integrity']: classification === 'Malicious' ? 2.8 : classification === 'Suspicious' ? 1.4 : -1.5,
      'Entropy Obfuscation': entropy > 7.3 ? 1.2 : -0.8
    }
  };
}

function isExecutable(ext) {
  return EXECUTABLE_EXTS.has(ext) || SCRIPT_EXTS.has(ext);
}

module.exports = {
  analyzeAttachment,
  computeEntropy,
  detectMagicBytes,
  EXECUTABLE_EXTS,
  SCRIPT_EXTS,
  MACRO_EXTS,
  ARCHIVE_EXTS
};
