// backend/engine/mlClient.js
// Talks to the local Python inference + SHAP service.

const ML_BASE_URL = process.env.ML_INFER_URL || 'http://127.0.0.1:5001';
const TIMEOUT_MS = Number(process.env.ML_TIMEOUT_MS || 8000);

async function mlRequest(pathname, body, timeoutMs = TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${ML_BASE_URL}${pathname}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`ML ${pathname} ${res.status}: ${errText}`);
    }
    return await res.json();
  } catch (err) {
    console.warn(`[ML] ${pathname} unavailable:`, err.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function predictEmail(emailText, senderEmail, urls, attachments) {
  return mlRequest('/predict', {
    email_text: emailText || '',
    sender_email: senderEmail || '',
    urls: Array.isArray(urls) ? urls : undefined,
    attachments: Array.isArray(attachments) ? attachments : undefined
  }, attachments?.length ? Math.max(TIMEOUT_MS, 30000) : TIMEOUT_MS);
}

function predictUrl(url) {
  return mlRequest('/predict_url', { url });
}

function predictAttachment(attachmentData) {
  return mlRequest('/predict_attachment', {
    filename: attachmentData.filename || 'attachment',
    content_base64: attachmentData.content_base64 || attachmentData.data || '',
    mime_type: attachmentData.mime_type || attachmentData.mime || ''
  }, Math.max(TIMEOUT_MS, 15000));
}

async function getAttachmentMetrics() {
  try {
    const res = await fetch(`${ML_BASE_URL}/attachment_metrics`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function predictEmailBatch(items) {
  return mlRequest('/predict_batch', { items: items || [] }, Math.max(TIMEOUT_MS, 20000));
}

async function mlHealth() {
  try {
    const res = await fetch(`${ML_BASE_URL}/health`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) return { ok: false };
    return { ok: true, ...(await res.json()) };
  } catch {
    return { ok: false };
  }
}

function mergeShap(heuristicShap, mlShap) {
  const out = {};
  if (mlShap && typeof mlShap === 'object') {
    Object.entries(mlShap).forEach(([k, v]) => {
      out[k] = Math.round(Number(v) * 1000) / 1000;
    });
  }
  if (heuristicShap && typeof heuristicShap === 'object') {
    Object.entries(heuristicShap).forEach(([k, v]) => {
      if (!(k in out)) out[k] = Math.round(Number(v) * 100) / 100;
    });
  }
  return out;
}

function blendScores(heuristicScore, mlProb) {
  if (typeof mlProb !== 'number' || Number.isNaN(mlProb)) {
    return heuristicScore;
  }
  let blended = 0.42 * heuristicScore + 0.58 * mlProb;
  if (heuristicScore >= 0.6 && mlProb >= 0.6) blended = Math.max(blended, 0.78);
  if (heuristicScore <= 0.15 && mlProb <= 0.25) blended = Math.min(blended, 0.16);
  return Math.max(0.01, Math.min(0.99, blended));
}

function classifyFromScore(score) {
  if (score >= 0.60) return 'Phishing';
  if (score >= 0.28) return 'Suspicious';
  return 'Legitimate';
}

module.exports = {
  ML_BASE_URL,
  blendScores,
  classifyFromScore,
  getAttachmentMetrics,
  mergeShap,
  mlHealth,
  predictAttachment,
  predictEmail,
  predictEmailBatch,
  predictUrl
};
