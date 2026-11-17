import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  MailSearch,
  ExternalLink,
  X,
  FileText,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { EmailAnalysisResult, AiThreatAnalysis } from '../types';
import { ShapBarChart } from './ShapBarChart';
import { AiThreatAnalysisSection } from './AiThreatAnalysisSection';

interface EmailScannerProps {
  initialEmailText?: string;
  initialSender?: string;
  onJumpToSenderVerifier: (sender: string) => void;
  onAnalysisComplete: (result: EmailAnalysisResult) => void;
}

const SAMPLE_EMAILS = {
  phish_paypal: `From: "PayPal Security" <security-alert@paypa1-account-update.xyz>\nSubject: URGENT: Your PayPal Account Has Been Suspended! Verify Identity\n\nDear Valued Customer,\n\nWe detected multiple unauthorized sign-in attempts to your PayPal account from unknown IP 194.26.29.11.\n\nFor your safety, YOUR ACCOUNT HAS BEEN TEMPORARILY SUSPENDED.\n\nYou must verify your password and banking details within 24 hours to prevent permanent account termination.\n\nClick here immediately: http://verify-paypal-user.security-update.xyz/login\n\nUrgent action required!\n\nSecurity Team\nPayPal Inc.`,
  phish_ceo: `From: "Chief Executive Officer" <executive-office@vendor-consulting.com>\nSubject: Vendor Acquisition Payment Discussion\n\nPlease review the vendor acquisition payment details when convenient. I am away from my desk today and would appreciate confirmation that the escrow paperwork is ready.\n\nRegards,\nChief Executive Officer`,
  legit_work: `From: "Sarah Miller" <sarah.miller@acme-corp.com>\nSubject: Project Kickoff Q3: Slides & Agenda for Monday 10:00 AM\n\nHi everyone,\n\nI have finalized the agenda and quarterly targets for our Q3 strategy rollout. Please review the shared Google Doc before our kickoff meeting on Monday at 10:00 AM PST.\n\nMeeting link: https://meet.google.com/abc-defg-hij\n\nBest regards,\nSarah Miller\nLead Product Architect`
};

export const EmailScanner: React.FC<EmailScannerProps> = ({
  initialEmailText = '',
  initialSender = '',
  onJumpToSenderVerifier,
  onAnalysisComplete
}) => {
  const [senderInput, setSenderInput] = useState(initialSender);
  const [emailText, setEmailText] = useState(initialEmailText);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<EmailAnalysisResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AiThreatAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  useEffect(() => {
    if (initialEmailText) {
      setEmailText(initialEmailText);
      const match = initialEmailText.match(/^From:\s*(.+)$/im);
      if (match && match[1] && !senderInput) {
        setSenderInput(match[1].trim());
      }
    }
    if (initialSender) {
      setSenderInput(initialSender);
    }
  }, [initialEmailText, initialSender]);

  const handleEmailTextChange = (val: string) => {
    setEmailText(val);
    if (!senderInput.trim()) {
      const match = val.match(/^From:\s*(.+)$/im);
      if (match && match[1]) {
        setSenderInput(match[1].trim());
      }
    }
  };

  const handleSelectSample = (key: keyof typeof SAMPLE_EMAILS) => {
    const text = SAMPLE_EMAILS[key];
    setEmailText(text);
    const match = text.match(/^From:\s*(.+)$/im);
    if (match && match[1]) {
      setSenderInput(match[1].trim());
    }
    triggerAnalysis(text, match && match[1] ? match[1].trim() : '', selectedFiles);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const newFiles = Array.from(e.target.files);
      const combined = [...selectedFiles, ...newFiles].slice(0, 20);
      setSelectedFiles(combined);
    }
  };

  const handleRemoveFile = (index: number) => {
    setSelectedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const runAiAnalysis = async (content: string, sender: string, files?: Array<{ filename: string; mime_type?: string }>) => {
    if (!content.trim() && !sender.trim()) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const res = await fetch('/api/ai-threat-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'email',
          content,
          sender,
          attachments: files
        })
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || 'AI analysis failed');
      }
      setAiAnalysis(data);
    } catch (err: any) {
      setAiError(err.message || 'AI threat investigation could not be completed.');
    } finally {
      setAiLoading(false);
    }
  };

  const handleClear = () => {
    setEmailText('');
    setSenderInput('');
    setSelectedFiles([]);
    setResult(null);
    setErrorMsg(null);
    setAiAnalysis(null);
    setAiError(null);
    setAiLoading(false);
  };

  const triggerAnalysis = async (text: string, sender: string, files: File[]) => {
    const trimmedText = text.trim();
    const trimmedSender = sender.trim();

    if (!trimmedText && !trimmedSender && files.length === 0) {
      return;
    }

    setLoading(true);
    setErrorMsg(null);

    // Concurrently trigger independent Agentic AI Threat Analysis
    runAiAnalysis(
      trimmedText,
      trimmedSender,
      files.map(f => ({ filename: f.name, mime_type: f.type }))
    );

    try {
      const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
      if (files.length > 20) {
        throw new Error('Select no more than 20 attachments at a time.');
      }
      if (totalBytes > 35 * 1024 * 1024) {
        throw new Error('Selected attachments exceed the 35 MB total limit.');
      }

      const attachmentsPayload = await Promise.all(
        files.map(async file => {
          const dataUrl = await new Promise<string>((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result as string);
            reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
            reader.readAsDataURL(file);
          });
          return {
            filename: file.name,
            mime_type: file.type,
            content_base64: dataUrl.split(',', 2)[1]
          };
        })
      );

      const res = await fetch('/api/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email_text: trimmedText,
          sender_email: trimmedSender,
          attachments: attachmentsPayload
        })
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Email analysis failed.');
      }

      setResult(data);
      onAnalysisComplete(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'Email analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const charCount = emailText.length;
  const wordCount = emailText.trim() ? emailText.trim().split(/\s+/).filter(Boolean).length : 0;

  const isPhish = result?.classification === 'Phishing';
  const isSuspicious = result?.classification === 'Suspicious';
  const riskLevel = result?.risk_level || (result?.risk_score && result.risk_score >= 70 ? 'High' : result?.risk_score && result.risk_score >= 28 ? 'Medium' : 'Low');

  return (
    <div className="space-y-6">
      {/* Presets Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
        <div>
          <h2 className="text-sm font-bold text-slate-900">Email Threat Analysis</h2>
          <p className="text-xs text-slate-500">Paste email text or choose an example below to check for phishing.</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-500">Examples:</span>
          <button
            onClick={() => handleSelectSample('phish_paypal')}
            className="text-xs px-2.5 py-1 rounded-md bg-red-50 text-red-700 hover:bg-red-100 border border-red-200 font-medium transition cursor-pointer"
          >
            PayPal Scam
          </button>
          <button
            onClick={() => handleSelectSample('phish_ceo')}
            className="text-xs px-2.5 py-1 rounded-md bg-amber-50 text-amber-800 hover:bg-amber-100 border border-amber-200 font-medium transition cursor-pointer"
          >
            CEO Wire Request
          </button>
          <button
            onClick={() => handleSelectSample('legit_work')}
            className="text-xs px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 font-medium transition cursor-pointer"
          >
            Normal Email
          </button>
        </div>
      </div>

      {/* Main Grid: Input on Left, Result on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Input Area */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
            <div className="space-y-1">
              <label htmlFor="emailSenderInput" className="text-xs font-semibold text-slate-700 flex items-center justify-between">
                <span>Sender Address (Optional)</span>
                <span className="text-[11px] text-slate-400 font-normal">Auto-detected</span>
              </label>
              <input
                id="emailSenderInput"
                type="text"
                value={senderInput}
                onChange={e => setSenderInput(e.target.value)}
                placeholder="e.g. security@paypal-verify.xyz"
                className="w-full bg-slate-50 border border-slate-200 focus:border-blue-500 focus:bg-white focus:ring-1 focus:ring-blue-500 rounded-lg px-3 py-2 text-xs text-slate-800 font-mono transition"
              />
            </div>

            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <label htmlFor="emailInput" className="text-xs font-semibold text-slate-700">Email Content</label>
                <button
                  type="button"
                  onClick={handleClear}
                  className="text-xs text-slate-400 hover:text-slate-600 transition cursor-pointer"
                >
                  Clear
                </button>
              </div>
              <textarea
                id="emailInput"
                rows={8}
                value={emailText}
                onChange={e => handleEmailTextChange(e.target.value)}
                className="w-full bg-slate-50 border border-slate-200 focus:border-blue-500 focus:bg-white focus:ring-1 focus:ring-blue-500 rounded-lg p-3 text-xs text-slate-800 placeholder-slate-400 font-mono transition resize-none custom-scrollbar"
                placeholder="Paste email subject and body text here..."
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="emailAttachmentInput" className="text-xs font-semibold text-slate-700">Attachments (Optional)</label>
              <input
                id="emailAttachmentInput"
                type="file"
                multiple
                onChange={handleFileChange}
                className="block w-full text-xs text-slate-600 file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-3 file:py-1.5 file:text-xs file:font-medium hover:file:bg-slate-200 cursor-pointer"
              />
              <p className="text-[11px] text-slate-400">Select up to 20 files and 35 MB total for static attachment analysis.</p>

              {selectedFiles.length > 0 && (
                <div className="mt-2 space-y-1 max-h-28 overflow-y-auto custom-scrollbar border border-slate-100 rounded-lg p-2 bg-slate-50">
                  {selectedFiles.map((file, idx) => (
                    <div key={`${file.name}-${idx}`} className="flex items-center justify-between text-xs text-slate-700 bg-white p-1.5 rounded border border-slate-200">
                      <span className="truncate max-w-[200px] flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        <span className="font-mono text-[11px] truncate">{file.name}</span>
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-slate-400">{(file.size / 1024).toFixed(1)} KB</span>
                        <button
                          type="button"
                          onClick={() => handleRemoveFile(idx)}
                          className="text-slate-400 hover:text-red-500"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>{charCount} characters</span>
              <span>{wordCount} words</span>
            </div>

            <button
              id="btnAnalyzeEmail"
              onClick={() => triggerAnalysis(emailText, senderInput, selectedFiles)}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm transition shadow-sm cursor-pointer disabled:opacity-60"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>Analyzing Email...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Analyze Email</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Result View */}
        <div className="lg:col-span-7 space-y-4">
          {errorMsg && (
            <div role="alert" className="bg-red-50 border border-red-200 rounded-xl p-4 text-xs text-red-800">
              {errorMsg}
            </div>
          )}

          {!result && !loading && !errorMsg && (
            <div className="bg-white border border-slate-200 border-dashed rounded-xl p-12 text-center space-y-2">
              <div className="w-10 h-10 rounded-full bg-slate-100 text-slate-400 mx-auto flex items-center justify-center">
                <MailSearch className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-slate-800">No Email Analyzed</h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Enter email content on the left or select an example above to see threat risk and detection factors.
              </p>
            </div>
          )}

          {loading && (
            <div className="bg-white border border-slate-200 rounded-xl p-12 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
              <p className="text-xs font-semibold text-slate-700">Analyzing email content & threat signals...</p>
            </div>
          )}

          {result && !loading && (
            <div className="space-y-4">
              {/* Verdict Banner */}
              <div
                className={`border rounded-xl p-4 shadow-sm flex items-center justify-between gap-4 ${
                  isPhish
                    ? 'border-red-200 bg-red-50/60'
                    : isSuspicious
                    ? 'border-amber-200 bg-amber-50/60'
                    : 'border-blue-200 bg-blue-50/60'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-11 h-11 rounded-lg flex items-center justify-center text-white text-lg font-bold ${
                      isPhish ? 'bg-red-600' : isSuspicious ? 'bg-amber-500' : 'bg-blue-600'
                    }`}
                  >
                    {isPhish ? (
                      <ShieldAlert className="w-6 h-6" />
                    ) : isSuspicious ? (
                      <AlertTriangle className="w-6 h-6" />
                    ) : (
                      <ShieldCheck className="w-6 h-6" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-base font-bold tracking-tight ${isPhish ? 'text-red-900' : isSuspicious ? 'text-amber-900' : 'text-blue-900'}`}>
                        {isPhish ? 'PHISHING DETECTED' : isSuspicious ? 'SUSPICIOUS EMAIL' : 'CLEAN & SAFE'}
                      </span>
                      <span
                        className={`text-[11px] px-2 py-0.5 rounded font-bold uppercase ${
                          isPhish
                            ? 'bg-red-100 text-red-700 border border-red-200'
                            : isSuspicious
                            ? 'bg-amber-100 text-amber-800 border border-amber-200'
                            : 'bg-blue-100 text-blue-700 border border-blue-200'
                        }`}
                      >
                        {riskLevel.toUpperCase()} RISK
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Confidence:{' '}
                      <span className="font-semibold text-slate-800">
                        {result.confidence_label || (result.probability ? `${(result.probability * 100).toFixed(0)}%` : 'Evaluated')}
                      </span>
                    </p>
                  </div>
                </div>

                {/* Score */}
                <div className="text-right pr-2">
                  <span className="block text-[10px] text-slate-400 uppercase font-semibold">Risk Score</span>
                  <span className="text-xl font-bold text-slate-900">{Math.round(result.risk_score)}/100</span>
                </div>
              </div>

              {/* Sender intelligence */}
              {result.sender_analysis && (result.sender_analysis.sender_email || result.sender_analysis.domain) && (
                <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
                    <span className="flex items-center gap-1.5">
                      <span>Sender Address Intelligence</span>
                    </span>
                    <button
                      onClick={() => onJumpToSenderVerifier(result.sender_analysis?.sender_email || senderInput)}
                      className="text-[11px] text-blue-600 hover:text-blue-800 flex items-center gap-1 cursor-pointer"
                    >
                      <span>Deep Inspect in Verifier</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </div>

                  <div className="flex items-center justify-between bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                    <div className="flex items-center gap-2 truncate">
                      <span className="font-mono text-slate-800 font-medium truncate">
                        {result.sender_analysis.sender_email || senderInput}
                      </span>
                      {result.sender_analysis.features?.brandImpersonationFound || result.sender_analysis.features?.hasLookalike ? (
                        <span className="text-[11px] px-2 py-0.5 rounded font-bold bg-red-100 text-red-700 border border-red-200">
                          SPOOFED
                        </span>
                      ) : result.sender_analysis.features?.isTrusted ? (
                        <span className="text-[11px] px-2 py-0.5 rounded font-bold bg-blue-100 text-blue-700 border border-blue-200">
                          VERIFIED
                        </span>
                      ) : (
                        <span className="text-[11px] px-2 py-0.5 rounded font-medium bg-slate-100 text-slate-700 border border-slate-200">
                          EXTERNAL
                        </span>
                      )}
                    </div>
                    <span className={`font-semibold text-xs shrink-0 ${(result.sender_analysis.risk_score || 0) >= 60 ? 'text-red-600' : 'text-blue-600'}`}>
                      Threat: {Math.round(result.sender_analysis.risk_score || 0)}%
                    </span>
                  </div>
                </div>
              )}

              {/* Email Authentication Headers (SPF/DKIM/DMARC) */}
              {result.header_analysis && result.header_analysis.hasAuthenticationResults && (
                <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
                    <span>Cryptographic Authentication Headers</span>
                    <span className={`text-[11px] ${
                      result.header_analysis.spf === 'pass' && result.header_analysis.dkim === 'pass' && result.header_analysis.dmarc === 'pass'
                        ? 'font-semibold text-blue-600'
                        : result.header_analysis.spf === 'fail' || result.header_analysis.dkim === 'fail' || result.header_analysis.dmarc === 'fail'
                        ? 'font-semibold text-red-600'
                        : 'font-medium text-slate-500'
                    }`}>
                      {result.header_analysis.spf === 'pass' && result.header_analysis.dkim === 'pass' && result.header_analysis.dmarc === 'pass'
                        ? 'All Cryptographic Checks Passed'
                        : result.header_analysis.spf === 'fail' || result.header_analysis.dkim === 'fail' || result.header_analysis.dmarc === 'fail'
                        ? 'Authentication Violations Detected'
                        : 'Partial Authentication Records'}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { label: 'SPF Policy', val: result.header_analysis.spf },
                      { label: 'DKIM Signature', val: result.header_analysis.dkim },
                      { label: 'DMARC Alignment', val: result.header_analysis.dmarc }
                    ].map(h => {
                      const val = h.val || 'none';
                      const isPass = val.toLowerCase().includes('pass');
                      const isFail = val.toLowerCase().includes('fail');
                      const bg = isPass
                        ? 'bg-blue-50 border-blue-200 text-blue-800'
                        : isFail
                        ? 'bg-red-50 border-red-200 text-red-800'
                        : 'bg-slate-50 border-slate-200 text-slate-700';

                      return (
                        <div key={h.label} className={`p-2 rounded-lg border ${bg}`}>
                          <span className="text-[10px] font-bold block opacity-75">{h.label}</span>
                          <span className="font-mono font-bold uppercase text-xs">{val}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Embedded URLs Diagnostic */}
              {result.url_analysis && result.url_analysis.length > 0 && (
                <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
                    <span>Embedded Destination URLs</span>
                    <span className="text-[11px] text-slate-400">
                      {result.url_analysis.length} link{result.url_analysis.length > 1 ? 's' : ''} found
                    </span>
                  </div>

                  <div className="space-y-2">
                    {result.url_analysis.map((item, idx) => {
                      const uRisk = item.diagnostics?.threat_probability || 0;
                      const uClass = item.diagnostics?.classification || 'Legitimate';
                      const isBad = uClass === 'Phishing';
                      const isWarn = uClass === 'Suspicious';
                      const badgeClass = isBad
                        ? 'bg-red-100 text-red-700 border-red-200'
                        : isWarn
                        ? 'bg-amber-100 text-amber-800 border-amber-200'
                        : 'bg-blue-100 text-blue-700 border-blue-200';

                      return (
                        <div
                          key={idx}
                          className={`p-2.5 rounded-lg border flex flex-col gap-1 ${
                            isBad ? 'bg-red-50/50 border-red-200' : isWarn ? 'bg-amber-50/50 border-amber-200' : 'bg-slate-50 border-slate-200'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-slate-800 font-medium truncate text-xs">{item.url}</span>
                            <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase border shrink-0 ${badgeClass}`}>
                              {uClass} ({Math.round(uRisk * 100)}%)
                            </span>
                          </div>
                          {item.diagnostics?.flags && item.diagnostics.flags.length > 0 && (
                            <div className="text-[11px] text-slate-600 space-y-0.5 mt-0.5">
                              {item.diagnostics.flags.map((f, fIdx) => (
                                <div key={fIdx}>&bull; {f}</div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Attachments Analysis */}
              {result.attachment_analysis && result.attachment_analysis.length > 0 && (
                <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
                    <span>Attachment Threat Analysis</span>
                    <span className="text-[11px] text-slate-400">
                      {result.attachment_analysis.length} file{result.attachment_analysis.length > 1 ? 's' : ''} inspected
                    </span>
                  </div>

                  <div className="space-y-2">
                    {result.attachment_analysis.map((att, idx) => {
                      const isBad = att.classification === 'Malicious';
                      const isWarn = att.classification === 'Suspicious';
                      const style = isBad
                        ? 'bg-red-50 border-red-200 text-red-800'
                        : isWarn
                        ? 'bg-amber-50 border-amber-200 text-amber-800'
                        : 'bg-blue-50 border-blue-200 text-blue-800';

                      return (
                        <div key={idx} className={`p-2.5 rounded-lg border text-xs ${style}`}>
                          <div className="flex justify-between items-center gap-2">
                            <span className="font-semibold font-mono truncate">{att.filename || 'Attachment'}</span>
                            <span className="font-semibold shrink-0">
                              {att.classification} &middot; {Math.round(att.risk_score || 0)}%
                            </span>
                          </div>
                          <p className="mt-1 text-[11px] opacity-90">
                            {att.detected_signals?.join('; ') || 'No static threat indicators found.'}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Security Guidance / Reasoning */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-1">
                <span className="text-xs font-semibold text-slate-700 block">Security Guidance & Analysis</span>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {result.reasoning || 'Email evaluated through multi-signal engine.'}
                </p>
              </div>

              {/* Detected Signals List */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                <span className="text-xs font-semibold text-slate-700 block">Identified Threat Signals & Indicators</span>
                <div className="space-y-1.5">
                  {(result.detected_signals && result.detected_signals.length > 0
                    ? result.detected_signals
                    : ['Standard communication structure and verified metrics.']
                  ).map((sig, idx) => (
                    <div
                      key={idx}
                      className={`p-2 rounded-lg border flex items-start gap-2 text-xs ${
                        isPhish
                          ? 'bg-red-50 border-red-100 text-red-900'
                          : isSuspicious
                          ? 'bg-amber-50 border-amber-100 text-amber-900'
                          : 'bg-blue-50 border-blue-100 text-blue-900'
                      }`}
                    >
                      {isPhish ? (
                        <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-red-600" />
                      ) : isSuspicious ? (
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-600" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5 text-blue-600" />
                      )}
                      <span className="leading-tight">{sig}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* SEPARATE AGENTIC AI ADVANCED THREAT ANALYSIS SECTION */}
              <AiThreatAnalysisSection
                analysis={aiAnalysis}
                loading={aiLoading}
                error={aiError}
                onRefresh={() =>
                  runAiAnalysis(
                    emailText,
                    senderInput,
                    selectedFiles.map(f => ({ filename: f.name, mime_type: f.type }))
                  )
                }
              />

              {/* SHAP Feature Contribution Chart */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                <span className="text-xs font-semibold text-slate-700 block">Model Explainability & Key Feature Weights</span>
                <ShapBarChart features={result.top_email_text_features} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
