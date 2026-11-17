import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  AlertCircle,
  AtSign,
  Search
} from 'lucide-react';
import { SenderAnalysisResult } from '../types';

interface SenderVerifierProps {
  initialSender?: string;
  onAnalysisComplete: (result: SenderAnalysisResult) => void;
}

const SAMPLE_SENDERS = {
  paypal_fake: `"PayPal Security Team" <security-alert@paypa1-account-update.xyz>`,
  ceo_spoof: `"Office of CEO" <executive-office@wire-transfer-ceo.link>`,
  google_legit: `"Google Cloud Security" <cloud-noreply@google.com>`
};

export const SenderVerifier: React.FC<SenderVerifierProps> = ({
  initialSender = '',
  onAnalysisComplete
}) => {
  const [senderInput, setSenderInput] = useState(initialSender);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<SenderAnalysisResult | null>(null);

  useEffect(() => {
    if (initialSender) {
      setSenderInput(initialSender);
      verifySender(initialSender);
    }
  }, [initialSender]);

  const verifySender = async (senderVal: string) => {
    const trimmed = senderVal.trim();
    if (!trimmed) return;

    setLoading(true);
    setErrorMsg(null);

    try {
      const res = await fetch('/predict_sender', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender_email: trimmed })
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Sender analysis failed');
      }

      setResult(data);
      onAnalysisComplete(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to verify sender address');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectSample = (key: keyof typeof SAMPLE_SENDERS) => {
    const val = SAMPLE_SENDERS[key];
    setSenderInput(val);
    verifySender(val);
  };

  const isPhish = result?.classification === 'Phishing';
  const isSuspicious = result?.classification === 'Suspicious';
  const p = result?.parsed_structure || {};
  const h = result?.heuristic_flags || {};

  return (
    <div className="space-y-6">
      {/* Presets Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
        <div>
          <h2 className="text-sm font-bold text-slate-900">Sender Identity & Spoofing Inspector</h2>
          <p className="text-xs text-slate-500">
            Inspect sender email addresses for display name spoofing, typosquatting, disposable domains, and brand impersonation.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-500">Presets:</span>
          <button
            onClick={() => handleSelectSample('paypal_fake')}
            className="text-xs px-2.5 py-1 rounded-md bg-red-50 text-red-700 hover:bg-red-100 border border-red-200 font-medium transition cursor-pointer"
          >
            PayPal Fake
          </button>
          <button
            onClick={() => handleSelectSample('ceo_spoof')}
            className="text-xs px-2.5 py-1 rounded-md bg-amber-50 text-amber-800 hover:bg-amber-100 border border-amber-200 font-medium transition cursor-pointer"
          >
            CEO Spoof
          </button>
          <button
            onClick={() => handleSelectSample('google_legit')}
            className="text-xs px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 font-medium transition cursor-pointer"
          >
            Google Cloud
          </button>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Input */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
            <div className="space-y-1">
              <label htmlFor="senderInput" className="text-xs font-semibold text-slate-700">
                Sender Email / Header Display
              </label>
              <textarea
                id="senderInput"
                rows={4}
                value={senderInput}
                onChange={e => setSenderInput(e.target.value)}
                placeholder='e.g. "PayPal Support" <support@paypa1-update.xyz>'
                className="w-full bg-slate-50 border border-slate-200 focus:border-blue-500 focus:bg-white focus:ring-1 focus:ring-blue-500 rounded-lg p-3 text-xs text-slate-800 font-mono transition resize-none custom-scrollbar"
              />
              <p className="text-[11px] text-slate-400">
                Supports RFC format: <code>"Display Name" &lt;email@domain.com&gt;</code> or bare email address.
              </p>
            </div>

            <button
              id="btnScanSender"
              onClick={() => verifySender(senderInput)}
              disabled={loading || !senderInput.trim()}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm transition shadow-sm cursor-pointer disabled:opacity-60"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>Verifying Sender...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Verify Sender</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Output */}
        <div className="lg:col-span-7 space-y-4">
          {errorMsg && (
            <div role="alert" className="bg-red-50 border border-red-200 rounded-xl p-4 text-xs text-red-800">
              {errorMsg}
            </div>
          )}

          {!result && !loading && !errorMsg && (
            <div className="bg-white border border-slate-200 border-dashed rounded-xl p-12 text-center space-y-2">
              <div className="w-10 h-10 rounded-full bg-slate-100 text-slate-400 mx-auto flex items-center justify-center">
                <AtSign className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-slate-800">No Sender Inspected</h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Enter an email address on the left or select a preset to analyze spoofing and reputational flags.
              </p>
            </div>
          )}

          {loading && (
            <div className="bg-white border border-slate-200 rounded-xl p-12 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
              <p className="text-xs font-semibold text-slate-700">Verifying sender reputation and domain heuristics...</p>
            </div>
          )}

          {result && !loading && (
            <div className="space-y-4">
              {/* Verdict Banner */}
              <div
                className={`border rounded-xl p-4 shadow-sm flex items-center justify-between gap-4 ${
                  isPhish
                    ? 'border-red-200 bg-red-50/50'
                    : isSuspicious
                    ? 'border-amber-200 bg-amber-50/50'
                    : 'border-blue-200 bg-blue-50/50'
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
                      <CheckCircle2 className="w-6 h-6" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-base font-bold tracking-tight ${isPhish ? 'text-red-900' : isSuspicious ? 'text-amber-900' : 'text-blue-900'}`}>
                        {isPhish
                          ? 'SPOOFED SENDER ADDRESS'
                          : isSuspicious
                          ? 'SUSPICIOUS SENDER'
                          : 'VERIFIED SENDER'}
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
                        {isPhish ? 'FLAGGED' : isSuspicious ? 'CAUTION' : 'SAFE'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 font-mono truncate max-w-sm">
                      {result.sender_email}
                    </p>
                  </div>
                </div>

                <div className="text-right pr-2">
                  <span className="block text-[10px] text-slate-400 uppercase font-semibold">Threat Score</span>
                  <span className="text-xl font-bold text-slate-900">{Math.round(result.risk_score)}%</span>
                </div>
              </div>

              {/* Detected Signals */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                <span className="text-xs font-semibold text-slate-700 block">Detected Signals & Threat Triggers</span>
                <div className="space-y-1.5">
                  {(result.detected_signals && result.detected_signals.length > 0
                    ? result.detected_signals
                    : ['Standard sender characteristics.']
                  ).map((sig, idx) => (
                    <div
                      key={idx}
                      className={`p-2 rounded-lg border text-xs flex items-center gap-2 ${
                        isPhish
                          ? 'bg-red-50 border-red-200 text-red-800'
                          : isSuspicious
                          ? 'bg-amber-50 border-amber-200 text-amber-800'
                          : 'bg-blue-50 border-blue-200 text-blue-800'
                      }`}
                    >
                      {isPhish ? (
                        <AlertCircle className="w-3.5 h-3.5 shrink-0 text-red-600" />
                      ) : isSuspicious ? (
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-amber-600" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-blue-600" />
                      )}
                      <span>{sig}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Address Structure Breakdown */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                <span className="text-xs font-semibold text-slate-700 block">Address RFC Structure</span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                  <div className="p-2 bg-slate-50 rounded-lg border border-slate-200 flex justify-between">
                    <span className="text-slate-500">Display Name</span>
                    <span className="font-semibold text-slate-800 truncate max-w-[120px]">{p.displayName || 'None'}</span>
                  </div>
                  <div className="p-2 bg-slate-50 rounded-lg border border-slate-200 flex justify-between">
                    <span className="text-slate-500">Domain</span>
                    <span className="font-mono text-slate-800 font-medium truncate max-w-[120px]">{p.domain || '—'}</span>
                  </div>
                  <div className="p-2 bg-slate-50 rounded-lg border border-slate-200 flex justify-between">
                    <span className="text-slate-500">TLD</span>
                    <span className={`font-mono ${h.is_suspicious_tld ? 'text-red-600 font-bold' : 'text-slate-800'}`}>
                      .{p.tld || '—'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Heuristics Matrix */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                <span className="text-xs font-semibold text-slate-700 block">Heuristics Inspection Matrix</span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  <div
                    className={`p-2 rounded-lg border flex flex-col justify-between ${
                      h.brand_impersonation
                        ? 'bg-red-50 border-red-200 text-red-800 font-semibold'
                        : 'bg-slate-50 border-slate-200 text-slate-700'
                    }`}
                  >
                    <span className="text-[11px] text-slate-500">Brand Impersonation</span>
                    <span className="text-xs mt-0.5">{h.brand_impersonation ? 'Detected' : 'None'}</span>
                  </div>

                  <div
                    className={`p-2 rounded-lg border flex flex-col justify-between ${
                      h.homoglyph_or_typo
                        ? 'bg-red-50 border-red-200 text-red-800 font-semibold'
                        : 'bg-slate-50 border-slate-200 text-slate-700'
                    }`}
                  >
                    <span className="text-[11px] text-slate-500">Lookalike Domain</span>
                    <span className="text-xs mt-0.5">{h.homoglyph_or_typo ? 'Detected' : 'None'}</span>
                  </div>

                  <div
                    className={`p-2 rounded-lg border flex flex-col justify-between ${
                      h.is_suspicious_tld
                        ? 'bg-amber-50 border-amber-200 text-amber-800 font-semibold'
                        : 'bg-slate-50 border-slate-200 text-slate-700'
                    }`}
                  >
                    <span className="text-[11px] text-slate-500">TLD Risk</span>
                    <span className="text-xs mt-0.5">{h.is_suspicious_tld ? 'Suspicious' : 'Normal'}</span>
                  </div>

                  <div
                    className={`p-2 rounded-lg border flex flex-col justify-between ${
                      h.is_disposable_domain
                        ? 'bg-red-50 border-red-200 text-red-800 font-semibold'
                        : 'bg-slate-50 border-slate-200 text-slate-700'
                    }`}
                  >
                    <span className="text-[11px] text-slate-500">Mailbox Type</span>
                    <span className="text-xs mt-0.5">{h.is_disposable_domain ? 'Disposable' : 'Standard'}</span>
                  </div>
                </div>
              </div>

              {/* Security Reasoning */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-1">
                <span className="text-xs font-semibold text-slate-700 block">Security Analysis</span>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {result.reasoning || 'Sender evaluated.'}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
