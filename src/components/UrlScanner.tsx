import React, { useState } from 'react';
import {
  Link2,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Search
} from 'lucide-react';
import { UrlAnalysisResult, AiThreatAnalysis } from '../types';
import { ShapBarChart } from './ShapBarChart';
import { AiThreatAnalysisSection } from './AiThreatAnalysisSection';

interface UrlScannerProps {
  onAnalysisComplete?: (result: UrlAnalysisResult) => void;
}

const SAMPLE_URLS = [
  { label: 'PayPal Scam', url: 'http://verify-paypal-user.security-update.xyz/login' },
  { label: 'Direct IP Host', url: 'http://194.26.29.11/secure-update/login.php' },
  { label: 'Clean Enterprise', url: 'https://console.cloud.google.com/billing' }
];

export const UrlScanner: React.FC<UrlScannerProps> = ({ onAnalysisComplete }) => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AiThreatAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const runAiAnalysis = async (targetUrl: string) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const res = await fetch('/api/ai-threat-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'url',
          content: trimmed,
          url: trimmed
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

  const scanUrl = async (targetUrl: string) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) return;

    setLoading(true);
    setErrorMsg(null);

    // Concurrently trigger independent Agentic AI Threat Analysis
    runAiAnalysis(trimmed);

    try {
      const res = await fetch('/predict_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed })
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || 'URL analysis failed');
      }

      setResult({ ...data, url: trimmed });
      if (onAnalysisComplete) onAnalysisComplete({ ...data, url: trimmed });
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to scan target URL');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectSample = (url: string) => {
    setUrlInput(url);
    scanUrl(url);
  };

  const isPhish = result?.classification === 'Phishing';
  const isSuspicious = result?.classification === 'Suspicious';

  return (
    <div className="space-y-6">
      {/* Presets Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
        <div>
          <h2 className="text-sm font-bold text-slate-900">Website & URL Scanner</h2>
          <p className="text-xs text-slate-500">
            Scan web addresses for credential harvesting paths, obfuscated IP hosts, suspicious TLDs, and typosquatting.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-500">Presets:</span>
          {SAMPLE_URLS.map(s => (
            <button
              key={s.label}
              onClick={() => handleSelectSample(s.url)}
              className="text-xs px-2.5 py-1 rounded-md bg-slate-100 text-slate-700 hover:bg-slate-200 border border-slate-200 font-medium transition cursor-pointer"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Input */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
            <div className="space-y-1">
              <label htmlFor="urlInput" className="text-xs font-semibold text-slate-700">
                Destination URL / Link
              </label>
              <input
                id="urlInput"
                type="text"
                value={urlInput}
                onChange={e => setUrlInput(e.target.value)}
                placeholder="e.g. http://verify-paypal-user.security-update.xyz/login"
                className="w-full bg-slate-50 border border-slate-200 focus:border-blue-500 focus:bg-white focus:ring-1 focus:ring-blue-500 rounded-lg px-3 py-2 text-xs text-slate-800 font-mono transition"
              />
            </div>

            <button
              id="btnScanUrl"
              onClick={() => scanUrl(urlInput)}
              disabled={loading || !urlInput.trim()}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm transition shadow-sm cursor-pointer disabled:opacity-60"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>Scanning Website...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Scan Website</span>
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
                <Link2 className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-slate-800">No URL Scanned</h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Paste a destination link on the left or select a sample above to run real-time threat diagnostics.
              </p>
            </div>
          )}

          {loading && (
            <div className="bg-white border border-slate-200 rounded-xl p-12 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
              <p className="text-xs font-semibold text-slate-700">Evaluating domain reputation & link structure...</p>
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
                          ? 'PHISHING WEBSITE DETECTED'
                          : isSuspicious
                          ? 'SUSPICIOUS WEBSITE'
                          : 'SAFE WEBSITE'}
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
                      {result.url}
                    </p>
                  </div>
                </div>

                <div className="text-right pr-2">
                  <span className="block text-[10px] text-slate-400 uppercase font-semibold">Threat Score</span>
                  <span className="text-xl font-bold text-slate-900">{Math.round(result.risk_score)}%</span>
                </div>
              </div>

              {/* Diagnostics Grid */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                <span className="text-xs font-semibold text-slate-700 block">Threat Diagnostics Summary</span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200 flex justify-between">
                    <span className="text-slate-500">Classification</span>
                    <span className={`font-semibold ${isPhish ? 'text-red-600' : isSuspicious ? 'text-amber-700' : 'text-blue-600'}`}>
                      {result.classification}
                    </span>
                  </div>
                  <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200 flex justify-between">
                    <span className="text-slate-500">Security Note</span>
                    <span className="text-slate-800 truncate max-w-[160px]">{result.reasoning || 'Checked.'}</span>
                  </div>
                  <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200 flex justify-between">
                    <span className="text-slate-500">ML Model Probability</span>
                    <span className="font-semibold text-slate-800">
                      {typeof result.ml_probability === 'number' ? `${Math.round(result.ml_probability * 100)}%` : 'Unavailable'}
                    </span>
                  </div>
                  <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200 flex justify-between">
                    <span className="text-slate-500">Model Version</span>
                    <span className="font-mono text-xs text-slate-800">{result.model_version || 'Production v1.0'}</span>
                  </div>
                </div>
              </div>

              {/* SEPARATE AGENTIC AI ADVANCED THREAT ANALYSIS SECTION */}
              <AiThreatAnalysisSection
                analysis={aiAnalysis}
                loading={aiLoading}
                error={aiError}
                onRefresh={() => runAiAnalysis(urlInput || result.url)}
              />

              {/* SHAP Feature Contribution Chart */}
              <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-2">
                <span className="text-xs font-semibold text-slate-700 block">Top URL Threat Features & SHAP Weights</span>
                <ShapBarChart features={result.top_url_features} emptyMessage="No URL feature weights computed." />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
