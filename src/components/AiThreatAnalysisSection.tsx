import React from 'react';
import {
  Sparkles,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Target,
  Brain,
  Layers,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Info
} from 'lucide-react';
import { AiThreatAnalysis } from '../types';

interface AiThreatAnalysisSectionProps {
  analysis: AiThreatAnalysis | null;
  loading: boolean;
  error?: string | null;
  onRefresh?: () => void;
}

export const AiThreatAnalysisSection: React.FC<AiThreatAnalysisSectionProps> = ({
  analysis,
  loading,
  error,
  onRefresh
}) => {
  if (loading) {
    return (
      <div className="bg-gradient-to-br from-indigo-50/70 via-purple-50/40 to-white border border-indigo-200 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-indigo-600 text-white flex items-center justify-center shadow-xs">
              <Sparkles className="w-4 h-4 animate-pulse" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <span>AI Advanced Threat Analysis</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold bg-indigo-100 text-indigo-700">
                  Agentic AI
                </span>
              </h3>
              <p className="text-[11px] text-slate-500">Autonomous reasoning independent of ML feature extraction</p>
            </div>
          </div>
        </div>

        <div className="p-8 text-center space-y-3">
          <div className="w-8 h-8 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <p className="text-xs font-semibold text-slate-700">
            Agentic AI investigating social engineering tactics, attack intent & contextual deception...
          </p>
          <p className="text-[11px] text-slate-400 max-w-sm mx-auto">
            Directly synthesizing cognitive pressure levers and psychological framing.
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-4 shadow-sm text-xs text-red-800 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-semibold">
            <AlertCircle className="w-4 h-4 text-red-600" />
            <span>AI Advanced Threat Analysis Encountered an Issue</span>
          </div>
          {onRefresh && (
            <button
              onClick={onRefresh}
              className="text-[11px] text-red-700 hover:text-red-900 underline flex items-center gap-1 cursor-pointer"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Retry</span>
            </button>
          )}
        </div>
        <p>{error}</p>
      </div>
    );
  }

  if (!analysis) {
    return null;
  }

  const isMalicious = analysis.threat_level === 'MALICIOUS';
  const isSuspicious = analysis.threat_level === 'SUSPICIOUS';

  return (
    <div className="bg-gradient-to-br from-indigo-50/60 via-white to-purple-50/40 border border-indigo-200 rounded-xl p-5 shadow-sm space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-indigo-100/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-indigo-600 to-purple-600 text-white flex items-center justify-center shadow-xs">
            <Sparkles className="w-4.5 h-4.5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-900 tracking-tight">AI Advanced Threat Analysis</h3>
              <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold bg-indigo-100 text-indigo-800 border border-indigo-200">
                Agentic Engine
              </span>
            </div>
            <p className="text-[11px] text-slate-500">
              Evaluated directly by cognitive AI agent independently of statistical ML models
            </p>
          </div>
        </div>

        {onRefresh && (
          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-semibold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 rounded-lg transition self-start sm:self-auto cursor-pointer"
            title="Re-run Agentic AI Investigation"
          >
            <RefreshCw className="w-3 h-3" />
            <span>Re-evaluate</span>
          </button>
        )}
      </div>

      {/* Threat Assessment Summary Banner */}
      <div
        className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-2xs ${
          isMalicious
            ? 'bg-red-50/80 border-red-200 text-red-950'
            : isSuspicious
            ? 'bg-amber-50/80 border-amber-200 text-amber-950'
            : 'bg-emerald-50/80 border-emerald-200 text-emerald-950'
        }`}
      >
        <div className="flex items-start gap-3">
          <div
            className={`w-10 h-10 rounded-lg flex items-center justify-center text-white shrink-0 mt-0.5 ${
              isMalicious ? 'bg-red-600' : isSuspicious ? 'bg-amber-500' : 'bg-emerald-600'
            }`}
          >
            {isMalicious ? (
              <ShieldAlert className="w-5 h-5" />
            ) : isSuspicious ? (
              <AlertTriangle className="w-5 h-5" />
            ) : (
              <ShieldCheck className="w-5 h-5" />
            )}
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider">
                Threat Assessment: {analysis.threat_level}
              </span>
              <span
                className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase border ${
                  isMalicious
                    ? 'bg-red-100 text-red-800 border-red-200'
                    : isSuspicious
                    ? 'bg-amber-100 text-amber-800 border-amber-200'
                    : 'bg-emerald-100 text-emerald-800 border-emerald-200'
                }`}
              >
                {analysis.confidence} Confidence
              </span>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed font-medium">
              {analysis.summary}
            </p>
          </div>
        </div>

        <div className="text-left sm:text-right shrink-0 border-t sm:border-t-0 pt-2 sm:pt-0 border-black/5">
          <span className="block text-[10px] text-slate-500 uppercase font-semibold">AI Threat Score</span>
          <span className="text-xl font-bold text-slate-900">{analysis.threat_score}/100</span>
        </div>
      </div>

      {/* Attack Intent Section */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs space-y-2">
        <div className="flex items-center gap-1.5 text-xs font-bold text-slate-900">
          <Target className="w-4 h-4 text-indigo-600" />
          <span>Attack Intent & Adversarial Objective</span>
        </div>
        <div className="p-3 bg-indigo-50/50 border border-indigo-100 rounded-lg flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-600"></span>
            <span className="text-xs font-semibold text-slate-900">{analysis.attack_intent}</span>
          </div>
          <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-white text-indigo-700 border border-indigo-200 shrink-0">
            Detected Intent
          </span>
        </div>
      </div>

      {/* Social Engineering Tactics Breakdown */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs font-bold text-slate-900">
            <Layers className="w-4 h-4 text-purple-600" />
            <span>Social Engineering Tactics & Psychological Levers</span>
          </div>
          <span className="text-[11px] text-slate-400">
            {analysis.social_engineering_tactics?.length || 0} tactic{analysis.social_engineering_tactics?.length === 1 ? '' : 's'} identified
          </span>
        </div>

        {(!analysis.social_engineering_tactics || analysis.social_engineering_tactics.length === 0) ? (
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>No deceptive social engineering, urgency coercion, or authority manipulation detected.</span>
          </div>
        ) : (
          <div className="space-y-2">
            {analysis.social_engineering_tactics.map((tactic, idx) => {
              const isHigh = tactic.severity === 'High';
              const isMed = tactic.severity === 'Medium';
              const badgeStyle = isHigh
                ? 'bg-red-100 text-red-800 border-red-200'
                : isMed
                ? 'bg-amber-100 text-amber-800 border-amber-200'
                : 'bg-blue-100 text-blue-800 border-blue-200';

              return (
                <div
                  key={idx}
                  className="p-3 bg-slate-50/80 border border-slate-200 rounded-lg text-xs space-y-1 hover:border-slate-300 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-900 flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-purple-600"></span>
                      {tactic.tactic}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase border shrink-0 ${badgeStyle}`}>
                      {tactic.severity} Severity
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-600 leading-relaxed pl-3">
                    {tactic.explanation}
                  </p>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Contextual Reasoning Section */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs space-y-2">
        <div className="flex items-center gap-1.5 text-xs font-bold text-slate-900">
          <Brain className="w-4 h-4 text-indigo-600" />
          <span>Contextual Reasoning & Forensic Investigation</span>
        </div>
        <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 leading-relaxed font-sans whitespace-pre-line">
          {analysis.contextual_reasoning}
        </div>
      </div>

      {/* Key Indicators & Recommended Mitigation Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Key Indicators */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs space-y-2">
          <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-indigo-600" />
            <span>Key Agentic Indicators</span>
          </span>
          <div className="space-y-1.5">
            {(analysis.key_indicators || []).map((indicator, idx) => (
              <div key={idx} className="flex items-start gap-1.5 text-[11px] text-slate-700">
                <span className="text-indigo-500 font-bold mt-0.5">&bull;</span>
                <span>{indicator}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recommended Mitigation */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs space-y-2">
          <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
            <span>Recommended Mitigation</span>
          </span>
          <div className="space-y-1.5">
            {(analysis.recommended_mitigation || []).map((action, idx) => (
              <div key={idx} className="flex items-start gap-1.5 text-[11px] text-slate-700">
                <span className="text-emerald-600 font-bold mt-0.5">&bull;</span>
                <span>{action}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
