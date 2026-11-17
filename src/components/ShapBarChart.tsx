import React from 'react';

interface ShapBarChartProps {
  features?: Record<string, number> | null;
  emptyMessage?: string;
}

export const ShapBarChart: React.FC<ShapBarChartProps> = ({
  features,
  emptyMessage = 'No distinct weights computed.'
}) => {
  if (!features || Object.keys(features).length === 0) {
    return (
      <div className="flex items-center justify-center h-36 text-xs text-slate-400">
        {emptyMessage}
      </div>
    );
  }

  const entries = Object.entries(features);
  const maxAbsValue = Math.max(...entries.map(([, v]) => Math.abs(Number(v))), 0.01);

  return (
    <div className="space-y-2 py-1">
      <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1 border-b border-slate-100 pb-1.5">
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-blue-500 inline-block"></span>
          <span>Protective (Reduces Threat)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-red-500 inline-block"></span>
          <span>Malicious Signal (Increases Threat)</span>
        </span>
      </div>

      <div className="space-y-2">
        {entries.map(([featureName, rawVal]) => {
          const val = Number(rawVal);
          const isThreat = val > 0;
          const displayLabel = featureName.replace(/_/g, ' ');
          const pct = Math.min(100, Math.max(8, (Math.abs(val) / maxAbsValue) * 100));

          return (
            <div key={featureName} className="text-xs group">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-slate-700 font-medium truncate max-w-[280px]" title={displayLabel}>
                  {displayLabel}
                </span>
                <span className={`font-mono text-[11px] font-semibold ${isThreat ? 'text-red-600' : 'text-blue-600'}`}>
                  {isThreat ? `+${val.toFixed(3)}` : val.toFixed(3)}
                </span>
              </div>
              <div className="w-full bg-slate-100 h-2.5 rounded-full overflow-hidden flex">
                {isThreat ? (
                  <div
                    className="bg-red-500 h-full rounded-full transition-all duration-300 group-hover:bg-red-600"
                    style={{ width: `${pct}%` }}
                  />
                ) : (
                  <div
                    className="bg-blue-500 h-full rounded-full transition-all duration-300 group-hover:bg-blue-600"
                    style={{ width: `${pct}%` }}
                  />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
