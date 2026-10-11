import {
  AlertTriangle,
  ArrowLeft,
  Clock3,
  FileText,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";

const riskStyles = {
  safe: {
    label: "Safe",
    color: "text-emerald-400",
    border: "border-emerald-400/30",
    background: "bg-emerald-400/10",
    icon: ShieldCheck,
  },
  suspicious: {
    label: "Suspicious",
    color: "text-amber-400",
    border: "border-amber-400/30",
    background: "bg-amber-400/10",
    icon: AlertTriangle,
  },
  phishing: {
    label: "Phishing",
    color: "text-red-400",
    border: "border-red-400/30",
    background: "bg-red-400/10",
    icon: ShieldAlert,
  },
};

function AnalysisResults({
  result,
  fileName,
  scannedAt,
  isGuest,
  onBack,
}) {
  const riskKey = result?.riskLevel?.toLowerCase();
  const risk = riskStyles[riskKey] || null;
  const score = Number.isFinite(result?.threatScore)
    ? Math.min(100, Math.max(0, result.threatScore))
    : null;
  const explanations = Array.isArray(result?.explanations)
    ? result.explanations
    : [];

  return (
    <section className="space-y-6" aria-labelledby="analysis-results-title">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-bold uppercase tracking-[0.2em] text-lime-400">
            Scan report
          </p>
          <h1
            id="analysis-results-title"
            className="mt-2 text-3xl font-black tracking-tight text-white"
          >
            Email Analysis Results
          </h1>
        </div>

        <button
          type="button"
          onClick={onBack}
          className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-2.5 text-sm font-semibold text-zinc-300 transition hover:border-lime-400/50 hover:text-lime-400"
        >
          <ArrowLeft size={16} />
          Analyze another email
        </button>
      </div>

      {!result && (
        <div className="rounded-2xl border border-amber-400/20 bg-amber-400/5 p-6 sm:p-8">
          <div className="flex items-start gap-4">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-amber-400/20 bg-amber-400/10 text-amber-400">
              <AlertTriangle size={21} />
            </div>
            <div>
              <h2 className="font-bold text-white">
                Analysis service not connected
              </h2>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">
                These panels are ready to display scan details when the
                analysis service is connected. No score or result has been
                generated or saved.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
        <div className="min-h-44 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-zinc-500">
            <FileText size={15} className="text-lime-400" />
            Scan metadata
          </div>

          <div className="mt-6 grid gap-5 sm:grid-cols-3">
            <div className="min-w-0">
              <p className="text-xs text-zinc-500">File</p>
              <p className="mt-2 truncate text-sm font-semibold text-white">
                {result?.fileName || fileName || "—"}
              </p>
            </div>
            <div className="min-w-0">
              <p className="text-xs text-zinc-500">Scan timestamp</p>
              <p className="mt-2 text-sm font-semibold text-white">
                {result?.scannedAt
                  ? new Date(result.scannedAt).toLocaleString()
                  : scannedAt
                    ? new Date(scannedAt).toLocaleString()
                    : "—"}
              </p>
            </div>
            <div className="min-w-0">
              <p className="text-xs text-zinc-500">Inference time</p>
              <p className="mt-2 text-sm font-semibold text-lime-400">
                {Number.isFinite(result?.inferenceTimeMs)
                  ? `${result.inferenceTimeMs} ms`
                  : "—"}
              </p>
            </div>
          </div>
        </div>

        <div className="min-h-44 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
          <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">
            Threat severity
          </p>

          <div className="mx-auto mt-2 max-w-sm">
            <svg
              viewBox="0 0 240 150"
              role="img"
              aria-label={
                score === null
                  ? "Empty threat severity gauge"
                  : `Threat severity ${score} out of 100`
              }
              className="w-full"
            >
              <path
                d="M 30 122 A 90 90 0 0 1 210 122"
                fill="none"
                stroke="#3f3f46"
                strokeWidth="14"
                strokeLinecap="butt"
                pathLength="100"
              />
              {score !== null && (
                <path
                  d="M 30 122 A 90 90 0 0 1 210 122"
                  fill="none"
                  stroke={
                    riskKey === "safe"
                      ? "#10b981"
                      : riskKey === "suspicious"
                        ? "#f59e0b"
                        : "#ef4444"
                  }
                  strokeWidth="7"
                  pathLength="100"
                  strokeDasharray={`${score} 100`}
                />
              )}
              <text x="15" y="132" fill="#a1a1aa" fontSize="10">
                0
              </text>
              <text
                x="120"
                y="25"
                fill="#a1a1aa"
                fontSize="10"
                textAnchor="middle"
              >
                50
              </text>
              <text
                x="225"
                y="132"
                fill="#a1a1aa"
                fontSize="10"
                textAnchor="end"
              >
                100
              </text>
              <text
                x="120"
                y="105"
                fill={
                  riskKey === "safe"
                    ? "#10b981"
                    : riskKey === "suspicious"
                      ? "#f59e0b"
                      : riskKey === "phishing"
                        ? "#ef4444"
                        : "#71717a"
                }
                fontSize="26"
                fontWeight="700"
                textAnchor="middle"
              >
                {score ?? "—"}
              </text>
              <text
                x="120"
                y="120"
                fill="#71717a"
                fontSize="9"
                textAnchor="middle"
              >
                {risk?.label.toUpperCase() || "AWAITING ANALYSIS"}
              </text>
            </svg>
          </div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <div className="min-h-64 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
          <h2 className="flex items-center gap-2 text-base font-bold text-white">
            <FileText size={17} className="text-lime-400" />
            Parsed email details
          </h2>
          <dl className="mt-5 space-y-4">
            {[
              ["Sender", result?.sender],
              ["Subject", result?.subject],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs font-bold uppercase tracking-wider text-zinc-600">
                  {label}
                </dt>
                <dd className="mt-2 min-h-10 break-words rounded-lg border border-zinc-800 bg-black/50 px-3 py-2.5 text-sm text-zinc-500">
                  {value || "Awaiting analysis service"}
                </dd>
              </div>
            ))}
          </dl>
          <div className="mt-5">
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-600">
              Email body
            </p>
            <div className="mt-2 max-h-80 min-h-24 overflow-y-auto whitespace-pre-wrap break-words rounded-lg border border-zinc-800 bg-black/50 p-3 text-sm leading-6 text-zinc-400">
              {result?.emailBody || "Awaiting analysis service"}
            </div>
          </div>
        </div>

        <div className="min-h-64 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
          <h2 className="flex items-center gap-2 text-base font-bold text-white">
            <Zap size={17} className="text-lime-400" />
            SHAP attribution & insights
          </h2>

          {explanations.length === 0 ? (
            <p className="mt-5 flex min-h-36 items-center justify-center rounded-xl border border-zinc-800 bg-black/40 p-4 text-center text-sm leading-6 text-zinc-600">
              No feature attributions or educational insights available.
            </p>
          ) : (
            <ul className="mt-5 space-y-4">
              {explanations.map((item, index) => (
                <li
                  key={`${item.feature || item.title || "feature"}-${index}`}
                  className="rounded-xl border border-zinc-800 bg-black/40 p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-bold text-white">
                      {item.title || item.feature || "Feature attribution"}
                    </h3>
                    {Number.isFinite(item.value) && (
                      <span className="text-xs font-mono text-lime-400">
                        {item.value > 0 ? "+" : ""}
                        {item.value.toFixed(3)}
                      </span>
                    )}
                  </div>
                  {item.insight && (
                    <p className="mt-2 text-sm leading-6 text-zinc-400">
                      {item.insight}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-zinc-900 pt-4 text-xs text-zinc-600">
        <span className="inline-flex items-center gap-2">
          {isGuest ? (
            <ShieldCheck size={14} className="text-lime-400" />
          ) : (
            <Clock3 size={14} className="text-lime-400" />
          )}
          {isGuest
            ? "Guest scans are not saved to an account."
            : "Account scan history requires the backend to be connected."}
        </span>
        <span>Email content is not stored by this results screen.</span>
      </div>
    </section>
  );
}

export default AnalysisResults;
