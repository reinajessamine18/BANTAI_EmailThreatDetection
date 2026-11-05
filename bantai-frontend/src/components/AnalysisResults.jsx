import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock3,
  Cpu,
  FileText,
  Info,
  MessageSquare,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { useEffect, useState } from "react";
import {
  friendlyError,
  getPreferences,
  preferencesToUi,
  submitFeedback,
} from "../api/client";

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
  onBack,
}) {
  const [advancedMode, setAdvancedMode] = useState(null);
  const [preferencesError, setPreferencesError] = useState("");
  const [feedbackCorrect, setFeedbackCorrect] = useState(
    result?.feedback?.isPredictionCorrect ?? null
  );
  const [suggestedLabel, setSuggestedLabel] = useState(
    result?.feedback?.suggestedLabel || ""
  );
  const [explanationHelpful, setExplanationHelpful] = useState(
    result?.feedback?.explanationHelpful == null
      ? ""
      : result.feedback.explanationHelpful
        ? "yes"
        : "no"
  );
  const [feedbackComment, setFeedbackComment] = useState(
    result?.feedback?.comment || ""
  );
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(
    Boolean(result?.feedback)
  );
  const [feedbackSaving, setFeedbackSaving] = useState(false);
  const [feedbackError, setFeedbackError] = useState("");
  const [feedbackMessage, setFeedbackMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    getPreferences()
      .then((preferences) => {
        if (!cancelled) {
          setAdvancedMode(preferencesToUi(preferences).enableShapAdvancedMode);
          setPreferencesError("");
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setAdvancedMode(null);
          setPreferencesError(friendlyError(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [result?.scanId]);

  const handleSubmitFeedback = async () => {
    if (feedbackCorrect === null || !result?.scanId || feedbackSaving) return;
    setFeedbackSaving(true);
    setFeedbackError("");
    setFeedbackMessage("");
    try {
      await submitFeedback(result.scanId, {
        isPredictionCorrect: feedbackCorrect,
        suggestedLabel:
          feedbackCorrect === false ? suggestedLabel || undefined : undefined,
        explanationHelpful:
          explanationHelpful === "" ? undefined : explanationHelpful === "yes",
        comment: feedbackComment.trim() || undefined,
      });
      setFeedbackSubmitted(true);
      setFeedbackMessage("Thank you. Your feedback was saved.");
    } catch (err) {
      setFeedbackError(friendlyError(err));
    } finally {
      setFeedbackSaving(false);
    }
  };

  const isContentOnly =
    result?.pipeline === "content_only" ||
    Boolean(result?.modelVersion?.includes("candidate-v2")) ||
    result?.subject === "[Content-Only Scan]";

  const riskKey = result?.riskLevel?.toLowerCase();
  const risk = riskStyles[riskKey] || null;
  const score = Number.isFinite(result?.threatScore)
    ? Math.min(100, Math.max(0, result.threatScore))
    : null;
  const explanations = Array.isArray(result?.explanations)
    ? result.explanations
    : [];

  const phishingProb = Number.isFinite(result?.phishingProbability)
    ? result.phishingProbability
    : null;
  const safeProb = Number.isFinite(result?.safeProbability)
    ? result.safeProbability
    : phishingProb !== null
      ? Math.round((1.0 - phishingProb) * 10000) / 10000
      : null;

  const classification =
    result?.modelClassification ||
    (phishingProb !== null
      ? phishingProb >= 0.5
        ? "Phishing"
        : isContentOnly
          ? "Legitimate"
          : "Safe"
      : null);

  const isPhishingClass = classification === "Phishing";

  return (
    <section className="space-y-6" aria-labelledby="analysis-results-title">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-lime-400">
              Scan report
            </p>
            {isContentOnly && (
              <span className="rounded border border-lime-400/30 bg-lime-400/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-lime-400">
                Candidate V2 EXP-4 Content-Only NLP
              </span>
            )}
          </div>
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
          Back to Threat History
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

      {/* Primary Verdict & Metadata Grid */}
      <div className="grid gap-5 xl:grid-cols-[1.2fr_1.2fr_1fr]">
        {/* Card 1: Scan Metadata */}
        <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-zinc-500">
              <FileText size={15} className="text-lime-400" />
              Scan Metadata
            </div>

            <div className="mt-5 space-y-4">
              <div>
                <p className="text-xs text-zinc-500">Target Message</p>
                <p className="mt-1 truncate text-sm font-semibold text-white">
                  {result?.fileName || fileName || "Active Gmail Message"}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-zinc-500">Scan Timestamp</p>
                  <p className="mt-1 text-sm font-medium text-white">
                    {result?.scannedAt
                      ? new Date(result.scannedAt).toLocaleString()
                      : scannedAt
                        ? new Date(scannedAt).toLocaleString()
                        : "—"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-zinc-500">Inference Latency</p>
                  <p className="mt-1 text-sm font-semibold text-lime-400">
                    {Number.isFinite(result?.inferenceTimeMs)
                      ? `${result.inferenceTimeMs} ms`
                      : "—"}
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 border-t border-zinc-900 pt-4">
            <p className="text-[11px] text-zinc-500">Model Pipeline</p>
            <p className="mt-1 text-xs font-mono text-zinc-300">
              {result?.modelVersion || (isContentOnly ? "candidate-v2-exp4-unigram-25k" : "baseline-v1")}
            </p>
          </div>
        </div>

        {/* Card 2: Statistical Model Verdict (EXP-4) */}
        <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-zinc-500">
                <Cpu size={15} className="text-lime-400" />
                Statistical Model Verdict
              </div>
              <span className="text-[10px] uppercase font-bold text-zinc-500">
                Threshold: 0.50
              </span>
            </div>

            {/* Verdict Badge */}
            <div className="mt-5 flex items-center gap-3">
              <div
                className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border ${
                  isPhishingClass
                    ? "border-red-500/30 bg-red-500/10 text-red-400"
                    : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                }`}
              >
                {isPhishingClass ? <ShieldAlert size={26} /> : <ShieldCheck size={26} />}
              </div>
              <div>
                <span className="text-xs font-medium text-zinc-500">Predicted Class</span>
                <p
                  className={`text-xl font-black uppercase tracking-wide ${
                    isPhishingClass ? "text-red-400" : "text-emerald-400"
                  }`}
                >
                  {classification || "—"}
                </p>
              </div>
            </div>

            {/* Posterior Probabilities */}
            <div className="mt-5 grid grid-cols-2 gap-4 rounded-xl border border-zinc-900 bg-black/40 p-3">
              <div>
                <p className="text-[11px] text-zinc-500">P(Phishing | text)</p>
                <p
                  className={`mt-1 font-mono text-base font-bold ${
                    isPhishingClass ? "text-red-400" : "text-zinc-300"
                  }`}
                >
                  {phishingProb !== null ? `${(phishingProb * 100).toFixed(1)}%` : "—"}
                </p>
              </div>
              <div>
                <p className="text-[11px] text-zinc-500">P(Legitimate | text)</p>
                <p
                  className={`mt-1 font-mono text-base font-bold ${
                    !isPhishingClass && safeProb !== null ? "text-emerald-400" : "text-zinc-300"
                  }`}
                >
                  {safeProb !== null ? `${(safeProb * 100).toFixed(1)}%` : "—"}
                </p>
              </div>
            </div>
          </div>

          <div className="mt-4 border-t border-zinc-900 pt-3 flex items-center justify-between text-xs text-zinc-500">
            <span>Raw margin:</span>
            <span className="font-mono text-zinc-300">
              {Number.isFinite(result?.shap?.rawMargin)
                ? `${result.shap.rawMargin > 0 ? "+" : ""}${result.shap.rawMargin.toFixed(3)} log-odds`
                : "Computed via SHAP"}
            </span>
          </div>
        </div>

        {/* Card 3: Threat Severity Score (Heuristic) */}
        <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-zinc-500">
                Threat Severity
              </span>
              <span
                className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                  risk?.border || "border-zinc-700"
                } ${risk?.background || "bg-zinc-800"} ${risk?.color || "text-zinc-400"}`}
              >
                {result?.riskTier || risk?.label || "Tier"}
              </span>
            </div>

            <div className="mx-auto mt-2 max-w-sm">
              <svg
                viewBox="0 0 240 140"
                role="img"
                aria-label={
                  score === null
                    ? "Empty threat severity gauge"
                    : `Threat severity ${score} out of 100`
                }
                className="w-full"
              >
                <path
                  d="M 30 115 A 90 90 0 0 1 210 115"
                  fill="none"
                  stroke="#27272a"
                  strokeWidth="14"
                  strokeLinecap="butt"
                  pathLength="100"
                />
                {score !== null && (
                  <path
                    d="M 30 115 A 90 90 0 0 1 210 115"
                    fill="none"
                    stroke={
                      riskKey === "safe"
                        ? "#10b981"
                        : riskKey === "suspicious"
                          ? "#f59e0b"
                          : "#ef4444"
                    }
                    strokeWidth="8"
                    pathLength="100"
                    strokeDasharray={`${score} 100`}
                  />
                )}
                <text x="15" y="125" fill="#71717a" fontSize="10">
                  0
                </text>
                <text
                  x="120"
                  y="20"
                  fill="#71717a"
                  fontSize="10"
                  textAnchor="middle"
                >
                  50
                </text>
                <text
                  x="225"
                  y="125"
                  fill="#71717a"
                  fontSize="10"
                  textAnchor="end"
                >
                  100
                </text>
                <text
                  x="120"
                  y="95"
                  fill={
                    riskKey === "safe"
                      ? "#10b981"
                      : riskKey === "suspicious"
                        ? "#f59e0b"
                        : riskKey === "phishing"
                          ? "#ef4444"
                          : "#71717a"
                  }
                  fontSize="28"
                  fontWeight="800"
                  textAnchor="middle"
                >
                  {score ?? "—"}
                </text>
                <text
                  x="120"
                  y="112"
                  fill="#71717a"
                  fontSize="8"
                  fontWeight="600"
                  textAnchor="middle"
                  letterSpacing="1"
                >
                  HEURISTIC SCORE
                </text>
              </svg>
            </div>
          </div>

          <p className="mt-2 text-center text-[11px] leading-4 text-zinc-500">
            Uncalibrated application heuristic score S = round(p × 100) mapped to risk tier.
          </p>
        </div>
      </div>

      {/* Scope Notice for Content-Only Scans */}
      {isContentOnly && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950/40 px-4 py-3 text-xs text-zinc-400 flex items-center gap-3">
          <Info size={16} className="text-lime-400 shrink-0" />
          <span>
            <strong className="text-zinc-200">Content-Only Scope Note:</strong> This scan evaluates visible body prose exclusively. Transport headers (SPF, DKIM, DMARC) and external hyperlink destination metadata are omitted by design without making network lookups.
          </span>
        </div>
      )}

      {/* Parsed Details & SHAP Explanation Grid */}
      <div className="grid gap-5 xl:grid-cols-2">
        {/* Email Details */}
        <div className="min-h-64 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
          <h2 className="flex items-center gap-2 text-base font-bold text-white">
            <FileText size={17} className="text-lime-400" />
            Parsed email details
          </h2>
          <dl className="mt-5 space-y-4">
            <div>
              <dt className="text-xs font-bold uppercase tracking-wider text-zinc-600">
                Sender
              </dt>
              <dd className="mt-2 min-h-10 break-words rounded-lg border border-zinc-800 bg-black/50 px-3 py-2.5 text-sm text-zinc-400">
                {isContentOnly
                  ? "Excluded from content-only NLP analysis (visible prose only)"
                  : result?.sender || "Awaiting analysis service"}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-bold uppercase tracking-wider text-zinc-600">
                Subject
              </dt>
              <dd className="mt-2 min-h-10 break-words rounded-lg border border-zinc-800 bg-black/50 px-3 py-2.5 text-sm text-zinc-300">
                {result?.subject || (isContentOnly ? "[Content-Only Scan]" : "Awaiting analysis service")}
              </dd>
            </div>
          </dl>
          <div className="mt-5">
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-600">
              Email body
            </p>
            <div className="mt-2 max-h-80 min-h-24 overflow-y-auto whitespace-pre-wrap break-words rounded-lg border border-zinc-800 bg-black/50 p-3 text-sm leading-6 text-zinc-400">
              {result?.emailBody ??
                (result?.emailBodyStored === false
                  ? "The email text was processed transiently in memory and is never stored in the database or server logs."
                  : "No email text available.")}
            </div>
            <p className="mt-2 text-[11px] text-zinc-500">
              Zero-body privacy invariant: raw email body text is never persisted to SQLite, browser storage, or logs.
            </p>
          </div>
        </div>

        {/* SHAP Attributions */}
        <div className="min-h-64 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-base font-bold text-white">
                <Zap size={17} className="text-lime-400" />
                SHAP attribution & insights
              </h2>
              {result?.shap?.baseValue !== undefined && (
                <span className="text-xs font-mono text-zinc-500">
                  Base value: {result.shap.baseValue?.toFixed(3)} log-odds
                </span>
              )}
            </div>

            {result?.shap?.note && (
              <p className="mt-3 text-xs leading-5 text-zinc-400">
                {result.shap.note}
              </p>
            )}
            {preferencesError && (
              <p role="alert" className="mt-3 text-xs leading-5 text-amber-400">
                Could not load your SHAP display preference. Numeric values are
                hidden. {preferencesError}
              </p>
            )}

            {explanations.length === 0 ? (
              <p className="mt-5 flex min-h-36 items-center justify-center rounded-xl border border-zinc-800 bg-black/40 p-4 text-center text-sm leading-6 text-zinc-600">
                No feature attributions or educational insights available for this email.
              </p>
            ) : (
              <ul className="mt-5 space-y-3">
                {explanations.map((item, index) => {
                  const isTowardPhishing =
                    item.direction === "toward_phishing" || item.value > 0;
                  return (
                    <li
                      key={`${item.feature || item.title || "feature"}-${index}`}
                      className="rounded-xl border border-zinc-800 bg-black/40 p-3.5 transition hover:border-zinc-700"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-xs font-bold text-white">
                            {item.feature || item.title}
                          </span>
                          <span
                            className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                              isTowardPhishing
                                ? "border-red-500/30 bg-red-500/10 text-red-400"
                                : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                            }`}
                          >
                            {isTowardPhishing ? "Pushes toward Phishing" : "Pushes toward Legitimate"}
                          </span>
                        </div>
                        {advancedMode === true &&
                          item.kind !== "indicator" &&
                          Number.isFinite(item.value) && (
                            <span
                              className={`text-xs font-mono font-bold ${
                                isTowardPhishing ? "text-red-400" : "text-emerald-400"
                              }`}
                            >
                              {item.value > 0 ? "+" : ""}
                              {item.value.toFixed(3)} log-odds
                            </span>
                          )}
                      </div>
                      {item.insight && (
                        <p className="mt-2 text-xs leading-5 text-zinc-400">
                          {item.insight}
                        </p>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <div className="mt-4 border-t border-zinc-900 pt-3 text-[11px] text-zinc-500">
            TreeExplainer additivity: sum(SHAP contributions) + baseValue ≈ model log-odds margin.
          </div>
        </div>
      </div>

      {/* Feedback Section */}
      {result?.scanId != null && (
        <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
          <h2 className="flex items-center gap-2 text-base font-bold text-white">
            <MessageSquare size={17} className="text-lime-400" />
            Help improve this analysis
          </h2>
          {feedbackSubmitted ? (
            <p role="status" className="mt-4 text-sm text-lime-400 flex items-center gap-2">
              <CheckCircle2 size={16} />
              {feedbackMessage || "Feedback has already been submitted for this scan."}
            </p>
          ) : (
            <div className="mt-4 space-y-4">
              <fieldset>
                <legend className="text-sm text-zinc-300">
                  Was the prediction correct?
                </legend>
                <div className="mt-2 flex flex-wrap gap-3">
                  {[
                    { value: true, label: "Yes, it was correct" },
                    { value: false, label: "No, it was incorrect" },
                  ].map((option) => (
                    <button
                      key={String(option.value)}
                      type="button"
                      aria-pressed={feedbackCorrect === option.value}
                      onClick={() => setFeedbackCorrect(option.value)}
                      className={`rounded-lg border px-3 py-2 text-sm transition ${
                        feedbackCorrect === option.value
                          ? "border-lime-400 bg-lime-400/10 text-lime-300"
                          : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
                      }`}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              </fieldset>

              {feedbackCorrect === false && (
                <div>
                  <label
                    htmlFor="suggested-label"
                    className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500"
                  >
                    Suggested classification (optional)
                  </label>
                  <select
                    id="suggested-label"
                    value={suggestedLabel}
                    onChange={(event) => setSuggestedLabel(event.target.value)}
                    className="w-full rounded-lg border border-zinc-800 bg-black px-3 py-2.5 text-sm text-white outline-none focus:border-lime-400"
                  >
                    <option value="">Choose a classification</option>
                    <option value="safe">Legitimate / Safe</option>
                    <option value="suspicious">Suspicious</option>
                    <option value="phishing">Phishing</option>
                  </select>
                </div>
              )}

              <div>
                <label
                  htmlFor="explanation-helpful"
                  className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500"
                >
                  Was the explanation helpful? (optional)
                </label>
                <select
                  id="explanation-helpful"
                  value={explanationHelpful}
                  onChange={(event) => setExplanationHelpful(event.target.value)}
                  className="w-full rounded-lg border border-zinc-800 bg-black px-3 py-2.5 text-sm text-white outline-none focus:border-lime-400"
                >
                  <option value="">No response</option>
                  <option value="yes">Yes</option>
                  <option value="no">No</option>
                </select>
              </div>

              <div>
                <label
                  htmlFor="feedback-comment"
                  className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500"
                >
                  Comment (optional)
                </label>
                <textarea
                  id="feedback-comment"
                  value={feedbackComment}
                  onChange={(event) => setFeedbackComment(event.target.value)}
                  maxLength={1000}
                  rows={3}
                  className="w-full resize-y rounded-lg border border-zinc-800 bg-black px-3 py-2.5 text-sm text-white outline-none focus:border-lime-400"
                />
              </div>

              {feedbackError && (
                <p role="alert" className="text-sm text-red-400">
                  {feedbackError}
                </p>
              )}
              <button
                type="button"
                onClick={handleSubmitFeedback}
                disabled={feedbackCorrect === null || feedbackSaving}
                className="rounded-lg bg-lime-400 px-4 py-2.5 text-sm font-bold text-black transition hover:bg-lime-300 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {feedbackSaving ? "Submitting..." : "Submit feedback"}
              </button>
            </div>
          )}
        </section>
      )}

      {/* Footer */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-zinc-900 pt-4 text-xs text-zinc-600">
        <span className="inline-flex items-center gap-2">
          <Clock3 size={14} className="text-lime-400" />
          {result?.saved
            ? "This scan was saved to your account audit history."
            : "This scan was not saved (Auto-save Scan Logs is off)."}
        </span>
        <span>The email body is never stored in persistent storage.</span>
      </div>
    </section>
  );
}

export default AnalysisResults;
