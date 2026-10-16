import {
  AlertTriangle,
  ArrowLeft,
  Clock3,
  FileText,
  ShieldAlert,
  ShieldCheck,
  Zap,
  MessageSquare,
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
  isGuest,
  onBack,
}) {
  const [advancedMode, setAdvancedMode] = useState(isGuest ? true : null);
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
    if (isGuest) return undefined;
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
  }, [isGuest, result?.scanId]);

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
          /*changed */ {result?.emailBody ?? (result?.emailBodyStored === false ? "The email text is never stored, so it is not shown for past scans." : "No email text available.")}
            </div>
          </div>
        </div>

        <div className="min-h-64 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
          <h2 className="flex items-center gap-2 text-base font-bold text-white">
            <Zap size={17} className="text-lime-400" />
            SHAP attribution & insights
          </h2>

          {result?.shap?.note && (
            <p className="mt-3 text-sm leading-6 text-zinc-400">
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
                    {advancedMode === true &&
                      item.kind !== "indicator" &&
                      Number.isFinite(item.value) && (
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

      {!isGuest && result?.scanId != null && (
        <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
          <h2 className="flex items-center gap-2 text-base font-bold text-white">
            <MessageSquare size={17} className="text-lime-400" />
            Help improve this analysis
          </h2>
          {feedbackSubmitted ? (
            <p role="status" className="mt-4 text-sm text-lime-400">
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
                    <option value="safe">Safe</option>
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

      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-zinc-900 pt-4 text-xs text-zinc-600">
        <span className="inline-flex items-center gap-2">
          {isGuest ? (
            <ShieldCheck size={14} className="text-lime-400" />
          ) : (
            <Clock3 size={14} className="text-lime-400" />
          )}
          {isGuest
            ? "Guest scans are not saved to an account."
            : (result?.saved ? "This scan was saved to your account history." : "This scan was not saved (Auto-save Scan Logs is off).") }
        </span>
        <span>The email body is never stored.</span>
      </div>
    </section>
  );
}

export default AnalysisResults;


// import {
//   AlertTriangle,
//   ArrowLeft,
//   Clock3,
//   FileText,
//   ShieldAlert,
//   ShieldCheck,
//   Zap,
// } from "lucide-react";

// const riskStyles = {
//   safe: {
//     label: "Safe",
//     color: "text-emerald-400",
//     border: "border-emerald-400/30",
//     background: "bg-emerald-400/10",
//     icon: ShieldCheck,
//   },
//   suspicious: {
//     label: "Suspicious",
//     color: "text-amber-400",
//     border: "border-amber-400/30",
//     background: "bg-amber-400/10",
//     icon: AlertTriangle,
//   },
//   phishing: {
//     label: "Phishing",
//     color: "text-red-400",
//     border: "border-red-400/30",
//     background: "bg-red-400/10",
//     icon: ShieldAlert,
//   },
// };

// function AnalysisResults({
//   result,
//   fileName,
//   scannedAt,
//   isGuest,
//   onBack,
// }) {
//   const riskKey = result?.riskLevel?.toLowerCase();
//   const risk = riskStyles[riskKey] || null;
//   const score = Number.isFinite(result?.threatScore)
//     ? Math.min(100, Math.max(0, result.threatScore))
//     : null;
//   const explanations = Array.isArray(result?.explanations)
//     ? result.explanations
//     : [];

//   return (
//     <section className="space-y-6" aria-labelledby="analysis-results-title">
//       <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
//         <div>
//           <p className="text-xs font-bold uppercase tracking-[0.2em] text-lime-400">
//             Scan report
//           </p>
//           <h1
//             id="analysis-results-title"
//             className="mt-2 text-3xl font-black tracking-tight text-white"
//           >
//             Email Analysis Results
//           </h1>
//         </div>

//         <button
//           type="button"
//           onClick={onBack}
//           className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-2.5 text-sm font-semibold text-zinc-300 transition hover:border-lime-400/50 hover:text-lime-400"
//         >
//           <ArrowLeft size={16} />
//           Analyze another email
//         </button>
//       </div>

//       {!result && (
//         <div className="rounded-2xl border border-amber-400/20 bg-amber-400/5 p-6 sm:p-8">
//           <div className="flex items-start gap-4">
//             <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-amber-400/20 bg-amber-400/10 text-amber-400">
//               <AlertTriangle size={21} />
//             </div>
//             <div>
//               <h2 className="font-bold text-white">
//                 Analysis service not connected
//               </h2>
//               <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">
//                 These panels are ready to display scan details when the
//                 analysis service is connected. No score or result has been
//                 generated or saved.
//               </p>
//             </div>
//           </div>
//         </div>
//       )}

//       <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
//         <div className="min-h-44 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
//           <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-zinc-500">
//             <FileText size={15} className="text-lime-400" />
//             Scan metadata
//           </div>

//           <div className="mt-6 grid gap-5 sm:grid-cols-3">
//             <div className="min-w-0">
//               <p className="text-xs text-zinc-500">File</p>
//               <p className="mt-2 truncate text-sm font-semibold text-white">
//                 {result?.fileName || fileName || "—"}
//               </p>
//             </div>
//             <div className="min-w-0">
//               <p className="text-xs text-zinc-500">Scan timestamp</p>
//               <p className="mt-2 text-sm font-semibold text-white">
//                 {result?.scannedAt
//                   ? new Date(result.scannedAt).toLocaleString()
//                   : scannedAt
//                     ? new Date(scannedAt).toLocaleString()
//                     : "—"}
//               </p>
//             </div>
//             <div className="min-w-0">
//               <p className="text-xs text-zinc-500">Inference time</p>
//               <p className="mt-2 text-sm font-semibold text-lime-400">
//                 {Number.isFinite(result?.inferenceTimeMs)
//                   ? `${result.inferenceTimeMs} ms`
//                   : "—"}
//               </p>
//             </div>
//           </div>
//         </div>

//         <div className="min-h-44 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
//           <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">
//             Threat severity
//           </p>

//           <div className="mx-auto mt-2 max-w-sm">
//             <svg
//               viewBox="0 0 240 150"
//               role="img"
//               aria-label={
//                 score === null
//                   ? "Empty threat severity gauge"
//                   : `Threat severity ${score} out of 100`
//               }
//               className="w-full"
//             >
//               <path
//                 d="M 30 122 A 90 90 0 0 1 210 122"
//                 fill="none"
//                 stroke="#3f3f46"
//                 strokeWidth="14"
//                 strokeLinecap="butt"
//                 pathLength="100"
//               />
//               {score !== null && (
//                 <path
//                   d="M 30 122 A 90 90 0 0 1 210 122"
//                   fill="none"
//                   stroke={
//                     riskKey === "safe"
//                       ? "#10b981"
//                       : riskKey === "suspicious"
//                         ? "#f59e0b"
//                         : "#ef4444"
//                   }
//                   strokeWidth="7"
//                   pathLength="100"
//                   strokeDasharray={`${score} 100`}
//                 />
//               )}
//               <text x="15" y="132" fill="#a1a1aa" fontSize="10">
//                 0
//               </text>
//               <text
//                 x="120"
//                 y="25"
//                 fill="#a1a1aa"
//                 fontSize="10"
//                 textAnchor="middle"
//               >
//                 50
//               </text>
//               <text
//                 x="225"
//                 y="132"
//                 fill="#a1a1aa"
//                 fontSize="10"
//                 textAnchor="end"
//               >
//                 100
//               </text>
//               <text
//                 x="120"
//                 y="105"
//                 fill={
//                   riskKey === "safe"
//                     ? "#10b981"
//                     : riskKey === "suspicious"
//                       ? "#f59e0b"
//                       : riskKey === "phishing"
//                         ? "#ef4444"
//                         : "#71717a"
//                 }
//                 fontSize="26"
//                 fontWeight="700"
//                 textAnchor="middle"
//               >
//                 {score ?? "—"}
//               </text>
//               <text
//                 x="120"
//                 y="120"
//                 fill="#71717a"
//                 fontSize="9"
//                 textAnchor="middle"
//               >
//                 {risk?.label.toUpperCase() || "AWAITING ANALYSIS"}
//               </text>
//             </svg>
//           </div>
//         </div>
//       </div>

//       <div className="grid gap-5 xl:grid-cols-2">
//         <div className="min-h-64 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
//           <h2 className="flex items-center gap-2 text-base font-bold text-white">
//             <FileText size={17} className="text-lime-400" />
//             Parsed email details
//           </h2>
//           <dl className="mt-5 space-y-4">
//             {[
//               ["Sender", result?.sender],
//               ["Subject", result?.subject],
//             ].map(([label, value]) => (
//               <div key={label}>
//                 <dt className="text-xs font-bold uppercase tracking-wider text-zinc-600">
//                   {label}
//                 </dt>
//                 <dd className="mt-2 min-h-10 break-words rounded-lg border border-zinc-800 bg-black/50 px-3 py-2.5 text-sm text-zinc-500">
//                   {value || "Awaiting analysis service"}
//                 </dd>
//               </div>
//             ))}
//           </dl>
//           <div className="mt-5">
//             <p className="text-xs font-bold uppercase tracking-wider text-zinc-600">
//               Email body
//             </p>
//             <div className="mt-2 max-h-80 min-h-24 overflow-y-auto whitespace-pre-wrap break-words rounded-lg border border-zinc-800 bg-black/50 p-3 text-sm leading-6 text-zinc-400">
//           /*changed */ {result?.emailBody ?? (result?.emailBodyStored === false ? "The email text is never stored, so it is not shown for past scans." : "No email text available.")}
//             </div>
//           </div>
//         </div>

//         <div className="min-h-64 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
//           <h2 className="flex items-center gap-2 text-base font-bold text-white">
//             <Zap size={17} className="text-lime-400" />
//             SHAP attribution & insights
//           </h2>

//           {explanations.length === 0 ? (
//             <p className="mt-5 flex min-h-36 items-center justify-center rounded-xl border border-zinc-800 bg-black/40 p-4 text-center text-sm leading-6 text-zinc-600">
//               No feature attributions or educational insights available.
//             </p>
//             ) : (
//             <ul className="mt-5 space-y-4">
//               {explanations.map((item, index) => (
//                 <li
//                   key={`${item.feature || item.title || "feature"}-${index}`}
//                   className="rounded-xl border border-zinc-800 bg-black/40 p-4"
//                 >
//                   <div className="flex flex-wrap items-center justify-between gap-2">
//                     <h3 className="text-sm font-bold text-white">
//                       {item.title || item.feature || "Feature attribution"}
//                     </h3>
//                     {Number.isFinite(item.value) && (
//                       <span className="text-xs font-mono text-lime-400">
//                         {item.value > 0 ? "+" : ""}
//                         {item.value.toFixed(3)}
//                       </span>
//                     )}
//                   </div>
//                   {item.insight && (
//                     <p className="mt-2 text-sm leading-6 text-zinc-400">
//                       {item.insight}
//                     </p>
//                   )}
//                 </li>
//               ))}
//             </ul>
//           )}
//         </div>
//       </div>

//       <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-zinc-900 pt-4 text-xs text-zinc-600">
//         <span className="inline-flex items-center gap-2">
//           {isGuest ? (
//             <ShieldCheck size={14} className="text-lime-400" />
//           ) : (
//             <Clock3 size={14} className="text-lime-400" />
//           )}
//           {isGuest
//             ? "Guest scans are not saved to an account."
//             : {result?.saved ? "This scan was saved to your account history." : "This scan was not saved (Auto-save Scan Logs is off)."} (drop the surrounding quotes, it is now an expression)}
//         </span>
//         <span>The email body is never stored.</span>
//       </div>
//     </section>
//   );
// }

// export default AnalysisResults;
