import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import AnalysisResults from "./AnalysisResults";
import { friendlyError, getScan } from "../api/client";

// A past scan, opened from Threat History (route: /app/threat-history/:scanId).
// The email body is never stored, so `result.emailBody` is null here.
function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    getScan(scanId)
      .then((data) => {
        if (!cancelled) setResult(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.status === 404 ? "Scan not found." : friendlyError(err));
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  if (error) {
    return (
      <div className="space-y-4">
        <p role="alert" className="text-sm text-red-400">{error}</p>
        <button type="button" onClick={() => navigate("/app/threat-history")} className="text-sm text-lime-400">
          Back to Threat History
        </button>
      </div>
    );
  }
  if (!result) return <p className="text-sm text-zinc-500">Loading scan…</p>;

  return (
    <AnalysisResults
      result={result}
      fileName={result.fileName}
      scannedAt={result.scannedAt}
      isGuest={false}
      onBack={() => navigate("/app/threat-history")}
    />
  );
}

export default ScanDetail;
