import { useState } from "react";
import { useNavigate } from "react-router-dom";

import shieldIcon from "../assets/shield-scan.png";
import uploadIcon from "../assets/upload-icon.png";

function AnalyzeEmail() {
  const [inputMethod, setInputMethod] = useState("upload");
  const [scanCompleted, setScanCompleted] = useState(false);

  const navigate = useNavigate();

  const handleScan = () => {
    setScanCompleted(true);
  };

  return (
    <main className="min-h-screen bg-black px-8 py-10 text-white">

      <div className="mx-auto max-w-5xl">

        {/* HEADER */}
        <div className="mb-8">

          <h1 className="text-3xl font-bold tracking-tight">
            Analyze Email
          </h1>

          <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
            Upload an email file or paste its contents to scan for
            potential security threats.
          </p>

        </div>

        {/* EMAIL INPUT */}
        <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">

          <h2 className="text-lg font-semibold">
            Email Input
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Choose how you want to provide the email for analysis.
          </p>

          {/* SWITCH */}
          <div className="mt-6 flex w-full rounded-lg border border-zinc-800 bg-black p-1">

            <button
              type="button"
              onClick={() => setInputMethod("upload")}
              className={`flex-1 rounded-md px-5 py-2.5 text-sm font-semibold transition ${
                inputMethod === "upload"
                  ? "bg-lime-400 text-black"
                  : "text-zinc-500 hover:text-white"
              }`}
            >
              Upload File
            </button>

            <button
              type="button"
              onClick={() => setInputMethod("paste")}
              className={`flex-1 rounded-md px-5 py-2.5 text-sm font-semibold transition ${
                inputMethod === "paste"
                  ? "bg-lime-400 text-black"
                  : "text-zinc-500 hover:text-white"
              }`}
            >
              Paste Content
            </button>

          </div>

          {/* UPLOAD */}
          {inputMethod === "upload" && (
            <div className="mt-6">

              <div className="flex min-h-[260px] flex-col items-center justify-center rounded-xl border border-dashed border-zinc-700 bg-black/40 px-6 text-center transition hover:border-lime-400/60">

                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-zinc-700 bg-zinc-900">
                    <img src={uploadIcon} alt="Upload" className="h-7 w-7 object-contain" />
                </div>

                <h3 className="text-base font-semibold text-white">
                  Drop your email file here
                </h3>

                <p className="mt-2 text-sm text-zinc-500">
                  or select an .eml file from your computer
                </p>

                <button
                  type="button"
                  className="mt-5 rounded-lg border border-zinc-700 bg-zinc-900 px-6 py-3 text-sm font-semibold text-white transition hover:border-lime-400 hover:text-lime-400"
                >
                  Browse File
                </button>

              </div>

            </div>
          )}

          {/* PASTE */}
          {inputMethod === "paste" && (
            <div className="mt-6">

              <textarea
                placeholder="Paste the complete email content here..."
                rows={12}
                onInput={(e) => {
                  e.target.style.height = "auto";
                  e.target.style.height = `${e.target.scrollHeight}px`;
                }}
                className="w-full overflow-hidden rounded-xl border border-zinc-800 bg-black/60 px-4 py-4 text-sm leading-6 text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
              />

            </div>
          )}

          {/* SCAN BUTTON */}
          <div className="mt-6 flex justify-center">

            <button
              type="button"
              onClick={handleScan}
              className="flex w-full max-w-md items-center justify-center gap-3 rounded-lg bg-lime-400 px-7 py-3.5 text-sm font-bold tracking-wide text-black transition hover:bg-lime-300 hover:shadow-[0_0_25px_rgba(190,255,0,0.25)]"
            >

              <img
                src={shieldIcon}
                alt=""
                className="h-5 w-5 object-contain"
              />

              SCAN EMAIL

            </button>

          </div>

          {/* RESULT PLACEHOLDER */}
          {scanCompleted && (
            <div className="mt-8 rounded-xl border border-zinc-800 bg-black/50 p-6">

              <h2 className="text-lg font-semibold">
                Email Analysis Results
              </h2>

              <p className="mt-2 text-sm leading-6 text-zinc-500">
                Your XGBoost threat analysis results will appear here
                once the FastAPI backend is connected.
              </p>

            </div>
          )}

        </div>

        {/* PRIVACY */}
        <div className="mt-6 flex justify-center px-4 text-center">

          <p className="text-[11px] leading-5 text-zinc-600">
            Privacy enforced: Email payloads are parsed securely via
            FastAPI and are stored according to your account's
            threat-history settings.
          </p>

        </div>

      </div>

    </main>
  );
}

export default AnalyzeEmail;