import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import logo from "../assets/BANTAI-logo.png";
import shieldIcon from "../assets/shield-scan.png";
import uploadIcon from "../assets/upload-icon.png";

const MAX_FREE_SCANS = 3;
const STORAGE_KEY = "bantaiGuestScanCount";

function GuestAnalyzeEmail() {
  const [inputMethod, setInputMethod] = useState("upload");
  const [scanCount, setScanCount] = useState(0);
  const [scanCompleted, setScanCompleted] = useState(false);

  useEffect(() => {
    const savedCount = Number(
      sessionStorage.getItem(STORAGE_KEY) || "0"
    );

    setScanCount(savedCount);
  }, []);

  const limitReached = scanCount >= MAX_FREE_SCANS;

  const handleScan = () => {
    if (limitReached) {
      return;
    }

    const nextCount = scanCount + 1;

    sessionStorage.setItem(
      STORAGE_KEY,
      String(nextCount)
    );

    setScanCount(nextCount);
    setScanCompleted(true);
  };

  return (
    <main className="min-h-screen bg-black text-white">

      {/* TOP BAR */}
      <header className="border-b border-zinc-800 bg-zinc-950">
        <div className="mx-auto flex h-20 max-w-7xl items-center px-6 lg:px-10">
            <Link to="/" className="flex items-center">
            
            <span className="text-2xl font-black italic tracking-tight text-white">
                BANTAI<span className="text-lime-400">.</span>
            </span>
            </Link>
        </div>
        </header>

      <div className="px-6 py-10">

        <div className="mx-auto max-w-5xl">

          {/* LIMIT REACHED */}
          {limitReached ? (
            <div className="flex min-h-[650px] items-center justify-center">

              <div className="w-full max-w-xl rounded-2xl border border-zinc-800 bg-zinc-950 p-8 text-center shadow-2xl sm:p-12">

                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-lime-400/30 bg-lime-400/10">

                  <span className="text-2xl text-lime-400">
                    ✓
                  </span>

                </div>

                <p className="mt-6 text-xs font-bold uppercase tracking-[0.25em] text-lime-400">
                  Free Scan Limit Reached
                </p>

                <h1 className="mt-3 text-3xl font-bold tracking-tight text-white">
                  You've used all 3 free scans.
                </h1>

                <p className="mx-auto mt-4 max-w-md text-sm leading-6 text-zinc-400">
                  Log in to continue analyzing emails and access
                  your saved threat history through the BANTAI platform.
                </p>

                <Link
                  to="/login"
                  className="mt-8 inline-flex w-full items-center justify-center rounded-lg bg-lime-400 px-7 py-3.5 text-sm font-bold tracking-wide text-black transition hover:bg-lime-300 hover:shadow-[0_0_25px_rgba(190,255,0,0.25)]"
                >
                  LOG IN TO CONTINUE
                </Link>

                <Link
                  to="/"
                  className="mt-4 inline-block text-xs font-semibold text-zinc-500 transition hover:text-white"
                >
                  Return to BANTAI home
                </Link>

              </div>

            </div>
          ) : (
            <>
              {/* PAGE HEADER */}
              <div className="mb-8">

                <h1 className="mt-4 text-3xl font-bold tracking-tight">
                  Analyze Email
                </h1>

                <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
                  Scan an email for potential phishing and security threats.
                  No account is required for your first 3 scans.
                </p>

                {/* SCAN COUNTER */}
                <div className="mt-4 inline-flex items-center rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-2">

                  <span className="text-xs text-zinc-500">
                    Free scans used:
                  </span>

                  <span className="ml-2 text-sm font-bold text-lime-400">
                    {scanCount} / {MAX_FREE_SCANS}
                  </span>

                </div>

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
                        <img src={uploadIcon} alt="Upload" className="h-7 w-7 object-contain"/>
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

                {/* SCAN */}
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

                {/* DEMO RESULT MESSAGE */}
                {scanCompleted && (
                  <div className="mt-6 rounded-xl border border-zinc-800 bg-black/50 p-4">

                    <p className="text-sm font-semibold text-white">
                      Email scan submitted.
                    </p>

                    <p className="mt-1 text-xs leading-5 text-zinc-500">
                      The actual XGBoost threat analysis result will
                      appear here once the FastAPI backend is connected.
                    </p>

                  </div>
                )}

              </div>

              {/* PRIVACY */}
              <div className="mt-6 flex justify-center px-4 text-center">

                <p className="text-[11px] leading-5 text-zinc-600">
                  Privacy enforced: Email payloads are parsed securely via
                  FastAPI and are not permanently stored in the database.
                </p>

              </div>

              {/* LOGIN CTA */}
              <div className="mt-8 text-center">

                <p className="text-xs text-zinc-600">
                  Want to save your scan history?
                </p>

                <Link
                  to="/login"
                  className="mt-2 inline-block text-xs font-semibold text-lime-400 transition hover:text-lime-300"
                >
                  Log in to access your BANTAI account
                </Link>

              </div>

            </>
          )}

        </div>

      </div>

    </main>
  );
}

export default GuestAnalyzeEmail;