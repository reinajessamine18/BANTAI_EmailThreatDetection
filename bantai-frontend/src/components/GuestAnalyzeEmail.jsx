import { useRef, useState } from "react";
import { Link } from "react-router-dom";

import shieldIcon from "../assets/shield-scan.png";
import uploadIcon from "../assets/upload-icon.png";
import AnalysisResults from "./AnalysisResults";

const MAX_FREE_SCANS = 3;
const STORAGE_KEY = "bantaiGuestScanCount";

function GuestAnalyzeEmail() {
  const [inputMethod, setInputMethod] = useState("upload");
  const [scanCount, setScanCount] = useState(
    () => Number(sessionStorage.getItem(STORAGE_KEY) || "0")
  );
  const [scanCompleted, setScanCompleted] = useState(false);
  const [pasteContent, setPasteContent] = useState("");
  const [scannedAt, setScannedAt] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const limitReached = scanCount >= MAX_FREE_SCANS;

  const handleFile = (file) => {
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".eml")) {
      alert("Please select a valid .eml email file.");
      return;
    }
    setSelectedFile(file);
    setSelectedFile(file);
  };

  const handleFileChange = (event) => {
    handleFile(event.target.files?.[0]);
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleScan = () => {
    if (limitReached) {
      return;
    }

    if (inputMethod === "upload") {
      if (!selectedFile) {
        alert("Select an .eml file before scanning.");
        return;
      }
    } else if (!pasteContent.trim()) {
      alert("Paste email content before scanning.");
      return;
    }

    const nextCount = scanCount + 1;
    sessionStorage.setItem(STORAGE_KEY, String(nextCount));
    setScanCount(nextCount);
    setScannedAt(new Date().toISOString());
    setScanCompleted(true);
  };

  if (scanCompleted) {
    return (
      <main className="min-h-screen bg-black px-6 py-10 text-white">
        <div className="mx-auto max-w-5xl">
          <Link
            to="/"
            className="mb-8 inline-flex text-xl font-black italic tracking-tight text-white"
          >
            BANTAI<span className="text-lime-400">.</span>
          </Link>
          <AnalysisResults
            result={null}
            fileName={
              inputMethod === "paste" ? "Pasted email" : selectedFile?.name
            }
            scannedAt={scannedAt}
            isGuest
            onBack={() => setScanCompleted(false)}
          />
        </div>
      </main>
    );
  }

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
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".eml,message/rfc822"
                      onChange={handleFileChange}
                      className="hidden"
                    />

                    <div
                      onDragOver={(event) => {
                        event.preventDefault();
                        setIsDragging(true);
                      }}
                      onDragLeave={(event) => {
                        event.preventDefault();
                        setIsDragging(false);
                      }}
                      onDrop={(event) => {
                        event.preventDefault();
                        setIsDragging(false);
                        handleFile(event.dataTransfer.files?.[0]);
                      }}
                      className={`flex min-h-[260px] flex-col items-center justify-center rounded-xl border border-dashed px-6 text-center transition ${
                        isDragging
                          ? "border-lime-400 bg-lime-400/5"
                          : "border-zinc-700 bg-black/40 hover:border-lime-400/60"
                      }`}
                    >
                      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-zinc-700 bg-zinc-900">
                        <img
                          src={uploadIcon}
                          alt=""
                          className="h-7 w-7 object-contain"
                        />
                      </div>

                      {selectedFile ? (
                        <>
                          <h3 className="max-w-full truncate text-base font-semibold text-white">
                            {selectedFile.name}
                          </h3>
                          <p className="mt-2 text-sm text-zinc-500">
                            {(selectedFile.size / 1024).toFixed(1)} KB
                          </p>
                          <div className="mt-5 flex gap-3">
                            <button
                              type="button"
                              onClick={() => fileInputRef.current?.click()}
                              className="rounded-lg border border-zinc-700 bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-white transition hover:border-lime-400 hover:text-lime-400"
                            >
                              Change File
                            </button>
                            <button
                              type="button"
                              onClick={handleRemoveFile}
                              className="rounded-lg border border-zinc-700 px-5 py-2.5 text-sm font-semibold text-zinc-400 transition hover:border-red-400 hover:text-red-400"
                            >
                              Remove
                            </button>
                          </div>
                        </>
                      ) : (
                        <>
                          <h3 className="text-base font-semibold text-white">
                            {isDragging
                              ? "Drop your email file here"
                              : "Drop your email file here"}
                          </h3>
                          <p className="mt-2 text-sm text-zinc-500">
                            or select an .eml file from your computer
                          </p>
                          <button
                            type="button"
                            onClick={() => fileInputRef.current?.click()}
                            className="mt-5 rounded-lg border border-zinc-700 bg-zinc-900 px-6 py-3 text-sm font-semibold text-white transition hover:border-lime-400 hover:text-lime-400"
                          >
                            Browse File
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* PASTE */}
                {inputMethod === "paste" && (
                  <div className="mt-6">

                    <textarea
                      placeholder="Paste the complete email content here..."
                      rows={12}
                      value={pasteContent}
                      onChange={(event) => setPasteContent(event.target.value)}
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

              </div>

              {/* PRIVACY */}
              <div className="mt-6 flex justify-center px-4 text-center">

                <p className="text-[11px] leading-5 text-zinc-600">
                  Email content is not sent or saved yet. Analysis will be
                  available once the FastAPI backend is connected.
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