import { useRef, useState } from "react";

import shieldIcon from "../assets/shield-scan.png";
import uploadIcon from "../assets/upload-icon.png";
import AnalysisResults from "./AnalysisResults";
import { friendlyError, scanEmail } from "../api/client";

function AnalyzeEmail() {
  const [inputMethod, setInputMethod] = useState("upload");
  const [scanCompleted, setScanCompleted] = useState(false);
  const [pasteContent, setPasteContent] = useState("");
  const [scannedAt, setScannedAt] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);

  // API State
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [result, setResult] = useState(null);

  const fileInputRef = useRef(null);

  const handleFile = (file) => {
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".eml")) {
      alert("Please select a valid .eml email file.");
      return;
    }

    setSelectedFile(file);
    setScanCompleted(false);
    setScanError("");
  };

  const handleFileChange = (event) => {
    const file = event.target.files?.[0];
    handleFile(file);
  };

  const handleDragOver = (event) => {
    event.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (event) => {
    event.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);

    const file = event.dataTransfer.files?.[0];
    handleFile(file);
  };

  const handleBrowse = () => {
    fileInputRef.current?.click();
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }

    setScanCompleted(false);
    setScanError("");
  };

  const handleScan = async () => {
    if (scanning) return;

    if (inputMethod === "upload" && !selectedFile) {
      alert("Select an .eml file before scanning.");
      return;
    }

    if (inputMethod === "paste" && !pasteContent.trim()) {
      alert("Paste email content before scanning.");
      return;
    }

    setScanning(true);
    setScanError("");
    try {
      const data = await scanEmail({
        file: inputMethod === "upload" ? selectedFile : undefined,
        text: inputMethod === "paste" ? pasteContent : undefined,
      });
      setResult(data);
      setScannedAt(data.scannedAt || new Date().toISOString());
      setScanCompleted(true);
    } catch (err) {
      setScanError(friendlyError(err));
    } finally {
      setScanning(false);
    }
  };

  if (scanCompleted) {
    return (
      <AnalysisResults
        result={result}
        fileName={inputMethod === "paste" ? "Pasted email" : selectedFile?.name}
        scannedAt={scannedAt}
        onBack={() => setScanCompleted(false)}
      />
    );
  }

  const formatFileSize = (bytes) => {
    if (bytes === 0) return "0 Bytes";

    const units = ["Bytes", "KB", "MB", "GB"];
    const index = Math.floor(Math.log(bytes) / Math.log(1024));

    return `${(bytes / Math.pow(1024, index)).toFixed(1)} ${units[index]}`;
  };

  return (
    <div className="space-y-8">

      {/* HEADER */}
      <div>
        <h1 className="text-3xl font-black tracking-tight text-white">
          Analyze Email
        </h1>
      </div>

      {/* EMAIL INPUT CARD */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">

        {/* CARD HEADER */}
        <div>
          <h2 className="text-lg font-bold text-white">
            Email Input
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Choose how you want to provide the email for analysis.
          </p>
        </div>

        {/* INPUT METHOD SWITCH */}
        <div className="mt-6 flex w-full rounded-lg border border-zinc-800 bg-black p-1">

          <button
            type="button"
            onClick={() => {
              setInputMethod("upload");
              setScanCompleted(false);
              setScanError("");
            }}
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
            onClick={() => {
              setInputMethod("paste");
              setScanCompleted(false);
              setScanError("");
            }}
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

            {!selectedFile ? (
              <div
                onDragOver={handleDragOver}
                onDragEnter={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                className={`flex min-h-[260px] flex-col items-center justify-center rounded-xl border border-dashed px-6 text-center transition ${
                  isDragging
                    ? "border-lime-400 bg-lime-400/5"
                    : "border-zinc-700 bg-black/40 hover:border-lime-400/60"
                }`}
              >

                <div
                  className={`mb-4 flex h-14 w-14 items-center justify-center rounded-full border transition ${
                    isDragging
                      ? "border-lime-400 bg-lime-400/10"
                      : "border-zinc-700 bg-zinc-900"
                  }`}
                >
                  <img
                    src={uploadIcon}
                    alt="Upload"
                    className="h-7 w-7 object-contain"
                  />
                </div>

                <h3 className="text-base font-semibold text-white">
                  Drop your email file here
                </h3>

                <p className="mt-2 text-sm text-zinc-500">
                  or select an .eml file from your computer
                </p>

                <button
                  type="button"
                  onClick={handleBrowse}
                  className="mt-5 rounded-lg border border-zinc-700 bg-zinc-900 px-6 py-3 text-sm font-semibold text-white transition hover:border-lime-400 hover:text-lime-400"
                >
                  Browse File
                </button>

              </div>
            ) : (
              <div className="flex min-h-[260px] flex-col items-center justify-center rounded-xl border border-lime-400/40 bg-lime-400/5 px-6 text-center">

                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-lime-400/40 bg-lime-400/10">
                  <img
                    src={uploadIcon}
                    alt="Selected file"
                    className="h-7 w-7 object-contain"
                  />
                </div>

                <p className="max-w-lg truncate text-base font-semibold text-white">
                  {selectedFile.name}
                </p>

                <p className="mt-2 text-sm text-zinc-500">
                  {formatFileSize(selectedFile.size)}
                </p>

                <div className="mt-5 flex items-center gap-3">

                  <button
                    type="button"
                    onClick={handleBrowse}
                    disabled={scanning}
                    className="rounded-lg border border-zinc-700 bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-white transition hover:border-lime-400 hover:text-lime-400 disabled:opacity-50"
                  >
                    Change File
                  </button>

                  <button
                    type="button"
                    onClick={handleRemoveFile}
                    disabled={scanning}
                    className="rounded-lg border border-zinc-700 px-5 py-2.5 text-sm font-semibold text-zinc-500 transition hover:border-red-400 hover:text-red-400 disabled:opacity-50"
                  >
                    Remove
                  </button>

                </div>

              </div>
            )}

          </div>
        )}

        {/* PASTE */}
        {inputMethod === "paste" && (
          <div className="mt-6">

            <textarea
              placeholder="Paste the complete email content here..."
              rows={12}
              value={pasteContent}
              onChange={(event) => {
                setPasteContent(event.target.value);
                setScanError("");
              }}
              onInput={(event) => {
                event.target.style.height = "auto";
                event.target.style.height = `${event.target.scrollHeight}px`;
              }}
              className="w-full overflow-hidden rounded-xl border border-zinc-800 bg-black/60 px-4 py-4 text-sm leading-6 text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
            />

          </div>
        )}

        {/* ERROR DISPLAY */}
        {scanError && (
          <div className="mt-6 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
            <p role="alert" className="text-xs text-red-400">
              {scanError}
            </p>
          </div>
        )}

        {/* SCAN BUTTON */}
        <div className="mt-6 flex justify-center">

          <button
            type="button"
            onClick={handleScan}
            disabled={scanning}
            className="flex w-full max-w-md items-center justify-center gap-3 rounded-lg bg-lime-400 px-7 py-3.5 text-sm font-bold tracking-wide text-black transition hover:bg-lime-300 hover:shadow-[0_0_25px_rgba(190,255,0,0.25)] disabled:opacity-50"
          >
            <img
              src={shieldIcon}
              alt=""
              className="h-5 w-5 object-contain"
            />

            {scanning ? "SCANNING..." : "SCAN EMAIL"}
          </button>

        </div>

      </div>

      {/* PRIVACY */}
      <div className="flex justify-center px-4 text-center">

        <p className="text-[11px] leading-5 text-zinc-600">
          Protected by end-to-end encryption. Authenticated scans are recorded in your account threat history.
        </p>

      </div>

    </div>
  );
}

export default AnalyzeEmail;


// import { useRef, useState } from "react";

// import shieldIcon from "../assets/shield-scan.png";
// import uploadIcon from "../assets/upload-icon.png";
// import AnalysisResults from "./AnalysisResults";

// function AnalyzeEmail() {
//   const [inputMethod, setInputMethod] = useState("upload");
//   const [scanCompleted, setScanCompleted] = useState(false);
//   const [pasteContent, setPasteContent] = useState("");
//   const [scannedAt, setScannedAt] = useState(null);
//   const [selectedFile, setSelectedFile] = useState(null);
//   const [isDragging, setIsDragging] = useState(false);

//   const fileInputRef = useRef(null);

//   const handleFile = (file) => {
//     if (!file) return;

//     if (!file.name.toLowerCase().endsWith(".eml")) {
//       alert("Please select a valid .eml email file.");
//       return;
//     }

//     setSelectedFile(file);
//     setScanCompleted(false);
//   };

//   const handleFileChange = (event) => {
//     const file = event.target.files?.[0];
//     handleFile(file);
//   };

//   const handleDragOver = (event) => {
//     event.preventDefault();
//     setIsDragging(true);
//   };

//   const handleDragLeave = (event) => {
//     event.preventDefault();
//     setIsDragging(false);
//   };

//   const handleDrop = (event) => {
//     event.preventDefault();
//     setIsDragging(false);

//     const file = event.dataTransfer.files?.[0];
//     handleFile(file);
//   };

//   const handleBrowse = () => {
//     fileInputRef.current?.click();
//   };

//   const handleRemoveFile = () => {
//     setSelectedFile(null);

//     if (fileInputRef.current) {
//       fileInputRef.current.value = "";
//     }

//     setScanCompleted(false);
//   };

//   const handleScan = () => {
//     if (inputMethod === "upload" && !selectedFile) {
//       alert("Select an .eml file before scanning.");
//       return;
//     }

//     if (inputMethod === "paste" && !pasteContent.trim()) {
//       alert("Paste email content before scanning.");
//       return;
//     }

//     setScannedAt(new Date().toISOString());
//     setScanCompleted(true);
//   };

//   if (scanCompleted) {
//     return (
//       <AnalysisResults
//         result={null}
//         fileName={inputMethod === "paste" ? "Pasted email" : selectedFile?.name}
//         scannedAt={scannedAt}
//         isGuest={false}
//         onBack={() => setScanCompleted(false)}
//       />
//     );
//   }

//   const formatFileSize = (bytes) => {
//     if (bytes === 0) return "0 Bytes";

//     const units = ["Bytes", "KB", "MB", "GB"];
//     const index = Math.floor(Math.log(bytes) / Math.log(1024));

//     return `${(bytes / Math.pow(1024, index)).toFixed(1)} ${units[index]}`;
//   };

//   return (
//     <div className="space-y-8">

//       {/* HEADER */}
//       <div>
//         <h1 className="text-3xl font-black tracking-tight text-white">
//           Analyze Email
//         </h1>

//       </div>

//       {/* EMAIL INPUT CARD */}
//       <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">

//         {/* CARD HEADER */}
//         <div>
//           <h2 className="text-lg font-bold text-white">
//             Email Input
//           </h2>

//           <p className="mt-1 text-sm text-zinc-500">
//             Choose how you want to provide the email for analysis.
//           </p>
//         </div>

//         {/* INPUT METHOD SWITCH */}
//         <div className="mt-6 flex w-full rounded-lg border border-zinc-800 bg-black p-1">

//           <button
//             type="button"
//             onClick={() => {
//               setInputMethod("upload");
//               setScanCompleted(false);
//             }}
//             className={`flex-1 rounded-md px-5 py-2.5 text-sm font-semibold transition ${
//               inputMethod === "upload"
//                 ? "bg-lime-400 text-black"
//                 : "text-zinc-500 hover:text-white"
//             }`}
//           >
//             Upload File
//           </button>

//           <button
//             type="button"
//             onClick={() => {
//               setInputMethod("paste");
//               setScanCompleted(false);
//             }}
//             className={`flex-1 rounded-md px-5 py-2.5 text-sm font-semibold transition ${
//               inputMethod === "paste"
//                 ? "bg-lime-400 text-black"
//                 : "text-zinc-500 hover:text-white"
//             }`}
//           >
//             Paste Content
//           </button>

//         </div>

//         {/* UPLOAD */}
//         {inputMethod === "upload" && (
//           <div className="mt-6">

//             <input
//               ref={fileInputRef}
//               type="file"
//               accept=".eml,message/rfc822"
//               onChange={handleFileChange}
//               className="hidden"
//             />

//             {!selectedFile ? (
//               <div
//                 onDragOver={handleDragOver}
//                 onDragEnter={handleDragOver}
//                 onDragLeave={handleDragLeave}
//                 onDrop={handleDrop}
//                 className={`flex min-h-[260px] flex-col items-center justify-center rounded-xl border border-dashed px-6 text-center transition ${
//                   isDragging
//                     ? "border-lime-400 bg-lime-400/5"
//                     : "border-zinc-700 bg-black/40 hover:border-lime-400/60"
//                 }`}
//               >

//                 <div
//                   className={`mb-4 flex h-14 w-14 items-center justify-center rounded-full border transition ${
//                     isDragging
//                       ? "border-lime-400 bg-lime-400/10"
//                       : "border-zinc-700 bg-zinc-900"
//                   }`}
//                 >
//                   <img
//                     src={uploadIcon}
//                     alt="Upload"
//                     className="h-7 w-7 object-contain"
//                   />
//                 </div>

//                 <h3 className="text-base font-semibold text-white">
//                   {isDragging
//                     ? "Drop your email file here"
//                     : "Drop your email file here"}
//                 </h3>

//                 <p className="mt-2 text-sm text-zinc-500">
//                   or select an .eml file from your computer
//                 </p>

//                 <button
//                   type="button"
//                   onClick={handleBrowse}
//                   className="mt-5 rounded-lg border border-zinc-700 bg-zinc-900 px-6 py-3 text-sm font-semibold text-white transition hover:border-lime-400 hover:text-lime-400"
//                 >
//                   Browse File
//                 </button>

//               </div>
//             ) : (
//               <div className="flex min-h-[260px] flex-col items-center justify-center rounded-xl border border-lime-400/40 bg-lime-400/5 px-6 text-center">

//                 <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-lime-400/40 bg-lime-400/10">
//                   <img
//                     src={uploadIcon}
//                     alt="Selected file"
//                     className="h-7 w-7 object-contain"
//                   />
//                 </div>

//                 <p className="max-w-lg truncate text-base font-semibold text-white">
//                   {selectedFile.name}
//                 </p>

//                 <p className="mt-2 text-sm text-zinc-500">
//                   {formatFileSize(selectedFile.size)}
//                 </p>

//                 <div className="mt-5 flex items-center gap-3">

//                   <button
//                     type="button"
//                     onClick={handleBrowse}
//                     className="rounded-lg border border-zinc-700 bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-white transition hover:border-lime-400 hover:text-lime-400"
//                   >
//                     Change File
//                   </button>

//                   <button
//                     type="button"
//                     onClick={handleRemoveFile}
//                     className="rounded-lg border border-zinc-700 px-5 py-2.5 text-sm font-semibold text-zinc-500 transition hover:border-red-400 hover:text-red-400"
//                   >
//                     Remove
//                   </button>

//                 </div>

//               </div>
//             )}

//           </div>
//         )}

//         {/* PASTE */}
//         {inputMethod === "paste" && (
//           <div className="mt-6">

//             <textarea
//               placeholder="Paste the complete email content here..."
//               rows={12}
//               value={pasteContent}
//               onChange={(event) => setPasteContent(event.target.value)}
//               onInput={(event) => {
//                 event.target.style.height = "auto";
//                 event.target.style.height = `${event.target.scrollHeight}px`;
//               }}
//               className="w-full overflow-hidden rounded-xl border border-zinc-800 bg-black/60 px-4 py-4 text-sm leading-6 text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
//             />

//           </div>
//         )}

//         {/* SCAN BUTTON */}
//         <div className="mt-6 flex justify-center">

//           <button
//             type="button"
//             onClick={handleScan}
//             className="flex w-full max-w-md items-center justify-center gap-3 rounded-lg bg-lime-400 px-7 py-3.5 text-sm font-bold tracking-wide text-black transition hover:bg-lime-300 hover:shadow-[0_0_25px_rgba(190,255,0,0.25)]"
//           >
//             <img
//               src={shieldIcon}
//               alt=""
//               className="h-5 w-5 object-contain"
//             />

//             SCAN EMAIL
//           </button>

//         </div>

//       </div>

//       {/* PRIVACY */}
//       <div className="flex justify-center px-4 text-center">

//         <p className="text-[11px] leading-5 text-zinc-600">
//           Email content is not sent or saved yet. Analysis and account
//           history will be available once the FastAPI backend is connected.
//         </p>

//       </div>

//     </div>
//   );
// }

// export default AnalyzeEmail;