import { useState } from "react";
import { Link } from "react-router-dom";

import backgroundImage from "../assets/bantai-login.webp";
import lockIcon from "../assets/lock-icon.png";
import {
  friendlyError,
  requestPasswordReset,
  resendPasswordResetCode,
  resetPassword,
  verifyPasswordResetCode,
} from "../api/client";

function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [resetAuthorization, setResetAuthorization] = useState("");
  const [step, setStep] = useState("email");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const runRequest = async (request, successMessage) => {
    setError("");
    setMessage("");
    setBusy(true);
    try {
      await request();
      setMessage(successMessage);
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setMessage("");
    setBusy(true);
    try {
      if (step === "email") {
        await requestPasswordReset(email.trim());
        setStep("code");
        setMessage("If an eligible account exists and email delivery succeeded, a reset code was sent.");
      } else if (step === "code") {
        const result = await verifyPasswordResetCode({ email: email.trim(), code: code.trim() });
        setResetAuthorization(result.resetAuthorization);
        setStep("password");
      } else {
        if (password !== confirmPassword) {
          setError("Passwords do not match.");
          return;
        }
        await resetPassword({
          token: resetAuthorization,
          newPassword: password,
          confirmPassword,
        });
        setStep("complete");
      }
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleResend = () => runRequest(
    () => resendPasswordResetCode(email.trim()),
    "If an eligible account exists and delivery succeeded, a new reset code was sent."
  );

  const headings = {
    email: ["Reset Password", "Enter your registered email address to request a reset code."],
    code: ["Verify Reset Code", `Enter the six-digit code sent to ${email}.`],
    password: ["Choose a New Password", "Set a new password for your account."],
    complete: ["Password Updated", "Your password was changed and active sessions were signed out."],
  };
  const [title, subtitle] = headings[step];

  return (
    <main
      className="relative min-h-screen bg-black bg-cover bg-center bg-no-repeat text-white"
      style={{ backgroundImage: `url(${backgroundImage})` }}
    >
      <div className="absolute inset-0 bg-black/55" />
      <div className="relative z-10 flex min-h-screen flex-col">
        <div className="flex flex-1 items-center justify-center px-6 py-12">
          <div className="w-full max-w-md rounded-2xl border border-zinc-800/80 bg-black/80 p-8 shadow-2xl backdrop-blur-md sm:p-10">
            <div className="mb-8 text-center">
              <div className="mb-5">
                <Link to="/" aria-label="BANTAI home" className="text-3xl font-black italic tracking-tight text-white">
                  BANTAI<span className="text-lime-400">.</span>
                </Link>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white">{title}</h1>
              <p className="mt-2 text-sm leading-6 text-zinc-500">{subtitle}</p>
            </div>

            {step === "complete" ? (
              <div className="space-y-5 text-center">
                <p role="status" className="rounded-lg border border-lime-400/20 bg-lime-400/10 px-4 py-4 text-sm leading-6 text-lime-300">
                  {subtitle}
                </p>
                <Link to="/login" className="inline-block text-sm font-semibold text-lime-400 hover:text-lime-300">
                  Go to Log In
                </Link>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-5">
                {step === "email" && (
                  <div>
                    <label htmlFor="reset-email" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Email
                    </label>
                    <input
                      id="reset-email"
                      type="email"
                      value={email}
                      onChange={(event) => setEmail(event.target.value)}
                      placeholder="name@company.com"
                      autoComplete="email"
                      required
                      disabled={busy}
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                  </div>
                )}
                {step === "code" && (
                  <div>
                    <label htmlFor="reset-code" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Reset Code
                    </label>
                    <input
                      id="reset-code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      pattern="[0-9]{6}"
                      minLength={6}
                      maxLength={6}
                      value={code}
                      onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                      required
                      disabled={busy}
                      placeholder="000000"
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-center text-lg tracking-[0.5em] text-white outline-none placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                  </div>
                )}
                {step === "password" && (
                  <>
                    <div>
                      <label htmlFor="new-password" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                        New Password
                      </label>
                      <input
                        id="new-password"
                        type="password"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        autoComplete="new-password"
                        minLength={10}
                        maxLength={128}
                        required
                        disabled={busy}
                        className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                      />
                    </div>
                    <div>
                      <label htmlFor="confirm-password" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                        Confirm New Password
                      </label>
                      <input
                        id="confirm-password"
                        type="password"
                        value={confirmPassword}
                        onChange={(event) => setConfirmPassword(event.target.value)}
                        autoComplete="new-password"
                        minLength={10}
                        maxLength={128}
                        required
                        disabled={busy}
                        className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                      />
                    </div>
                  </>
                )}

                {error && (
                  <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs leading-5 text-red-400">
                    {error}
                  </p>
                )}
                {message && (
                  <p role="status" className="rounded-lg border border-lime-400/20 bg-lime-400/10 px-4 py-3 text-xs leading-5 text-lime-300">
                    {message}
                  </p>
                )}

                <button
                  type="submit"
                  disabled={busy}
                  className="w-full rounded-lg bg-lime-400 px-6 py-3.5 text-sm font-bold uppercase tracking-wider text-black transition hover:bg-lime-300 disabled:opacity-50"
                >
                  {busy ? "Please wait..." : step === "email" ? "Send Reset Code" : step === "code" ? "Verify Code" : "Update Password"}
                </button>
              </form>
            )}

            {step === "code" && (
              <div className="mt-5 text-center">
                <button type="button" onClick={handleResend} disabled={busy} className="text-xs font-semibold text-lime-400 hover:text-lime-300 disabled:opacity-50">
                  Resend code
                </button>
              </div>
            )}
            {step !== "complete" && (
              <div className="mt-7 text-center">
                <Link to="/login" className="text-xs font-semibold text-lime-400 transition hover:text-lime-300">
                  Back to Log In
                </Link>
              </div>
            )}
          </div>
        </div>
        <footer className="px-6 pb-7 text-center">
          <div className="flex items-center justify-center gap-2">
            <img src={lockIcon} alt="" className="h-4 w-4 object-contain opacity-60" />
            <p className="text-[11px] leading-5 text-zinc-500">
              Reset codes expire and can be used only once.
            </p>
          </div>
        </footer>
      </div>
    </main>
  );
}

export default ForgotPassword;
