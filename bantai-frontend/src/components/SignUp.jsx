import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import backgroundImage from "../assets/bgimg-login.png";
import lockIcon from "../assets/lock-icon.png";
import {
  friendlyError,
  register,
  resendRegistrationCode,
  verifyRegistration,
} from "../api/client";

function SignUp() {
  const [username, setUsername] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState("register");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setMessage("");
    if (step === "register" && password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setBusy(true);
    try {
      if (step === "register") {
        await register({
          username: username.trim(),
          fullName: name.trim(),
          email: email.trim(),
          password,
          confirmPassword,
        });
        setStep("verify");
        setMessage("If email delivery succeeded, enter the six-digit code to verify your account.");
      } else {
        await verifyRegistration({ email: email.trim(), code: code.trim() });
        navigate("/app/dashboard", { replace: true });
      }
    } catch (err) {
      if (err?.code === "email_delivery_failed") setStep("verify");
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleResend = async () => {
    setError("");
    setMessage("");
    setBusy(true);
    try {
      await resendRegistrationCode(email.trim());
      setMessage("If the account is pending verification and delivery succeeded, a new code was sent.");
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

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
                <Link
                  to="/"
                  aria-label="BANTAI home"
                  className="text-3xl font-black italic tracking-tight text-white"
                >
                  BANTAI<span className="text-lime-400">.</span>
                </Link>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white">
                {step === "register" ? "Create account" : "Verify your email"}
              </h1>
              <p className="mt-2 text-sm leading-6 text-zinc-500">
                {step === "register"
                  ? "Create your BANTAI threat intelligence account."
                  : `Enter the six-digit code sent to ${email}.`}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
              {step === "register" ? (
                <>
                  <div>
                    <label htmlFor="username" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Username
                    </label>
                    <input
                      id="username"
                      value={username}
                      onChange={(event) => setUsername(event.target.value)}
                      autoComplete="username"
                      minLength={3}
                      maxLength={32}
                      required
                      disabled={busy}
                      placeholder="Choose a username"
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                  </div>
                  <div>
                    <label htmlFor="name" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Full Name
                    </label>
                    <input
                      id="name"
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                      autoComplete="name"
                      maxLength={120}
                      disabled={busy}
                      placeholder="Your full name"
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                  </div>
                  <div>
                    <label htmlFor="email" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Email
                    </label>
                    <input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(event) => setEmail(event.target.value)}
                      autoComplete="email"
                      required
                      disabled={busy}
                      placeholder="name@company.com"
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                  </div>
                  <div>
                    <label htmlFor="password" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Password
                    </label>
                    <input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete="new-password"
                      minLength={10}
                      maxLength={128}
                      required
                      disabled={busy}
                      placeholder="At least 10 characters"
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                  </div>
                  <div>
                    <label htmlFor="confirm-password" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Confirm Password
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
                      placeholder="Confirm your password"
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                  </div>
                </>
              ) : (
                <div>
                  <label htmlFor="registration-code" className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400">
                    Verification Code
                  </label>
                  <input
                    id="registration-code"
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
                {busy ? "Please wait..." : step === "register" ? "Create Account" : "Verify Email"}
              </button>
            </form>

            {step === "verify" && (
              <div className="mt-5 flex justify-center gap-5 text-xs">
                <button type="button" onClick={handleResend} disabled={busy} className="font-semibold text-lime-400 hover:text-lime-300 disabled:opacity-50">
                  Resend code
                </button>
                <button
                  type="button"
                  onClick={() => { setStep("register"); setCode(""); setError(""); setMessage(""); }}
                  disabled={busy}
                  className="text-zinc-400 hover:text-white disabled:opacity-50"
                >
                  Change details
                </button>
              </div>
            )}

            <div className="mt-7 text-center">
              <p className="text-xs text-zinc-500">
                Already have a BANTAI account?
              </p>
              <Link to="/login" className="mt-1 inline-block text-xs font-semibold text-lime-400 transition hover:text-lime-300">
                Log in
              </Link>
            </div>
          </div>
        </div>
        <footer className="px-6 pb-7 text-center">
          <div className="flex items-center justify-center gap-2">
            <img src={lockIcon} alt="" className="h-4 w-4 object-contain opacity-60" />
            <p className="text-[11px] leading-5 text-zinc-500">
              Your account is activated only after email verification.
            </p>
          </div>
        </footer>
      </div>
    </main>
  );
}

export default SignUp;
