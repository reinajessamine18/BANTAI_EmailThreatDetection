import { useState } from "react";
import { Link } from "react-router-dom";

import backgroundImage from "../assets/bgimg-login.png";
import lockIcon from "../assets/lock-icon.png";
import { friendlyError, requestPasswordReset } from "../api/client";

function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      await requestPasswordReset(email.trim());
      setSent(true);
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
                <span className="text-3xl font-black italic tracking-tight text-white">
                  BANTAI<span className="text-lime-400">.</span>
                </span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white">
                Reset Password
              </h1>
              <p className="mt-2 text-sm leading-6 text-zinc-500">
                Enter the email address associated with your account. We’ll send
                a single-use reset link if an account exists.
              </p>
            </div>

            {sent ? (
              <div
                role="status"
                className="rounded-lg border border-lime-400/20 bg-lime-400/10 px-4 py-4 text-sm leading-6 text-lime-300"
              >
                If an account exists for that email, a reset link will be sent.
                Check your inbox and spam folder.
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-5">
                <div>
                  <label
                    htmlFor="reset-email"
                    className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                  >
                    Email
                  </label>
                  <input
                    id="reset-email"
                    name="email"
                    type="email"
                    value={email}
                    onChange={(event) => {
                      setEmail(event.target.value);
                      setError("");
                    }}
                    placeholder="name@company.com"
                    autoComplete="email"
                    required
                    disabled={busy}
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                  />
                </div>

                {error && (
                  <p
                    role="alert"
                    className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs leading-5 text-red-400"
                  >
                    {error}
                  </p>
                )}

                <button
                  type="submit"
                  disabled={busy}
                  className="w-full rounded-lg bg-lime-400 px-6 py-3.5 text-sm font-bold uppercase tracking-wider text-black transition hover:bg-lime-300 disabled:opacity-50"
                >
                  {busy ? "Sending..." : "Send Reset Link"}
                </button>
              </form>
            )}

            <div className="mt-7 text-center">
              <Link
                to="/login"
                className="text-xs font-semibold text-lime-400 transition hover:text-lime-300"
              >
                Back to Log In
              </Link>
            </div>
          </div>
        </div>

        <footer className="px-6 pb-7 text-center">
          <div className="flex items-center justify-center gap-2">
            <img
              src={lockIcon}
              alt=""
              className="h-4 w-4 object-contain opacity-60"
            />
            <p className="text-[11px] leading-5 text-zinc-500">
              A reset link can only be used once and expires after a short time.
            </p>
          </div>
        </footer>
      </div>
    </main>
  );
}

export default ForgotPassword;
