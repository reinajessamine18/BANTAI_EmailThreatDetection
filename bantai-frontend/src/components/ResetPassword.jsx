import { useState } from "react";
import { Eye, EyeOff } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";

import backgroundImage from "../assets/bgimg-login.png";
import lockIcon from "../assets/lock-icon.png";
import { friendlyError, resetPassword } from "../api/client";

function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") || "";
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPasswords, setShowPasswords] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [complete, setComplete] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 10) {
      setError("Password must be at least 10 characters.");
      return;
    }

    setBusy(true);
    try {
      await resetPassword({ token, newPassword: password });
      setComplete(true);
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
                Choose a New Password
              </h1>
              <p className="mt-2 text-sm leading-6 text-zinc-500">
                Your reset link is single-use and expires soon.
              </p>
            </div>

            {complete ? (
              <div className="space-y-5 text-center">
                <p
                  role="status"
                  className="rounded-lg border border-lime-400/20 bg-lime-400/10 px-4 py-4 text-sm leading-6 text-lime-300"
                >
                  Your password has been changed. All existing sessions have
                  been signed out.
                </p>
                <Link
                  to="/login"
                  className="inline-block text-sm font-semibold text-lime-400 transition hover:text-lime-300"
                >
                  Go to Log In
                </Link>
              </div>
            ) : !token ? (
              <div className="space-y-5 text-center">
                <p role="alert" className="text-sm leading-6 text-red-400">
                  This reset link is missing its token. Request a new link to
                  continue.
                </p>
                <Link
                  to="/forgot-password"
                  className="inline-block text-sm font-semibold text-lime-400 transition hover:text-lime-300"
                >
                  Request a new link
                </Link>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-5">
                <div>
                  <label
                    htmlFor="new-password"
                    className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                  >
                    New Password
                  </label>
                  <div className="relative">
                    <input
                      id="new-password"
                      name="new-password"
                      type={showPasswords ? "text" : "password"}
                      value={password}
                      onChange={(event) => {
                        setPassword(event.target.value);
                        setError("");
                      }}
                      autoComplete="new-password"
                      required
                      minLength={10}
                      maxLength={128}
                      disabled={busy}
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 pr-12 text-sm text-white outline-none transition focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswords((shown) => !shown)}
                      aria-label={showPasswords ? "Hide passwords" : "Show passwords"}
                      disabled={busy}
                      className="absolute right-3 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-zinc-400 transition hover:bg-white/10 hover:text-white disabled:opacity-50"
                    >
                      {showPasswords ? (
                        <EyeOff aria-hidden="true" size={20} />
                      ) : (
                        <Eye aria-hidden="true" size={20} />
                      )}
                    </button>
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="confirm-password"
                    className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                  >
                    Confirm New Password
                  </label>
                  <div className="relative">
                    <input
                      id="confirm-password"
                      name="confirm-password"
                      type={showPasswords ? "text" : "password"}
                      value={confirmPassword}
                      onChange={(event) => {
                        setConfirmPassword(event.target.value);
                        setError("");
                      }}
                      autoComplete="new-password"
                      required
                      minLength={10}
                      maxLength={128}
                      disabled={busy}
                      className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 pr-12 text-sm text-white outline-none transition focus:border-lime-400 focus:ring-1 focus:ring-lime-400 disabled:opacity-50"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswords((shown) => !shown)}
                      aria-label={showPasswords ? "Hide passwords" : "Show passwords"}
                      disabled={busy}
                      className="absolute right-3 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-zinc-400 transition hover:bg-white/10 hover:text-white disabled:opacity-50"
                    >
                      {showPasswords ? (
                        <EyeOff aria-hidden="true" size={20} />
                      ) : (
                        <Eye aria-hidden="true" size={20} />
                      )}
                    </button>
                  </div>
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
                  {busy ? "Resetting..." : "Reset Password"}
                </button>
              </form>
            )}
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
              Reset links are single-use and expire after a short time.
            </p>
          </div>
        </footer>
      </div>
    </main>
  );
}

export default ResetPassword;
